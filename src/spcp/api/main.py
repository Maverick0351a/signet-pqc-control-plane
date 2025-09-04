
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException

from ..policy.circuit_breaker import CircuitBreaker
from ..policy.store import load_policy, set_policy
from ..receipts.merkle import build_sth
from ..receipts.sign import sign_receipt_ed25519
from ..settings import settings
from .models import PolicyDoc, PQCCBOMReceipt, PQCEnforcementReceipt

app = FastAPI(title="Signet PQC Control Plane (MVP)")

DATA = settings.spcp_data_dir
RECEIPTS = DATA / "receipts"
PROOFS = DATA / "proofs"
STH_FILE = DATA / "sth.json"
KEY_DIR = DATA / "keys"
for d in (RECEIPTS, PROOFS, KEY_DIR):
    d.mkdir(parents=True, exist_ok=True)

# In a lab, generate a transient keypair if not present (ed25519)
SK_FILE = KEY_DIR / "signing_key_ed25519.b64"
VK_FILE = KEY_DIR / "verify_key_ed25519.b64"
if not SK_FILE.exists():
    from ..receipts.sign import gen_ed25519_keypair
    sk, vk = gen_ed25519_keypair()
    SK_FILE.write_text(base64.b64encode(sk).decode())
    VK_FILE.write_text(base64.b64encode(vk).decode())

def _load_keys():
    """Load (or lazily re-generate) the Ed25519 keypair.

    Tests wipe the data directory after the module import, which can remove the
    previously generated transient key files. To keep the API resilient we
    recreate them here if missing instead of assuming one-shot startup logic.
    """
    if (not SK_FILE.exists()) or (not VK_FILE.exists()):
        from ..receipts.sign import gen_ed25519_keypair
        KEY_DIR.mkdir(parents=True, exist_ok=True)
        sk_new, vk_new = gen_ed25519_keypair()
        SK_FILE.write_text(base64.b64encode(sk_new).decode())
        VK_FILE.write_text(base64.b64encode(vk_new).decode())
    sk = base64.b64decode(SK_FILE.read_text().strip())
    vk = base64.b64decode(VK_FILE.read_text().strip())
    return sk, vk

_cb = CircuitBreaker()

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/policy")
def get_policy():
    return load_policy().model_dump()

@app.put("/policy")
def put_policy(doc: PolicyDoc):
    sk, _ = _load_keys()
    signed = set_policy(doc, sk)
    _refresh_sth()
    return signed

def _read_prev_hash():
    files = sorted(RECEIPTS.glob("*.json"))
    if not files:
        return None
    obj = json.loads(files[-1].read_text())
    return obj.get("payload_hash_b64")

def _store_signed_receipt(name: str, signed: dict) -> Path:
    p = RECEIPTS / f"{name}.json"
    RECEIPTS.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(signed, indent=2))
    return p

def _refresh_sth():
    """Recompute STH over all receipts in insertion order."""
    files = sorted(RECEIPTS.glob("*.json"))
    leaves = []
    for f in files:
        obj = json.loads(f.read_text())
        # leaf = sha256(payload) excluding signature fields
        excluded = ("payload_hash_b64", "receipt_sig_b64", "sig_alg")
        core = {k: v for k, v in obj.items() if k not in excluded}
        payload = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
        leaves.append(hashlib.sha256(payload).digest())
    leaves_b64 = [base64.b64encode(x).decode() for x in leaves]
    sth = build_sth(leaves_b64)
    STH_FILE.write_text(json.dumps(sth, indent=2))
    return sth

@app.post("/events")
def post_event(body: dict = Body(...)):  # noqa: B008 FastAPI dependency pattern
    sk, vk = _load_keys()
    kind = body.get("kind")
    # Validate & sign with server key (control plane as anchor)
    if kind == "pqc.enforcement":
        rec = PQCEnforcementReceipt.model_validate(body).model_dump()
    elif kind == "pqc.cbom":
        rec = PQCCBOMReceipt.model_validate(body).model_dump()
    else:
        raise HTTPException(400, f"unsupported receipt kind {kind}")

    rec["prev_receipt_hash_b64"] = _read_prev_hash()
    signed = sign_receipt_ed25519(rec, sk)
    # Sanitize hash fragment for filesystem (base64 can contain '/' '+')
    hash_prefix = signed["payload_hash_b64"][:8].replace("/", "_").replace("+", "-")
    _store_signed_receipt(f"{kind.replace('.','_')}_{hash_prefix}", signed)
    _refresh_sth()

    # Feed circuit breaker with outcome if enforcement
    if kind == "pqc.enforcement":
        _cb.add_outcome(bool(rec.get("decision", {}).get("allow", False)))
        changed = _cb.maybe_trip(load_policy(), sk)
        if changed:
            _refresh_sth()

    return signed
