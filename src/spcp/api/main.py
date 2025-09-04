
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Request, Response

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
    # If data directory or key dir was removed after import (tests), recreate.
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if (not SK_FILE.exists()) or (not VK_FILE.exists()):
        from ..receipts.sign import gen_ed25519_keypair
        sk_new, vk_new = gen_ed25519_keypair()
        # Extra safety: ensure parent exists right before writing
        SK_FILE.parent.mkdir(parents=True, exist_ok=True)
        SK_FILE.write_text(base64.b64encode(sk_new).decode())
        VK_FILE.write_text(base64.b64encode(vk_new).decode())
    sk = base64.b64decode(SK_FILE.read_text().strip())
    vk = base64.b64decode(VK_FILE.read_text().strip())
    return sk, vk

_cb = CircuitBreaker()

@app.get("/health")
@app.get("/healthz")  # alias for k8s style probes
def health():
    return {"ok": True}

@app.get("/policy")
def get_policy():
    return load_policy().model_dump()

@app.put("/policy")
def put_policy(doc: PolicyDoc):
    # Recreate data directories if removed after import (test isolation)
    for d in (RECEIPTS, PROOFS, KEY_DIR):
        d.mkdir(parents=True, exist_ok=True)
    sk, _ = _load_keys()
    signed = set_policy(doc, sk)
    _refresh_sth()
    return signed

def _read_prev_hash():
    """Return the payload hash of the newest well-formed receipt.

    Malformed / truncated JSON files are skipped to keep chain resilient.
    """
    files = sorted(RECEIPTS.glob("*.json"))
    for p in reversed(files):  # iterate newest first
        try:
            obj = json.loads(p.read_text())
        except Exception as e:  # noqa: S112 - tolerate malformed but log
            logging.exception("Failed to parse receipt file %s: %s", p, e)
            continue
        if isinstance(obj, dict) and "payload_hash_b64" in obj:
            return obj.get("payload_hash_b64")
    return None

def _store_signed_receipt(name: str, signed: dict) -> Path:
    p = RECEIPTS / f"{name}.json"
    RECEIPTS.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(signed, indent=2))
    return p

def _refresh_sth():
    """Recompute STH over all receipts, skipping malformed ones."""
    files = sorted(RECEIPTS.glob("*.json"))
    leaves: list[bytes] = []
    for f in files:
        try:
            obj = json.loads(f.read_text())
        except Exception as e:  # noqa: S112
            logging.exception("Failed to parse receipt file %s during STH refresh: %s", f, e)
            continue
        if not isinstance(obj, dict):
            continue
        excluded = ("payload_hash_b64", "receipt_sig_b64", "sig_alg")
        core = {k: v for k, v in obj.items() if k not in excluded}
        try:
            payload = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
        except Exception as e:  # noqa: S112
            logging.exception("Failed to canonicalize receipt core from %s: %s", f, e)
            continue
        leaves.append(hashlib.sha256(payload).digest())
    leaves_b64 = [base64.b64encode(x).decode() for x in leaves]
    sth = build_sth(leaves_b64)
    STH_FILE.write_text(json.dumps(sth, indent=2))
    return sth

def extract_handshake_tuple(headers: dict) -> dict:
    """Extract negotiated TLS / PQC parameters from ingress headers.

    Expected (case-insensitive) headers per requirement:
      - X-TLS-Protocol  -> tls_version
      - X-TLS-Cipher    -> cipher
      - X-TLS-Group     -> group_or_kem
      - X-ALPN (or legacy X-TLS-ALPN) -> alpn
      - X-TLS-SNI       -> sni

    We also tolerate the earlier "X-TLS-ALPN" header for backwards compatibility.
    """
    def h(*names: str):  # return first present header value
        for n in names:
            v = headers.get(n)
            if v is not None:
                return v
        return None

    return {
        "tls_version": h("x-tls-protocol"),
        "cipher": h("x-tls-cipher"),
        "group_or_kem": h("x-tls-group"),
        "sig_alg": "ed25519",  # placeholder until real extraction
        "sni": h("x-tls-sni"),
        "peer_ip": None,
        "alpn": h("x-alpn", "x-tls-alpn"),
        "client_cert_sha256": None,
        "client_cert_sig_alg": None,
    }


def _compute_policy_hash(doc: PolicyDoc) -> str:
    """Deterministic hash (base64 sha256) of the policy doc for receipts."""
    core = doc.model_dump()
    payload = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(hashlib.sha256(payload).digest()).decode()


_deny_window: list[float] = []  # timestamps of recently emitted soft deny receipts


@app.middleware("http")
async def soft_policy_enforcer(request: Request, call_next):  # pragma: no cover (tested indirectly)
    path = request.url.path
    # Skip control endpoints
    if path.startswith(("/events", "/policy", "/health", "/receipts")):
        return await call_next(request)
    # If no other application routes exist, this will rarely trigger; placeholder for integration.
    negotiated = extract_handshake_tuple(request.headers)
    group = negotiated.get("group_or_kem")
    policy = load_policy()
    deny_reason: str | None = None
    if group is None:
        deny_reason = "missing_group"
    elif group in policy.deny_groups:
        deny_reason = "explicit_deny"
    elif policy.allow_groups and group not in policy.allow_groups:
        deny_reason = "not_in_allowlist"

    if deny_reason:
        # Rate limit deny receipts to avoid spam
        now = time.time()
        window_seconds = settings.soft_policy_window_seconds()
        limit = settings.soft_policy_deny_limit
        # prune
        while _deny_window and now - _deny_window[0] > window_seconds:
            _deny_window.pop(0)
        emit = len(_deny_window) < limit
        if emit:
            _deny_window.append(now)
        # Emit a deny enforcement receipt representing a soft validation failure
        if emit:
            sk, _ = _load_keys()
            rec = {
                "kind": "pqc.enforcement",
                "ts_ms": int(time.time() * 1000),
                "policy_version": policy.version,
                "policy_hash_b64": _compute_policy_hash(policy),
                "negotiated": negotiated,
                "decision": {"allow": False, "reason": deny_reason},
                "prev_receipt_hash_b64": _read_prev_hash(),
            }
            signed = sign_receipt_ed25519(rec, sk)
            hash_prefix = signed["payload_hash_b64"][:8].replace("/", "_").replace("+", "-")
            _store_signed_receipt(f"pqc_enforcement_{hash_prefix}", signed)
            _refresh_sth()
        return Response(
            status_code=403,
            media_type="application/json",
            content=json.dumps({
                "detail": "pqc policy violation",
                "reason": deny_reason,
                "receipt_emitted": emit,
            }),
        )
    return await call_next(request)


@app.post("/events")
def post_event(request: Request, body: dict = Body(...)):  # noqa: B008 FastAPI dependency pattern
    sk, vk = _load_keys()
    kind = body.get("kind")
    # Allow new schema alias 'type'
    if kind is None and body.get("type"):
        kind = body["type"]
        body["kind"] = kind
    # Validate & sign with server key (control plane as anchor)
    if kind == "pqc.enforcement":
        # If client omitted negotiated section, attempt to build from headers
        if "negotiated" not in body:
            body["negotiated"] = extract_handshake_tuple(request.headers)
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

    # Outward compatibility layer: include new field naming schema while retaining legacy fields.
    # New outward keys required: type, time (RFC3339), policy_id, decision (string), reason,
    # negotiated { protocol, kex_group, sigalg, cipher }, peer, prev_receipt_hash_b64,
    # payload_hash_b64, signature_b64, signer_kid.
    # Derive RFC3339 time from ts_ms if present.
    from datetime import datetime, timezone
    ts_ms = signed.get("ts_ms")
    if ts_ms is not None:
        dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
        rfc3339 = dt.isoformat().replace("+00:00", "Z")
    else:
        rfc3339 = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    decision_obj = signed.get("decision", {}) if isinstance(signed.get("decision"), dict) else {}
    decision_str = "allow" if decision_obj.get("allow") else "deny"
    reason_val = decision_obj.get("reason")
    nego = signed.get("negotiated", {}) or {}
    outward_negotiated = {
        "protocol": nego.get("tls_version"),
        "kex_group": nego.get("group_or_kem"),
        "sigalg": nego.get("sig_alg"),
        "cipher": nego.get("cipher"),
    }
    # signer_kid: stable hash of verify key
    signer_kid = base64.b64encode(hashlib.sha256(vk).digest()).decode()[:16]
    # Preserve raw negotiated under negotiated_raw; outward transformed becomes negotiated
    if "negotiated" in signed:
        signed.setdefault("negotiated_raw", signed.get("negotiated"))
    signed.update({
        "type": signed.get("kind"),
        "time": rfc3339,
        "policy_id": signed.get("policy_version"),
        "decision": decision_str,
        "reason": reason_val,
        "negotiated_summary": outward_negotiated,
        "peer": body.get("peer"),
        "signature_b64": signed.get("receipt_sig_b64"),
        "signer_kid": signer_kid,
    })
    return signed


@app.get("/echo")
def echo():
    """Simple placeholder application route subject to soft policy enforcement."""
    return {"ok": True}


@app.get("/receipts/latest")
def get_latest_receipt():  # pragma: no cover (tested separately)
    """Return most recent valid receipt JSON (by mtime) or 404.

    Uses SIGNET_STORAGE_DIR env var if set, else current DATA path.
    Valid receipts must parse as JSON object and contain 'kind' or 'type'.
    Skips unreadable / malformed files.
    """
    base_dir_env = os.getenv("SIGNET_STORAGE_DIR")
    base = Path(base_dir_env) if base_dir_env else DATA
    receipts_dir = base / "receipts"
    if not receipts_dir.exists():
        raise HTTPException(404, "no receipts")
    files = list(receipts_dir.glob("*.json"))
    if not files:
        raise HTTPException(404, "no receipts")
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    for p in files:
        try:
            obj = json.loads(p.read_text())
        except Exception as e:  # noqa: S112
            logging.exception("Failed to parse candidate latest receipt %s: %s", p, e)
            continue
        if isinstance(obj, dict) and ("kind" in obj or "type" in obj):
            return obj
    raise HTTPException(404, "no valid receipts found")
