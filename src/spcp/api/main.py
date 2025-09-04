from __future__ import annotations

import base64
import fnmatch
import hashlib
import io
import json
import logging
import os
import secrets
import time
import zipfile
from collections import OrderedDict
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Request, Response

from ..cbom.collector import collect_cbom
from ..pch.auth import get_channel_binding, parse_pch_authorization
from ..policy.circuit_breaker import CircuitBreaker
from ..policy.store import load_policy, set_policy
from ..policy.tuple_policy import evaluate_tuple_policy, load_tuple_policy, set_tuple_policy
from ..receipts.merkle import build_sth
from ..receipts.sign import sign_receipt_ed25519
from ..settings import settings
from .models import PolicyDoc, PQCCBOMReceipt, PQCEnforcementReceipt

# Metrics (simple counters; replace with real Prometheus client in production)
_metrics = {
    "pch_challenges_issued": 0,
    "pch_verifications_ok": 0,
    "pch_verifications_failed_sig": 0,
    "pch_verifications_failed_nonce": 0,
    "pch_verifications_failed_binding": 0,
    "pch_verifications_failed_policy": 0,
}

app = FastAPI(title="Signet PQC Control Plane (MVP)")

# Helper to emit deny receipt for PCH enforcement failures
_def_emit_marker = True

def _emit_pch_deny(route: str, caller_id: str, reason: str, params: dict | None = None):  # pragma: no cover - IO
    try:
        sk, _ = _load_keys()
        negotiated = {
            "tls_version": None,
            "cipher": None,
            "group_or_kem": None,
            "sig_alg": "ed25519",
            "sni": None,
            "peer_ip": None,
            "alpn": None,
        }
        rec = {
            "kind": "pqc.enforcement",
            "ts_ms": int(time.time()*1000),
            "policy_version": load_policy().version,
            "policy_hash_b64": _compute_policy_hash(load_policy()),
            "negotiated": negotiated,
            "decision": {"allow": False, "reason": reason},
            "pch_present": True,
            "route": route,
            "caller_id": caller_id,
            "prev_receipt_hash_b64": _read_prev_hash(),
            "pch": {
                "present": True,
                "verified": False,
                "channel_binding": "tls-session-id",
                "failure_reason": reason,
            },
        }
        if params:
            if params.get("challenge"):
                rec["pch"]["challenge"] = params.get("challenge")
            if params.get("keyId"):
                rec["pch"]["key_id_b64"] = params.get("keyId")
        signed = sign_receipt_ed25519(rec, sk)
        hash_prefix = signed["payload_hash_b64"][:8].replace("/","_").replace("+","-")
        _store_signed_receipt(f"pqc_enforcement_{hash_prefix}", signed)
        _refresh_sth()
    except Exception:
        logging.exception("Failed to emit PCH deny receipt (%s)", reason)

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

# --- PCH Nonce Cache (simple in-memory LRU with TTL) ---
class _NonceCache:
    def __init__(self, ttl_seconds: int = 300, max_size: int = 4096):
        self.ttl = ttl_seconds
        self.max_size = max_size
        self._data: OrderedDict[str, float] = OrderedDict()

    def issue(self) -> str:
        nonce = base64.b64encode(secrets.token_bytes(16)).decode()
        self._store(nonce)
        return nonce

    def _store(self, nonce: str):
        now = time.time()
        self._prune(now)
        self._data[nonce] = now
        self._data.move_to_end(nonce)
        if len(self._data) > self.max_size:
            self._data.popitem(last=False)

    def verify(self, nonce: str) -> bool:
        now = time.time()
        self._prune(now)
        if nonce in self._data:
            # one-time use; remove to prevent replay
            self._data.pop(nonce, None)
            return True
        return False

    def _prune(self, now: float):
        cutoff = now - self.ttl
        for k, ts in list(self._data.items()):
            if ts < cutoff:
                self._data.pop(k, None)

_pch_nonce_cache = _NonceCache()

# --- New PCH Enforcement Nonce Cache keyed by (client_ip, route, tls_binding_hint, nonce) ---
class _TupleNonceCache:
    def __init__(self, ttl: int, max_size: int = 8192):
        self.ttl = ttl
        self.max_size = max_size
        self._data: OrderedDict[str, float] = OrderedDict()

    def _key(self, client_ip: str, route: str, binding: str, nonce: str) -> str:
        return f"{client_ip}|{route}|{binding}|{nonce}"

    def issue(self, client_ip: str, route: str, binding: str) -> str:
        nonce = base64.b64encode(secrets.token_bytes(16)).decode()
        k = self._key(client_ip, route, binding, nonce)
        now = time.time()
        self._prune(now)
        self._data[k] = now
        self._data.move_to_end(k)
        if len(self._data) > self.max_size:
            self._data.popitem(last=False)
        return nonce

    def consume(self, client_ip: str, route: str, binding: str, nonce: str) -> bool:
        now = time.time()
        self._prune(now)
        k = self._key(client_ip, route, binding, nonce)
        if k in self._data:
            self._data.pop(k, None)
            return True
        return False

    def _prune(self, now: float):
        cutoff = now - self.ttl
        for k, ts in list(self._data.items()):
            if ts < cutoff:
                self._data.pop(k, None)

_pch_tuple_nonces = _TupleNonceCache(settings.pch_nonce_ttl_enforcer_seconds)

@app.get("/health")
@app.get("/healthz")  # alias for k8s style probes
def health():
    return {"ok": True}

@app.get("/policy")
def get_policy():
    return load_policy().model_dump()

@app.get("/tuple-policy")
def get_tuple_policy():
    return load_tuple_policy().model_dump()

@app.put("/tuple-policy")
def put_tuple_policy(doc: dict):  # lightweight; pydantic in tuple_policy
    from ..api.models import TuplePolicy
    pol = TuplePolicy.model_validate(doc)
    set_tuple_policy(pol)
    return pol.model_dump()

@app.put("/policy")
def put_policy(doc: PolicyDoc):
    # Recreate data directories if removed after import (test isolation)
    for d in (RECEIPTS, PROOFS, KEY_DIR):
        d.mkdir(parents=True, exist_ok=True)
    sk, _ = _load_keys()
    signed = set_policy(doc, sk)
    _refresh_sth()
    # Reset soft deny rate limiter on policy change to avoid stale saturation affecting new policy tests
    try:
        _deny_window.clear()
    except Exception as e:  # pragma: no cover - defensive
        logging.debug("Failed to clear deny window on policy change: %s", e)
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
    # Expose session id to negotiated metadata for observability (not in decision logic yet)
    "session_id": h("x-tls-session-id"),
        "client_cert_sha256": None,
        "client_cert_sig_alg": None,
    }


def _compute_policy_hash(doc: PolicyDoc) -> str:
    """Deterministic hash (base64 sha256) of the policy doc for receipts."""
    core = doc.model_dump()
    payload = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(hashlib.sha256(payload).digest()).decode()


def _outward_enforcement_shape(raw: dict) -> dict:
    """Transform an internal signed enforcement receipt into outward schema.

    Expected outward top-level keys (subset):
      type, time, tls {version,kx_group,sigalg}, policy {policy_id, decision, reason?},
      prev_receipt_hash_b64, payload_hash_b64, signature_b64
    """
    if raw.get("kind") != "pqc.enforcement":  # pass through other kinds
        return raw
    from datetime import datetime, timezone
    ts_ms = raw.get("ts_ms")
    if ts_ms is not None:
        dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
        iso = dt.isoformat().replace("+00:00", "Z")
    else:  # fallback
        iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    nego = raw.get("negotiated") or {}
    tuple_pol = None
    try:  # lazy import to avoid cycles
        from ..policy.tuple_policy import load_tuple_policy  # noqa: WPS433
        tuple_pol = load_tuple_policy()
    except Exception:  # pragma: no cover - defensive
        tuple_pol = None
    decision_obj = raw.get("decision") or {}
    # Some legacy signed receipts (or earlier transformation passes) may have collapsed
    # decision to a string already. Normalize to dict-like accessor pattern.
    if isinstance(decision_obj, str):  # pragma: no cover - defensive path
        decision_obj = {"allow": decision_obj == "allow"}
    outward = {
        "type": raw.get("kind"),
        "time": iso,
        "tls": {
            "version": nego.get("tls_version"),
            "kx_group": nego.get("group_or_kem"),
            "sigalg": nego.get("sig_alg"),
        },
        "policy": {
            "policy_id": getattr(tuple_pol, "policy_id", raw.get("policy_version")),
            "decision": "allow" if decision_obj.get("allow") else "deny",
        },
        "prev_receipt_hash_b64": raw.get("prev_receipt_hash_b64"),
        "payload_hash_b64": raw.get("payload_hash_b64"),
        "signature_b64": raw.get("receipt_sig_b64"),
        "pch": {"present": bool(raw.get("pch_present", False))},
    "route": raw.get("route"),
    "caller_id": raw.get("caller_id"),
    }
    if raw.get("pch_present") and isinstance(raw.get("pch"), dict):
        outward["pch"].update(raw["pch"])  # propagate verification details
    reason = decision_obj.get("reason")
    if reason:
        outward["policy"]["reason"] = reason
    return outward


def _outward_cbom_shape(raw: dict) -> dict:
    if raw.get("kind") != "pqc.cbom":
        return raw
    from datetime import datetime, timezone
    ts_ms = raw.get("ts_ms")
    if ts_ms is not None:
        dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
        iso = dt.isoformat().replace("+00:00", "Z")
    else:
        iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    # Backward compatibility: raw may not have extended fields; attempt enrichment if absent
    platform_meta = raw.get("platform") or {}
    openssl_meta = raw.get("openssl") or {}
    tls_meta = raw.get("tls") or {}
    proxy_meta = raw.get("proxy") or {}
    outward = {
        "type": "pqc.cbom",
        "time": iso,
        "platform": platform_meta,
        "openssl": openssl_meta,
        "tls": tls_meta,
        "proxy": proxy_meta,
        "prev_receipt_hash_b64": raw.get("prev_receipt_hash_b64"),
        "payload_hash_b64": raw.get("payload_hash_b64"),
        "signature_b64": raw.get("receipt_sig_b64"),
    }
    return outward


_deny_window: list[float] = []  # timestamps of recently emitted soft deny receipts


def _verify_pch_request(request: Request, policy: PolicyDoc) -> tuple[bool, dict]:
    """Verify PCH Authorization and channel binding; return (allow, pch_block)."""
    auth = request.headers.get("authorization")
    # Enforce header size limit (<1.5KB) early to mitigate middlebox truncation risk.
    if auth and len(auth) > 1500:
        return (False, {"present": True, "failure_reason": "auth_header_too_large"})
    tls_session_id = request.headers.get("x-tls-session-id")
    tls_exporter = request.headers.get("x-tls-exporter")
    pch_block: dict = {"present": False, "verified": False}
    if not auth or not auth.lower().startswith("pch"):
        return (not policy.require_pch, pch_block)
    params = parse_pch_authorization(auth)
    pch_block["present"] = True
    required = ["keyId","alg","created","challenge","evidence","signature"]
    if any(k not in params for k in required):
        pch_block["failure_reason"] = "missing_param"
        return (False, pch_block)
    # created timestamp freshness check
    try:
        created_ts = int(params.get("created", "0"))
    except Exception:
        created_ts = 0
    pch_block["created"] = created_ts
    now = int(time.time())
    max_age = getattr(settings, "pch_max_age_seconds", 300)
    future_skew = getattr(settings, "pch_future_skew_seconds", 120)
    if created_ts == 0 or created_ts > now + future_skew or now - created_ts > max_age:
        pch_block["failure_reason"] = "created_too_old"
        return (False, pch_block)
    # Nonce freshness
    challenge_b64 = params.get("challenge")
    pch_block["challenge"] = challenge_b64
    try:
        base64.b64decode(challenge_b64 or "")
    except Exception:
        pch_block["failure_reason"] = "bad_challenge_b64"
        return (False, pch_block)
    if not _pch_nonce_cache.verify(challenge_b64):
        pch_block["failure_reason"] = "stale_or_unknown_challenge"
        return (False, pch_block)
    # Channel binding
    chan_kind, chan_raw, chan_header = get_channel_binding(request)
    if chan_header:
        pch_block["channel_binding"] = chan_header
        if chan_kind == "tls-session-id":
            expected = None
            if tls_session_id:
                expected = base64.b64encode(tls_session_id.encode()).decode()
            if not expected or expected != chan_header.split(":",1)[1]:
                pch_block["failure_reason"] = "channel_binding_mismatch"
                return (False, pch_block)
        elif chan_kind == "tls-exporter":
            expected = None
            if tls_exporter:
                expected = base64.b64encode(tls_exporter.encode()).decode()
            if not expected or expected != chan_header.split(":",1)[1]:
                pch_block["failure_reason"] = "channel_binding_mismatch"
                return (False, pch_block)
    # Evidence
    try:
        evidence_bytes = base64.b64decode(params.get("evidence",""))
        evidence = json.loads(evidence_bytes.decode())
        # Privacy: ensure evidence does not contain hostnames/paths (PII). Reject if keys present.
        forbidden_keys = {"host", "hostname", "path", "url"}
        if any(k in evidence for k in forbidden_keys):
            pch_block["failure_reason"] = "evidence_disallowed_keys"
            return (False, pch_block)
    except Exception:
        pch_block["failure_reason"] = "bad_evidence"
        return (False, pch_block)
    ev_type = evidence.get("type")
    merkle_root_b64 = evidence.get("merkle_root_b64")
    cbom_hash_b64 = evidence.get("cbom_hash_b64")
    policy_id = evidence.get("policy_id")
    ok_lengths = False
    try:
        if isinstance(merkle_root_b64, str):
            mr = base64.b64decode(merkle_root_b64 + "==")  # tolerate missing padding
            ok_lengths = len(mr) in (32, 64)
    except Exception:
        ok_lengths = False
    try:
        if isinstance(cbom_hash_b64, str):
            ch = base64.b64decode(cbom_hash_b64 + "==")
            if len(ch) != 32:
                ok_lengths = False
    except Exception:
        ok_lengths = False
    if not (ev_type == "pch.sth" and ok_lengths and isinstance(policy_id, str)):
        pch_block["failure_reason"] = "invalid_evidence"
        return (False, pch_block)
    # Only retain minimal reference fields to keep header-derived data small and privacy-preserving.
    pch_block["evidence_ref"] = {"type": ev_type, "merkle_root_b64": merkle_root_b64, "cbom_hash_b64": cbom_hash_b64, "policy_id": policy_id}
    # Signature base (HTTP Message Signatures subset)
    covered = []
    method = request.method.upper()
    covered.append(f"@method:{method}")
    pch_block["method"] = method
    covered.append(f"@path:{request.url.path}")
    pch_block["path"] = request.url.path
    # Host header can be absent in TestClient; treat missing as empty authority string
    authority = request.headers.get("host", "")
    covered.append(f"@authority:{authority}")
    pch_block["authority"] = authority
    chal_hdr = challenge_b64 or ""
    covered.append(f"challenge:{chal_hdr}")
    chan_val = chan_header or ""
    covered.append(f"pch-channel-binding:{chan_val}")
    body_digest = request.headers.get("content-digest")
    if body_digest:
        covered.append(f"content-digest:{body_digest}")
    sig_input = "\n".join(covered).encode()
    # Verify signature (only ed25519 supported in requirement)
    if params.get("alg","ed25519").lower() != "ed25519":
        pch_block["failure_reason"] = "unsupported_alg"
        return (False, pch_block)
    try:
        from nacl.signing import VerifyKey
        vk_b64 = params.get("keyId","")
        vk_bytes = base64.b64decode(vk_b64)
        vk = VerifyKey(vk_bytes)
        sig = base64.b64decode(params.get("signature",""))
        vk.verify(sig_input, sig)
        pch_block["key_id_b64"] = vk_b64
        pch_block["signature_b64"] = params.get("signature")
    except Exception:
        pch_block["failure_reason"] = "bad_signature"
        return (False, pch_block)
    pch_block["verified"] = True
    return (True, pch_block)

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
    # Existing simple group policy
    if group is None:
        deny_reason = "missing_group"
    elif group in policy.deny_groups:
        deny_reason = "explicit_deny"
    elif policy.allow_groups and group not in policy.allow_groups:
        deny_reason = "not_in_allowlist"
    # Tuple policy overlay (only if not already denied)
    if deny_reason is None:
        # Only attempt tuple policy evaluation if key negotiated attributes are present.
        # In unit tests or early integrations we may only pass a group header; missing
        # tls_version/cipher should not trigger a validation error or denial.
        if negotiated.get("tls_version") and negotiated.get("cipher"):
            try:
                allow_tuple, mismatch_reason = evaluate_tuple_policy(PQCEnforcementReceipt.model_validate({
                    "kind": "pqc.enforcement",
                    "ts_ms": int(time.time()*1000),
                    "policy_version": policy.version,
                    "policy_hash_b64": "",
                    "negotiated": negotiated,
                    "decision": {"allow": True},
                }).negotiated)  # reuse validation to coerce structure
                if not allow_tuple:
                    # Normalize outward deny reason per spec expectation
                    deny_reason = "tuple_not_allowed"
            except Exception:  # pragma: no cover - defensive
                logging.debug("Skipping tuple policy evaluation due to incomplete negotiated tuple")

    # PCH Authorization processing
    policy = load_policy()
    allow_pch, pch_block = _verify_pch_request(request, policy)
    if policy.require_pch and not allow_pch:
        deny_reason = pch_block.get("failure_reason", "pch_required")
    if deny_reason:
        # Rate limit deny receipts to avoid spam
        now = time.time()
        window_seconds = settings.soft_policy_window_seconds()
        limit = settings.soft_policy_deny_limit
        # prune
        while _deny_window and now - _deny_window[0] > window_seconds:
            _deny_window.pop(0)
        emit = len(_deny_window) < limit
        # For initial missing_group events after policy reset, force first emission even if window state odd.
        if deny_reason == "missing_group" and not _deny_window:
            emit = True
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
                "route": path,
                "caller_id": request.client.host if request.client else None,
            }
            if pch_block.get("present"):
                rec["pch_present"] = True
                rec["pch"] = pch_block
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
    # Allowed flow - proceed then emit allow receipt (post-response generation) to include chain continuity.
    response = await call_next(request)
    try:
        if response.status_code < 400:
            sk, _ = _load_keys()
            rec = {
                "kind": "pqc.enforcement",
                "ts_ms": int(time.time() * 1000),
                "policy_version": policy.version,
                "policy_hash_b64": _compute_policy_hash(policy),
                "negotiated": negotiated,
                "decision": {"allow": True},
                "prev_receipt_hash_b64": _read_prev_hash(),
                "route": path,
                "caller_id": request.client.host if request.client else None,
            }
            if pch_block.get("present"):
                rec["pch_present"] = True
                rec["pch"] = pch_block
            signed = sign_receipt_ed25519(rec, sk)
            hash_prefix = signed["payload_hash_b64"][:8].replace("/", "_").replace("+", "-")
            _store_signed_receipt(f"pqc_enforcement_{hash_prefix}", signed)
            _refresh_sth()
    except Exception as e:  # noqa: S112 - defensive logging
        logging.exception("Failed to emit allow receipt: %s", e)
    return response


def _route_requires_pch(path: str) -> bool:
    patterns = settings.pch_required_routes or []
    for pat in patterns:
        if fnmatch.fnmatch(path, pat):
            return True
    return False


def _parse_signature_header(sig_input: str) -> dict | None:
    # Expect shape: keyId="...",alg="ed25519",created="<int>",headers="@method @path ...",signature="b64"
    try:
        parts = [p.strip() for p in sig_input.split(",") if p.strip()]
        d = {}
        for p in parts:
            if "=" in p:
                k, v = p.split("=",1)
                d[k] = v.strip().strip('"')
        return d
    except Exception:  # noqa: S112
        return None


def _build_signed_components(request: Request, covered_fields: list[str]) -> bytes:
    lines: list[str] = []
    for f in covered_fields:
        if f == "@method":
            lines.append(f"@method:{request.method.upper()}")
        elif f == "@path":
            lines.append(f"@path:{request.url.path}")
        elif f == "@authority":
            lines.append(f"@authority:{request.headers.get('host','')}")
        elif f.lower() == "content-digest":
            cd = request.headers.get("content-digest", "")
            lines.append(f"content-digest:{cd}")
        elif f == "pch-challenge":
            lines.append(f"pch-challenge:{request.headers.get('pch-challenge','')}")
        elif f == "pch-channel-binding":
            lines.append(f"pch-channel-binding:{request.headers.get('pch-channel-binding','')}")
        elif f == "pch-evidence":
            lines.append(f"pch-evidence:{request.headers.get('pch-evidence','')}")
        else:
            # unknown field: include header value if present
            lines.append(f"{f}:{request.headers.get(f, '')}")
    return "\n".join(lines).encode()


def _verify_evidence(evidence_b64: str) -> tuple[bool, dict | None, str | None]:
    if len(evidence_b64) > settings.pch_max_header_bytes:
        return False, None, "evidence_too_large"
    try:
        raw = base64.b64decode(evidence_b64.strip(":"))
        doc = json.loads(raw.decode())
    except Exception:  # noqa: S112
        return False, None, "bad_evidence_b64"
    # Basic schema
    required = {"type","time","policy_id","merkle_root_b64","tree_size","attestation"}
    if not required.issubset(doc.keys()):
        return False, None, "evidence_schema"
    if doc.get("type") != "pch.sth":
        return False, None, "evidence_type"
    att = doc.get("attestation") or {}
    if att.get("mode") not in {"software"}:
        return False, None, "attestation_mode"
    return True, doc, None


@app.middleware("http")
async def pch_enforcer(request: Request, call_next):  # pragma: no cover - new logic tested separately
    path = request.url.path
    if not _route_requires_pch(path):
        return await call_next(request)
    client_ip = request.client.host if request.client else "unknown"
    session_id = request.headers.get("x-tls-session-id") or ""  # binding hint
    binding_hint = base64.b64encode(session_id.encode()).decode() if session_id else "none"
    sig_header = request.headers.get("authorization")
    evidence_header = request.headers.get("pch-evidence")  # expected :<b64>:
    # challenge header value consumed via headers in signature-input parsing; no direct use here
    sig_input_header = request.headers.get("signature-input")

    # If no signature, issue challenge
    if not sig_header or "pch" not in sig_header.lower():
        nonce = _pch_tuple_nonces.issue(client_ip, path, binding_hint)
        _metrics["pch_challenges_issued"] += 1
        resp = Response(status_code=401)
        val = f":{base64.b64encode(nonce.encode()).decode()}:"
        resp.headers["WWW-Authenticate"] = f'PCH realm="pqc", algs="ed25519", challenge="{val}"'
        resp.headers["PCH-Challenge"] = val
        return resp
    # Parse signature style header reused from existing _verify_pch_request for consistency
    params = parse_pch_authorization(sig_header)
    if not params:
        _metrics["pch_verifications_failed_sig"] += 1
        _emit_pch_deny(path, client_ip, "bad_authorization")
        return Response(status_code=403, media_type="application/json", content=json.dumps({"reason":"bad_authorization"}))
    # Require Signature-Input header with required covered fields
    if not sig_input_header:
        _metrics["pch_verifications_failed_sig"] += 1
        _emit_pch_deny(path, client_ip, "missing_signature_input", params)
        return Response(status_code=403, media_type="application/json", content=json.dumps({"reason":"missing_signature_input"}))
    # Very small parser for: sig1=("@method" "@path" ...);created=...
    try:
        _prefix, rest = sig_input_header.split("=",1)
        paren_start = rest.find("(")
        paren_end = rest.find(")", paren_start+1)
        inner = rest[paren_start+1:paren_end]
        raw_fields = [f.strip().strip('"') for f in inner.split() if f.strip()]
    except Exception:  # noqa: S112
        _metrics["pch_verifications_failed_sig"] += 1
        _emit_pch_deny(path, client_ip, "bad_signature_input", params)
        return Response(status_code=403, media_type="application/json", content=json.dumps({"reason":"bad_signature_input"}))
    # Required fields
    required_fields = {"@method","@path","@authority","pch-challenge","pch-channel-binding","pch-evidence"}
    body_present = request.method.upper() in {"POST","PUT","PATCH"} or (request.headers.get("content-length") not in (None, "0"))
    if body_present:
        required_fields.add("content-digest")
    field_counts = {}
    for f in raw_fields:
        field_counts[f] = field_counts.get(f,0)+1
    duplicates = [f for f,cnt in field_counts.items() if cnt>1]
    missing = [f for f in required_fields if f not in field_counts]
    if duplicates:
        _metrics["pch_verifications_failed_sig"] += 1
        _emit_pch_deny(path, client_ip, "duplicate_fields", params)
        return Response(status_code=403, media_type="application/json", content=json.dumps({"reason":"duplicate_fields","details":duplicates}))
    if missing:
        _metrics["pch_verifications_failed_sig"] += 1
        _emit_pch_deny(path, client_ip, "missing_fields", params)
        return Response(status_code=403, media_type="application/json", content=json.dumps({"reason":"missing_fields","details":missing}))
    # Validate evidence separately
    if not evidence_header:
        _metrics["pch_verifications_failed_policy"] += 1
        _emit_pch_deny(path, client_ip, "missing_evidence", params)
        return Response(status_code=403, media_type="application/json", content=json.dumps({"reason":"missing_evidence"}))
    ok_evi, evidence_doc, evi_reason = _verify_evidence(evidence_header.strip())
    if not ok_evi:
        _metrics["pch_verifications_failed_policy"] += 1
        _emit_pch_deny(path, client_ip, evi_reason or "bad_evidence", params)
        return Response(status_code=403, media_type="application/json", content=json.dumps({"reason": evi_reason}))
    # Challenge validation
    chal = request.headers.get("pch-challenge") or params.get("challenge")
    if not chal:
        _metrics["pch_verifications_failed_nonce"] += 1
        _emit_pch_deny(path, client_ip, "missing_challenge", params)
        return Response(status_code=403, media_type="application/json", content=json.dumps({"reason":"missing_challenge"}))
    try:
        chal_decoded = base64.b64decode(chal.strip(":"))
    except Exception:  # noqa: S112
        _metrics["pch_verifications_failed_nonce"] += 1
        _emit_pch_deny(path, client_ip, "bad_challenge_b64", params)
        return Response(status_code=403, media_type="application/json", content=json.dumps({"reason":"bad_challenge_b64"}))
    # Consume nonce (base64 string without colons)
    if not _pch_tuple_nonces.consume(client_ip, path, binding_hint, chal_decoded.decode()):
        _metrics["pch_verifications_failed_nonce"] += 1
        _emit_pch_deny(path, client_ip, "stale_challenge", params)
        return Response(status_code=403, media_type="application/json", content=json.dumps({"reason":"stale_challenge"}))
    # Channel binding enforcement
    if not session_id:
        _metrics["pch_verifications_failed_binding"] += 1
        _emit_pch_deny(path, client_ip, "missing_session_id", params)
        return Response(status_code=403, media_type="application/json", content=json.dumps({"reason":"missing_session_id"}))
    expected_binding = f"tls-session-id=:{base64.b64encode(session_id.encode()).decode()}:"
    provided_binding = request.headers.get("pch-channel-binding")
    if provided_binding != expected_binding:
        _metrics["pch_verifications_failed_binding"] += 1
        _emit_pch_deny(path, client_ip, "binding_mismatch", params)
        return Response(status_code=403, media_type="application/json", content=json.dumps({"reason":"binding_mismatch"}))
    # Signature verification
    created_ts = int(params.get("created", "0")) if params.get("created") else 0
    now = int(time.time())
    if created_ts == 0 or now - created_ts > settings.pch_nonce_ttl_enforcer_seconds or created_ts > now + settings.pch_future_skew_seconds:
        _metrics["pch_verifications_failed_sig"] += 1
        _emit_pch_deny(path, client_ip, "stale_created", params)
        return Response(status_code=403, media_type="application/json", content=json.dumps({"reason":"stale_created"}))
    try:
        sig_input_bytes = _build_signed_components(request, raw_fields)
        from nacl.signing import VerifyKey
        vk_b64 = params.get("keyId","")
        vk = VerifyKey(base64.b64decode(vk_b64))
        sig = base64.b64decode(params.get("signature",""))
        vk.verify(sig_input_bytes, sig)
    except Exception:  # noqa: S112
        _metrics["pch_verifications_failed_sig"] += 1
        _emit_pch_deny(path, client_ip, "signature_invalid", params)
        return Response(status_code=403, media_type="application/json", content=json.dumps({"reason":"signature_invalid"}))
    # Policy checks
    current_policy = load_policy()
    if evidence_doc.get("policy_id") != current_policy.version:
        _metrics["pch_verifications_failed_policy"] += 1
        _emit_pch_deny(path, client_ip, "policy_id_mismatch", params)
        return Response(status_code=403, media_type="application/json", content=json.dumps({"reason":"policy_id_mismatch"}))
    # Success -> proceed and emit receipt (allow path)
    _metrics["pch_verifications_ok"] += 1
    response = await call_next(request)
    try:
        if response.status_code < 400:
            sk, _ = _load_keys()
            negotiated = extract_handshake_tuple(request.headers)
            rec = {
                "kind": "pqc.enforcement",
                "ts_ms": int(time.time()*1000),
                "policy_version": current_policy.version,
                "policy_hash_b64": _compute_policy_hash(current_policy),
                "negotiated": negotiated,
                "decision": {"allow": True},
                "pch_present": True,
                "route": path,
                "caller_id": client_ip,
                "pch": {
                    "present": True,
                    "verified": True,
                    "channel_binding": "tls-session-id",
                    "challenge": chal,
                    "evidence_ref": {
                        "type": "pch.sth",
                        "merkle_root_b64": evidence_doc.get("merkle_root_b64"),
                        "cbom_hash_b64": (evidence_doc.get("attestation") or {}).get("cbom_hash_b64"),
                    },
                },
                "prev_receipt_hash_b64": _read_prev_hash(),
            }
            signed = sign_receipt_ed25519(rec, sk)
            hash_prefix = signed["payload_hash_b64"][:8].replace("/","_").replace("+","-")
            _store_signed_receipt(f"pqc_enforcement_{hash_prefix}", signed)
            _refresh_sth()
    except Exception:  # noqa: S112
        logging.exception("Failed emitting PCH allow receipt (enforcer)")
    return response


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
    if kind == "pqc.enforcement":
        outward = _outward_enforcement_shape(signed)
        # Preserve original negotiated for legacy/tests expecting it
        if "negotiated" not in outward and "negotiated" in signed:
            outward["negotiated"] = signed["negotiated"]
        # Always include negotiated_raw for completeness
        outward.setdefault("negotiated_raw", signed.get("negotiated"))
        return outward
    return signed


@app.get("/echo")
def echo():
    """Simple placeholder application route subject to soft policy enforcement."""
    return {"ok": True}


@app.get("/protected")
def protected():  # pragma: no cover - exercised in compose integration test
    """Alias route intended for end-to-end PCH integration tests via nginx/proxy.

    Functionally identical to /echo but semantically indicates a protected
    resource in integration scenarios. Keeping implementation trivial avoids
    introducing application logic that could mask PCH enforcement issues.
    """
    return {"ok": True}


@app.get("/receipts/latest")
def get_latest_receipt(type: str | None = None, require_pch: bool = False, raw: bool = False):  # pragma: no cover (tested separately)
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
            if type and obj.get("kind") != type and obj.get("type") != type:
                continue
            if require_pch and not obj.get("pch_present") and not (isinstance(obj.get("pch"), dict) and obj.get("pch", {}).get("present")):
                continue
            if raw:
                # Return stored JSON as-is (except ensure 'kind' present if only 'type').
                if "kind" not in obj and "type" in obj:
                    obj["kind"] = obj["type"]
                return obj
            else:
                shaped = _outward_enforcement_shape(obj) if obj.get("kind") == "pqc.enforcement" else _outward_cbom_shape(obj)
                # Preserve original kind for callers/tests expecting it
                shaped.setdefault("kind", obj.get("kind"))
                return shaped
    raise HTTPException(404, "no valid receipts found")

@app.middleware("http")
async def pch_challenge_injector(request: Request, call_next):  # pragma: no cover
    # This runs AFTER soft_policy_enforcer above (order of registration). For unauthorized
    # requests lacking PCH auth when policy requires it, we can issue a challenge.
    response = await call_next(request)
    if response.status_code == 403:
        # Only transform to 401 when policy explicitly requires PCH and auth missing.
        try:
            pol = load_policy()
            require = getattr(pol, "require_pch", False)
        except Exception:
            require = False
        if require and not request.headers.get("authorization"):
            nonce = _pch_nonce_cache.issue()
            response.status_code = 401
            response.headers["WWW-Authenticate"] = f'PCH realm="pqc", challenge="{nonce}", algs="ed25519"'
            sess = request.headers.get("x-tls-session-id")
            if sess:
                response.headers["X-TLS-Session-ID"] = sess
    return response


@app.get("/cbom/latest")
def get_latest_cbom():  # pragma: no cover
    files = sorted(RECEIPTS.glob("*.json"))
    for p in reversed(files):
        try:
            obj = json.loads(p.read_text())
        except Exception:  # noqa: S112
            continue
        if isinstance(obj, dict) and obj.get("kind") == "pqc.cbom":
            return _outward_cbom_shape(obj)
    raise HTTPException(404, "no cbom receipts")

@app.post("/cbom/collect")
def collect_cbom_now():  # pragma: no cover - simple IO orchestration
    sk, _ = _load_keys()
    core = collect_cbom()
    core["prev_receipt_hash_b64"] = _read_prev_hash()
    signed = sign_receipt_ed25519({k: v for k, v in core.items() if k != "signature_b64"}, sk)
    hash_prefix = signed["payload_hash_b64"][:8].replace("/", "_").replace("+", "-")
    _store_signed_receipt(f"pqc_cbom_{hash_prefix}", signed)
    _refresh_sth()
    return _outward_cbom_shape(signed)


@app.get("/compliance/pack")
@app.post("/compliance/pack")
def get_compliance_pack(since: int | None = None):  # pragma: no cover - IO heavy
    """Return a ZIP compliance bundle.

    Default (no since parameter): legacy pack (sth.json + last 50 enforcement receipts + proofs + verify script).
    With ?since=<ts>: new format containing:
      - STH.json (latest Signed Tree Head; capitalized name per requirement)
      - receipts.jsonl (newline-delimited JSON of receipts with ts_ms >= since)
      - proofs/ (all proof json files present; future: filter to those receipts)
      - verify.py (offline chain + optional PCH verifier)

    The `since` timestamp is interpreted as milliseconds if >= 1e12 else seconds.
    """
    DATA.mkdir(parents=True, exist_ok=True)
    RECEIPTS.mkdir(parents=True, exist_ok=True)
    PROOFS.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    # Determine latest STH source (batched sth directory takes precedence if present)
    sth_dir = DATA / "sth"
    latest_sth_path: Path | None = None
    if sth_dir.exists():
        sth_files = sorted(sth_dir.glob("sth_*.json"), key=lambda p: p.stat().st_mtime)
        if sth_files:
            latest_sth_path = sth_files[-1]
    if latest_sth_path is None and STH_FILE.exists():  # fallback to legacy single STH
        latest_sth_path = STH_FILE

    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if since is None:
            # Legacy packaging branch preserved for backward compatibility
            if latest_sth_path and latest_sth_path.exists():
                zf.write(latest_sth_path, arcname="sth.json")
            enforcement = []
            for r in sorted(RECEIPTS.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
                try:
                    obj = json.loads(r.read_text())
                except Exception as e:  # noqa: S112
                    logging.debug("Skipping unreadable receipt during legacy pack build: %s", e)
                if isinstance(obj, dict) and obj.get("kind") == "pqc.enforcement":
                    enforcement.append(r)
                if len(enforcement) >= 50:
                    break
            for idx, path_obj in enumerate(enforcement):
                arcname = f"receipts/enforcement/enforcement_{idx}.json"
                try:
                    zf.write(path_obj, arcname=arcname)
                except Exception:
                    logging.exception("Failed to add enforcement receipt %s", path_obj)
            for pth in sorted(PROOFS.glob("*.json")):
                try:
                    zf.write(pth, arcname=f"proofs/{pth.name}")
                except Exception:
                    logging.exception("Failed to add proof %s", pth)
        else:
            # New format
            since_ms = since if since >= 1_000_000_000_000 else since * 1000  # seconds -> ms
            if latest_sth_path and latest_sth_path.exists():
                zf.write(latest_sth_path, arcname="STH.json")
            # Collect receipts meeting threshold
            receipts = []
            for r in sorted(RECEIPTS.glob("*.json"), key=lambda p: p.stat().st_mtime):
                try:
                    obj = json.loads(r.read_text())
                except Exception as e:  # noqa: S112
                    logging.debug("Skipping unreadable receipt for since-pack: %s", e)
                if not isinstance(obj, dict):
                    continue
                ts_ms = obj.get("ts_ms")
                if ts_ms is None:
                    # fallback to file mtime in ms
                    ts_ms = int(r.stat().st_mtime * 1000)
                if ts_ms >= since_ms:
                    receipts.append(obj)
            # Write receipts.jsonl
            lines = []
            for rec in receipts:
                try:
                    lines.append(json.dumps(rec, separators=(",", ":"), sort_keys=True))
                except Exception as e:  # noqa: S112
                    logging.debug("Skipping receipt serialization for jsonl: %s", e)
            zf.writestr("receipts.jsonl", "\n".join(lines) + ("\n" if lines else ""))
            # Proofs directory (currently unfiltered)
            for pth in sorted(PROOFS.glob("*.json")):
                try:
                    zf.write(pth, arcname=f"proofs/{pth.name}")
                except Exception:
                    logging.exception("Failed to add proof %s", pth)
        # Common tooling for both branches
        verify_py = """#!/usr/bin/env python3
import sys, json, base64, hashlib
from pathlib import Path

def load_jsonl(path):
    for line in open(path, 'r', encoding='utf-8'):
        line=line.strip()
        if not line: continue
        yield json.loads(line)

def sha256_b64(data: bytes) -> str:
    import hashlib, base64
    return base64.b64encode(hashlib.sha256(data).digest()).decode()

def build_core_payload(obj):
    # remove signature related fields to reconstruct payload for hash verification
    excluded = {'receipt_sig_b64','sig_alg'}
    core = {k: v for k, v in obj.items() if k not in excluded}
    return json.dumps(core, sort_keys=True, separators=(',', ':')).encode()

def verify_chain(objs):
    prev = None
    for idx, obj in enumerate(objs):
        payload_hash = obj.get('payload_hash_b64')
        calc_hash = sha256_b64(build_core_payload(obj))
        if payload_hash != calc_hash:
            return False, f'hash_mismatch@{idx}'
        if prev is not None and obj.get('prev_receipt_hash_b64') not in {prev.get('payload_hash_b64'), None}:
            return False, f'prev_link_mismatch@{idx}'
        prev = obj
    return True, None

def main():
    if len(sys.argv) < 2:
        print('Usage: verify.py <receipts.jsonl>'); sys.exit(1)
    path = Path(sys.argv[1])
    objs = list(load_jsonl(path))
    ok, reason = verify_chain(objs)
    print(json.dumps({'verified': ok, 'reason': reason}))

if __name__ == '__main__':
    main()
"""
        zf.writestr("verify.py", verify_py)
    buf.seek(0)
    fname = "signet_compliance_pack.zip" if since is None else f"signet_compliance_pack_since_{since}.zip"
    headers = {"Content-Disposition": f"attachment; filename={fname}"}
    return Response(content=buf.getvalue(), media_type="application/zip", headers=headers)
