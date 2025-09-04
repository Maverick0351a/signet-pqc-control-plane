
from __future__ import annotations
import time, httpx, hashlib, base64
from typing import Dict, Any

def sha256_b64(b: bytes) -> str:
    import hashlib, base64
    return base64.b64encode(hashlib.sha256(b).digest()).decode()

def emit_enforcement_event(api_url: str, policy_version: str, policy_hash_b64: str,
                           negotiated: Dict[str, Any], allow: bool, reason: str | None = None):
    body = {
        "kind": "pqc.enforcement",
        "ts_ms": int(time.time()*1000),
        "policy_version": policy_version,
        "policy_hash_b64": policy_hash_b64,
        "negotiated": negotiated,
        "decision": {"allow": allow, "reason": reason},
    }
    r = httpx.post(f"{api_url}/events", json=body, timeout=5.0)
    r.raise_for_status()
    return r.json()
