import base64
import json
from typing import Any, Dict

from nacl import signing
from nacl.encoding import RawEncoder

from .builder import canonicalize_cbom


def sign_cbom_document(doc: Dict[str, Any], signer: signing.SigningKey) -> Dict[str, Any]:
    canonical = canonicalize_cbom(doc)
    sig = signer.sign(canonical.encode("utf-8"), encoder=RawEncoder).signature
    b64sig = base64.b64encode(sig).decode("ascii")
    signed = dict(doc)
    signed.setdefault("signatures", [])
    signed["signatures"].append({
        "algorithm": "ed25519",
        "value": b64sig,
        "keyId": "signet-agent-ed25519",
    })
    return signed


def verify_cbom_signature(doc: Dict[str, Any], verify_key: signing.VerifyKey) -> bool:
    sigs = doc.get("signatures") or []
    for s in sigs:
        if s.get("algorithm") != "ed25519":
            continue
        val = s.get("value")
        if not val:
            continue
        try:
            canonical = canonicalize_cbom({k: doc[k] for k in doc if k != "signatures"})
            verify_key.verify(canonical.encode("utf-8"), base64.b64decode(val))
            return True
        except Exception:  # pragma: no cover - verification failure path
            continue
    return False
