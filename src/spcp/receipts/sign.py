
from __future__ import annotations

import base64
import hashlib
from typing import Any

from nacl.encoding import RawEncoder
from nacl.signing import SigningKey, VerifyKey

from .jcs import jcs_canonical


def sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()

def gen_ed25519_keypair() -> tuple[bytes, bytes]:
    sk = SigningKey.generate()
    vk = sk.verify_key
    return (bytes(sk), bytes(vk))

def sign_receipt_ed25519(receipt: dict[str, Any], sk_bytes: bytes) -> dict[str, Any]:
    """Return a new dict with 'payload_hash_b64' and 'receipt_sig_b64'."""
    payload = jcs_canonical(receipt)
    payload_hash_b64 = sha256_b64(payload)
    sk = SigningKey(sk_bytes)
    sig = sk.sign(payload, encoder=RawEncoder).signature  # 64 bytes
    return {
        **receipt,
        "payload_hash_b64": payload_hash_b64,
        "receipt_sig_b64": base64.b64encode(sig).decode(),
        "sig_alg": "ed25519",
    }

def verify_receipt_ed25519(signed: dict[str, Any], vk_bytes: bytes) -> bool:
    expected_hash = signed.get("payload_hash_b64")
    sig_b64 = signed.get("receipt_sig_b64")
    if not expected_hash or not sig_b64:
        return False
    # Recompute hash on the object *without* the signature fields.
    core = {
        k: v
        for k, v in signed.items()
        if k not in ("payload_hash_b64", "receipt_sig_b64", "sig_alg")
    }
    payload = jcs_canonical(core)
    if sha256_b64(payload) != expected_hash:
        return False
    sig = base64.b64decode(sig_b64)
    vk = VerifyKey(vk_bytes)
    try:
        vk.verify(payload, sig, encoder=RawEncoder)
        return True
    except Exception:
        return False
