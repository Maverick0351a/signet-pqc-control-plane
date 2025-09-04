
import time

from spcp.receipts.sign import gen_ed25519_keypair, sign_receipt_ed25519, verify_receipt_ed25519


def test_sign_verify_roundtrip():
    sk, vk = gen_ed25519_keypair()
    rec = {
        "kind": "pqc.enforcement",
        "ts_ms": int(time.time() * 1000),
        "policy_version": "v1",
        "policy_hash_b64": "h",
        "negotiated": {
            "tls_version": "TLS1.3",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "group_or_kem": "p256_kyber768",
            "sig_alg": "ed25519",
        },
        "decision": {"allow": True},
    }
    signed = sign_receipt_ed25519(rec, sk)
    assert verify_receipt_ed25519(signed, vk)
    # Tamper
    signed["decision"]["allow"] = False
    assert not verify_receipt_ed25519(signed, vk)
