import os
import time
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

@pytest.mark.skipif(not os.environ.get("RUN_INT"), reason="Set RUN_INT=1 to run integration tests")
def test_allow_then_deny_flow():
    """Phase A: bring up default stack and emit allow receipt.

    Phase B: restart with restricted compose override and ensure a new receipt appears.
    This is a smoke-style test; it does not assert full cryptographic details.
    """
    # Phase A
    subprocess.check_call(["docker","compose","up","-d"], cwd=REPO_ROOT)
    try:
        time.sleep(3)
        import requests
        payload = {
            "kind": "pqc.enforcement",
            "ts_ms": int(time.time()*1000),
            "policy_version": "v0",
            "policy_hash_b64": "",
            "negotiated": {
                "tls_version": "TLS1.3",
                "cipher": "TLS_AES_128_GCM_SHA256",
                "group_or_kem": "X25519Kyber768",
                "sig_alg": "ed25519",
                "sni": None,
                "peer_ip": None,
                "alpn": "h2",
                "client_cert_sha256": None,
                "client_cert_sig_alg": None,
            },
            "decision": {"allow": True}
        }
        r = requests.post("http://localhost:8080/events", json=payload, timeout=5)
        assert r.status_code == 200
        first_hash = r.json()["payload_hash_b64"]
        # Confirm latest endpoint returns this hash
        rl = requests.get("http://localhost:8080/receipts/latest", timeout=5)
        assert rl.status_code == 200
        assert rl.json().get("payload_hash_b64") == first_hash

        # Phase B: restricted proxy
        subprocess.check_call(["docker","compose","down"], cwd=REPO_ROOT)
        subprocess.check_call(["docker","compose","-f","docker-compose.yml","-f","docker/compose.restricted.yml","up","-d"], cwd=REPO_ROOT)
        time.sleep(4)
        # Trigger traffic (ignore cert verify for local self-signed)
        try:
            requests.get("https://localhost/echo", verify=False, timeout=5)
        except Exception:
            pass

        # Poll for new receipt
        deadline = time.time() + 15
        new_obj = None
        while time.time() < deadline:
            rl2 = requests.get("http://localhost:8080/receipts/latest", timeout=5)
            if rl2.status_code == 200 and rl2.json().get("payload_hash_b64") != first_hash:
                new_obj = rl2.json()
                break
            time.sleep(1)
        assert new_obj, "Expected a new receipt after restricted phase"
        assert new_obj.get("type") in ("pqc.enforcement", "policy.change")
    finally:
        subprocess.call(["docker","compose","down"], cwd=REPO_ROOT)
