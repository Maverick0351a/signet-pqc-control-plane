import shutil
import time

from fastapi.testclient import TestClient

from spcp.api.main import DATA, app


def setup_module():
    if DATA.exists():
        shutil.rmtree(DATA)
    DATA.mkdir(parents=True, exist_ok=True)


def test_events_endpoint_populates_negotiated_from_headers_when_absent():
    c = TestClient(app)

    # Seed a policy that allows the test group
    policy_doc = {
        "version": "vh1",
        "allow_groups": ["p256_kyber768"],
        "deny_groups": [],
        "mode": "hybrid",
        "description": "test",
    }
    assert c.put("/policy", json=policy_doc).status_code == 200

    # Post an enforcement event WITHOUT negotiated block; expect server to inject from headers
    headers = {
        "X-TLS-Protocol": "TLS1.3",
        "X-TLS-Cipher": "TLS_AES_128_GCM_SHA256",
        "X-TLS-Group": "p256_kyber768",
        "X-ALPN": "h2",
        "X-TLS-SNI": "svc.test",
    }
    payload = {
        "kind": "pqc.enforcement",
        "ts_ms": int(time.time() * 1000),
        "policy_version": policy_doc["version"],
        # policy_hash_b64 can be blank; server recomputes and signs with canonical form
        "policy_hash_b64": "",
        "decision": {"allow": True},
    }
    r = c.post("/events", json=payload, headers=headers)
    assert r.status_code == 200, r.text
    obj = r.json()
    negotiated = obj.get("negotiated")
    assert negotiated, "Server should attach negotiated block"
    assert negotiated["tls_version"] == "TLS1.3"
    assert negotiated["cipher"] == "TLS_AES_128_GCM_SHA256"
    assert negotiated["group_or_kem"] == "p256_kyber768"
    assert negotiated["alpn"] == "h2"
    assert negotiated["sni"] == "svc.test"
