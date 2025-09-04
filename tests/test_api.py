
from fastapi.testclient import TestClient
from spcp.api.main import app, DATA, RECEIPTS, STH_FILE
from spcp.api.models import PolicyDoc
import json, base64, hashlib, time, os, shutil

def setup_module():
    # Clean data dir
    if DATA.exists():
        shutil.rmtree(DATA)
    DATA.mkdir(parents=True, exist_ok=True)

def test_policy_and_enforcement_flow():
    c = TestClient(app)

    # Get default policy
    r = c.get("/policy")
    assert r.status_code == 200
    cur = r.json()

    # Update policy to v1 (hybrid)
    new = {"version":"v1","allow_groups":["p256_kyber768"],"deny_groups":[],"mode":"hybrid","description":"pilot"}
    r2 = c.put("/policy", json=new)
    assert r2.status_code == 200

    # Emit a pqc.enforcement (allowed case)
    policy_hash_b64 = base64.b64encode(hashlib.sha256(json.dumps(new, sort_keys=True, separators=(',', ':')).encode()).digest()).decode()
    e1 = {
        "kind": "pqc.enforcement",
        "ts_ms": int(time.time()*1000),
        "policy_version": "v1",
        "policy_hash_b64": policy_hash_b64,
        "negotiated": {
            "tls_version": "TLS1.3",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "group_or_kem": "p256_kyber768",
            "sig_alg": "ed25519",
            "sni": "svc.local"
        },
        "decision": {"allow": True}
    }
    r3 = c.post("/events", json=e1)
    assert r3.status_code == 200

    # Emit a denied case -> feed circuit breaker window
    e2 = dict(e1)
    e2["negotiated"] = {**e1["negotiated"], "group_or_kem": "p256"}
    e2["decision"] = {"allow": False, "reason":"not in allowlist"}
    for _ in range(25):
        c.post("/events", json=e2)

    # STH exists
    assert STH_FILE.exists()
    sth = json.loads(STH_FILE.read_text())
    assert sth["tree_size"] >= 2
