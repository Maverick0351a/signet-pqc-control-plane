
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


def test_circuit_breaker_trips_quickly(monkeypatch):
    """Simulate a small window where a failure threshold triggers a policy downgrade.

    We override circuit breaker settings to require only 4 events with >=50% failures.
    Then send two allows and two denies -> expect downgrade receipt and tree growth.
    """
    from spcp.settings import settings as live_settings
    # Monkeypatch settings
    monkeypatch.setattr(live_settings, 'cb_window_size', 4)
    monkeypatch.setattr(live_settings, 'cb_min_events', 4)
    monkeypatch.setattr(live_settings, 'cb_error_rate_threshold', 0.5)
    # Reinitialize circuit breaker in the app module to respect new settings window size
    import spcp.api.main as main_mod
    from spcp.policy.circuit_breaker import CircuitBreaker
    main_mod._cb = CircuitBreaker()

    c = TestClient(app)
    # Fresh start
    if DATA.exists():
        import shutil
        shutil.rmtree(DATA)
    DATA.mkdir(parents=True, exist_ok=True)

    # Seed policy v1
    base_policy = {"version":"v1","allow_groups":["grp"],"deny_groups":[],"mode":"pqc","description":"pilot"}
    r = c.put('/policy', json=base_policy)
    assert r.status_code == 200
    policy_hash_b64 = base64.b64encode(hashlib.sha256(json.dumps(base_policy, sort_keys=True, separators=(',', ':')).encode()).digest()).decode()

    def ev(allow: bool):
        return {
            "kind": "pqc.enforcement",
            "ts_ms": int(time.time()*1000),
            "policy_version": "v1" if allow else "v1",  # original version referenced
            "policy_hash_b64": policy_hash_b64,
            "negotiated": {
                "tls_version": "TLS1.3",
                "cipher": "TLS_AES_128_GCM_SHA256",
                "group_or_kem": "grp" if allow else "bad",
                "sig_alg": "ed25519",
                "sni": "svc.local"
            },
            "decision": {"allow": allow, "reason": None if allow else "denied"}
        }

    # Two successes
    for _ in range(2):
        assert c.post('/events', json=ev(True)).status_code == 200
    # Two failures
    for _ in range(2):
        assert c.post('/events', json=ev(False)).status_code == 200

    # Expect a circuit-breaker policy downgrade receipt to exist (version suffix '-cb')
    receipts = sorted(RECEIPTS.glob('*.json'))
    names = [p.name for p in receipts]
    downgrade = [n for n in names if 'policy_change_v1-cb' in n]
    assert downgrade, f"Expected downgrade receipt; found: {names}"

    # STH reflects all events + policy change (>=5 leaves)
    assert STH_FILE.exists()
    sth_obj = json.loads(STH_FILE.read_text())
    assert sth_obj['tree_size'] >= 5

    # Verify hash linking - after the first receipt that sets chain baseline
    import json as _json
    for p in receipts:
        obj = _json.loads(p.read_text())
        # Allow the very first policy.change (from_version v0) to lack prev link
        if obj.get('prev_receipt_hash_b64') is None:
            if obj.get('kind') == 'policy.change' and obj.get('from_version') == 'v0':
                continue
        assert obj.get('prev_receipt_hash_b64') is not None, f"Missing prev hash in {p.name}"
