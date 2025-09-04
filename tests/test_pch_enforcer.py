import base64
import json
import shutil
import time
from fastapi.testclient import TestClient

from spcp.api.main import app, DATA, RECEIPTS
from spcp.settings import settings

from nacl import signing


def _reset_data():
    if DATA.exists():
        shutil.rmtree(DATA)
    DATA.mkdir(parents=True, exist_ok=True)


def _seed_policy(client, version="vPCH"):
    doc = {
        "version": version,
        "allow_groups": [],
        "deny_groups": [],
        "mode": "hybrid",
        "description": "pch test",
    }
    r = client.put("/policy", json=doc)
    assert r.status_code == 200
    return doc


def _gen_keypair():
    sk = signing.SigningKey.generate()
    vk = sk.verify_key
    return sk, vk


def _build_evidence(policy_id: str):
    ev = {
        "type": "pch.sth",
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "policy_id": policy_id,
        "merkle_root_b64": base64.b64encode(b"m" * 32).decode(),
        "tree_size": 1,
        "attestation": {"mode": "software", "cbom_hash_b64": base64.b64encode(b"c" * 32).decode()},
    }
    return base64.b64encode(json.dumps(ev, separators=(",", ":"), sort_keys=True).encode()).decode()


def _sign(sig_input: bytes, sk: signing.SigningKey) -> str:
    return base64.b64encode(sk.sign(sig_input).signature).decode()


def test_pch_challenge_issued_on_missing_signature(monkeypatch):
    monkeypatch.setattr(settings, "pch_required_routes", ["/echo*"])
    c = TestClient(app)
    _reset_data()
    _seed_policy(c)
    r = c.get("/echo")
    assert r.status_code == 401, r.text
    assert "WWW-Authenticate" in r.headers
    assert r.headers.get("PCH-Challenge")


def test_pch_403_on_nonce_mismatch(monkeypatch):
    monkeypatch.setattr(settings, "pch_required_routes", ["/echo*"])
    c = TestClient(app)
    _reset_data()
    pol = _seed_policy(c)
    # First get challenge
    r1 = c.get("/echo")
    assert r1.status_code == 401
    chal = r1.headers["PCH-Challenge"]  # format :<b64>:
    # Build fake request with wrong challenge (modify one char)
    bad_chal = ":AAAA" + chal[5:] if len(chal) > 5 else chal
    sk, vk = _gen_keypair()
    evidence_b64 = _build_evidence(pol["version"])
    session_id = "abcd"  # binding
    headers = {
        "PCH-Challenge": bad_chal,
        "PCH-Channel-Binding": f"tls-session-id=:{base64.b64encode(session_id.encode()).decode()}:",
        "PCH-Evidence": f":{evidence_b64}:",
    }
    covered = ["@method", "@path", "@authority", "pch-challenge", "pch-channel-binding", "pch-evidence"]
    sig_input_lines = [
        f"@method:GET",
        f"@path:/echo",
        f"@authority:",
        f"pch-challenge:{bad_chal}",
        f"pch-channel-binding:{headers['PCH-Channel-Binding']}",
        f"pch-evidence:{headers['PCH-Evidence']}",
    ]
    sig_input = "\n".join(sig_input_lines).encode()
    sig = _sign(sig_input, sk)
    key_b64 = base64.b64encode(vk.encode()).decode()
    headers["Authorization"] = f"PCH keyId={key_b64},alg=ed25519,created={int(time.time())},challenge={bad_chal.strip(':')},evidence={evidence_b64},signature={sig}"
    headers["Signature-Input"] = 'sig1=("' + '" "'.join(covered) + '");created=' + str(int(time.time()))
    r2 = c.get("/echo", headers=headers)
    assert r2.status_code == 403


def test_pch_403_on_channel_binding_mismatch(monkeypatch):
    monkeypatch.setattr(settings, "pch_required_routes", ["/echo*"])
    c = TestClient(app)
    _reset_data()
    pol = _seed_policy(c)
    # Challenge
    r1 = c.get("/echo", headers={"X-TLS-Session-ID": "abcd"})
    chal = r1.headers["PCH-Challenge"]
    good_chal_inner = chal.strip(":")
    sk, vk = _gen_keypair()
    evidence_b64 = _build_evidence(pol["version"])
    session_id = "abcd"
    # Intentionally wrong binding b64 (change session id)
    headers = {
        "PCH-Challenge": chal,
        "PCH-Channel-Binding": f"tls-session-id=:{base64.b64encode(b'XXXX').decode()}:",
        "PCH-Evidence": f":{evidence_b64}:",
    }
    covered = ["@method", "@path", "@authority", "pch-challenge", "pch-channel-binding", "pch-evidence"]
    sig_input_lines = [
        f"@method:GET",
        f"@path:/echo",
        f"@authority:",
        f"pch-challenge:{chal}",
        f"pch-channel-binding:{headers['PCH-Channel-Binding']}",
        f"pch-evidence:{headers['PCH-Evidence']}",
    ]
    sig_input = "\n".join(sig_input_lines).encode()
    sig = _sign(sig_input, sk)
    key_b64 = base64.b64encode(vk.encode()).decode()
    headers["Authorization"] = f"PCH keyId={key_b64},alg=ed25519,created={int(time.time())},challenge={good_chal_inner},evidence={evidence_b64},signature={sig}"
    headers["Signature-Input"] = 'sig1=("' + '" "'.join(covered) + '");created=' + str(int(time.time()))
    headers["X-TLS-Session-ID"] = session_id  # expected real session id
    r2 = c.get("/echo", headers=headers)
    assert r2.status_code == 403


def test_pch_200_valid_flow(monkeypatch):
    monkeypatch.setattr(settings, "pch_required_routes", ["/echo*"])
    c = TestClient(app)
    _reset_data()
    pol = _seed_policy(c)
    # Challenge
    r1 = c.get("/echo", headers={"X-TLS-Session-ID": "abcd"})
    chal = r1.headers["PCH-Challenge"]
    chal_inner = chal.strip(":")
    sk, vk = _gen_keypair()
    evidence_b64 = _build_evidence(pol["version"])
    session_id = "abcd"
    binding = f"tls-session-id=:{base64.b64encode(session_id.encode()).decode()}:"
    headers = {
        "PCH-Challenge": chal,
        "PCH-Channel-Binding": binding,
        "PCH-Evidence": f":{evidence_b64}:",
        "X-TLS-Session-ID": session_id,
        "Host": "testserver",
        "X-TLS-Group": "grp",  # satisfy soft policy layer (missing_group otherwise)
    }
    covered = ["@method", "@path", "@authority", "pch-challenge", "pch-channel-binding", "pch-evidence"]
    sig_input_lines = [
        f"@method:GET",
        f"@path:/echo",
        f"@authority:testserver",
        f"pch-challenge:{chal}",
        f"pch-channel-binding:{binding}",
        f"pch-evidence:{headers['PCH-Evidence']}",
    ]
    sig_input = "\n".join(sig_input_lines).encode()
    sig = _sign(sig_input, sk)
    key_b64 = base64.b64encode(vk.encode()).decode()
    headers["Authorization"] = f"PCH keyId={key_b64},alg=ed25519,created={int(time.time())},challenge={chal_inner},evidence={evidence_b64},signature={sig}"
    headers["Signature-Input"] = 'sig1=("' + '" "'.join(covered) + '");created=' + str(int(time.time()))
    r2 = c.get("/echo", headers=headers)
    assert r2.status_code == 200, r2.text
    # Receipt emitted with verified true
    receipts = list(RECEIPTS.glob("*.json"))
    assert receipts, "expected at least one receipt"
    found_verified = False
    for p in receipts:
        obj = json.loads(p.read_text())
        if obj.get("kind") == "pqc.enforcement" and obj.get("pch", {}).get("verified"):
            found_verified = True
            break
    assert found_verified, "No verified PCH receipt found"
