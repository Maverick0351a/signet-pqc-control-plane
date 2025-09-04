import base64, json, time, os
from fastapi.testclient import TestClient
from spcp.api.main import app, _pch_nonce_cache, _load_keys, _compute_policy_hash, load_policy
from spcp.api.models import PolicyDoc
from spcp.api.main import DATA
import shutil


def setup_module():
    if DATA.exists():
        shutil.rmtree(DATA)
    DATA.mkdir(parents=True, exist_ok=True)
    # Ensure any prior test setting an alternate storage dir (SIGNET_STORAGE_DIR)
    # does not leak into these PCH tests, which rely on the default DATA path.
    os.environ.pop("SIGNET_STORAGE_DIR", None)


def _set_policy(client, require_pch: bool = True):
    # Include both a synthetic group (grpA) and a tuple-policy allowed group (X25519)
    # so we can drive an allow-path receipt that also satisfies tuple policy.
    doc = {
        "version": f"v{int(time.time())}",
        "allow_groups": ["grpA", "X25519"],
        "deny_groups": [],
        "mode": "hybrid",
        "require_pch": require_pch,
    }
    r = client.put("/policy", json=doc)
    assert r.status_code == 200


def _build_auth(vk_b64: str, nonce: str, evidence: dict, path: str = "/echo", authority: str = "testserver", channel_binding: str | None = None):
    # Construct covered string matching implementation (include channel binding value if provided)
    binding_val = channel_binding or ""
    covered = [
        f"@method:GET",
        f"@path:{path}",
        f"@authority:{authority}",
        f"challenge:{nonce}",
        f"pch-channel-binding:{binding_val}",
    ]
    sig_input = "\n".join(covered).encode()
    from nacl.signing import SigningKey
    sk, vk = _load_keys()
    # Use server key just for test convenience; real client uses its own key
    from nacl.signing import SigningKey as SK
    signing = SK(sk)
    sig = signing.sign(sig_input).signature
    auth = (
        "PCH "
        f'keyId="{vk_b64}",'  # treat server vk as client key
        'alg="ed25519",'
        f'created="{int(time.time())}",'\
        f'challenge="{nonce}",'\
        f'evidence="{base64.b64encode(json.dumps(evidence).encode()).decode()}",'\
        f'signature="{base64.b64encode(sig).decode()}"'
    )
    return auth


def test_pch_challenge_then_authorize_ok():
    c = TestClient(app)
    _set_policy(c, require_pch=True)
    # First request without auth -> 401 with challenge
    r1 = c.get("/echo")
    assert r1.status_code == 401
    www = r1.headers.get("WWW-Authenticate")
    assert www and "challenge=" in www
    nonce = www.split('challenge="')[1].split('"')[0]
    # Form evidence
    evidence = {"type": "pch.sth", "merkle_root_b64": base64.b64encode(b'0'*32).decode(), "cbom_hash_b64": base64.b64encode(b'1'*32).decode(), "policy_id": "v1"}
    vk_b64 = open(DATA / "keys" / "verify_key_ed25519.b64","r").read().strip()
    auth = _build_auth(vk_b64, nonce, evidence)
    # Provide required group to avoid missing_group denial so that allow receipt captures pch
    # Provide both grpA (simple allow list) and a tuple-policy allowed group (X25519) to satisfy all gates.
    r2 = c.get(
        "/echo",
        headers={
            "Authorization": auth,
            "x-tls-group": "X25519",
            "x-tls-cipher": "TLS_AES_128_GCM_SHA256",
            "x-tls-protocol": "TLS1.3",
            "host": "testserver",
        },
    )
    assert r2.status_code in (200,403)  # allow if other policy passes
    # Latest enforcement receipt should have pch.present true
    # Allow a bit more time for async post-response receipt emission under load from full suite
    time.sleep(0.1)
    import json
    attempts = 40
    found = False
    for _ in range(attempts):
        # Query API with require_pch filter
        lr = c.get("/receipts/latest", params={"type":"pqc.enforcement", "require_pch": "true"})
        if lr.status_code == 200:
            try:
                obj = lr.json()
                if obj.get("pch", {}).get("present") is True:
                    found = True
                    break
            except Exception:
                pass
        # Always fall back to scanning entire receipts directory to avoid relying solely on ordering
        receipts_dir = DATA / "receipts"
        for path in sorted(receipts_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                jd = json.loads(path.read_text())
            except Exception:
                continue
            if jd.get("kind") == "pqc.enforcement" and (jd.get("pch_present") or jd.get("pch",{}).get("present")):
                found = True
                break
        if found:
            break
        time.sleep(0.025)
    assert found, "No enforcement receipt with pch_present found"


def test_pch_invalid_signature_denied():
    c = TestClient(app)
    _set_policy(c, require_pch=True)
    r1 = c.get("/echo")
    nonce = r1.headers.get("WWW-Authenticate").split('challenge="')[1].split('"')[0]
    evidence = {"type": "pch.sth", "merkle_root_b64": base64.b64encode(b'0'*32).decode(), "cbom_hash_b64": base64.b64encode(b'1'*32).decode(), "policy_id": "v1"}
    vk_b64 = open(DATA / "keys" / "verify_key_ed25519.b64","r").read().strip()
    # Tamper signature
    auth = _build_auth(vk_b64, nonce, evidence) + "tamper"
    r2 = c.get("/echo", headers={"Authorization": auth})
    assert r2.status_code == 403


def test_pch_binding_mismatch_denied():
    c = TestClient(app)
    _set_policy(c, require_pch=True)
    r1 = c.get("/echo")
    nonce = r1.headers.get("WWW-Authenticate").split('challenge="')[1].split('"')[0]
    evidence = {"type": "pch.sth", "merkle_root_b64": base64.b64encode(b'0'*32).decode(), "cbom_hash_b64": base64.b64encode(b'1'*32).decode(), "policy_id": "v1"}
    vk_b64 = open(DATA / "keys" / "verify_key_ed25519.b64","r").read().strip()
    auth = _build_auth(vk_b64, nonce, evidence)
    # Provide channel binding header that won't match any server session id
    r2 = c.get("/echo", headers={"Authorization": auth, "PCH-Channel-Binding": "tls-session-id:AAAA"})
    assert r2.status_code == 403


def test_pch_nonce_reuse_denied():
    c = TestClient(app)
    _set_policy(c, require_pch=True)
    r1 = c.get("/echo")
    assert r1.status_code == 401
    nonce = r1.headers.get("WWW-Authenticate").split('challenge="')[1].split('"')[0]
    evidence = {"type": "pch.sth", "merkle_root_b64": base64.b64encode(b'0'*32).decode(), "cbom_hash_b64": base64.b64encode(b'1'*32).decode(), "policy_id": "v1"}
    vk_b64 = open(DATA / "keys" / "verify_key_ed25519.b64","r").read().strip()
    auth = _build_auth(vk_b64, nonce, evidence)
    # First use (may be allow or 403 depending on tuple policy completeness)
    c.get("/echo", headers={"Authorization": auth, "x-tls-group": "X25519", "x-tls-cipher": "TLS_AES_128_GCM_SHA256", "x-tls-protocol": "TLS1.3"})
    # Reuse same nonce should be denied due to one-time use removal from cache
    r3 = c.get("/echo", headers={"Authorization": auth, "x-tls-group": "X25519", "x-tls-cipher": "TLS_AES_128_GCM_SHA256", "x-tls-protocol": "TLS1.3"})
    assert r3.status_code == 403


def test_pch_channel_binding_session_id_success():
    c = TestClient(app)
    _set_policy(c, require_pch=True)
    # First 401 challenge
    r1 = c.get("/echo", headers={"x-tls-session-id": "sess123"})
    assert r1.status_code == 401
    nonce = r1.headers.get("WWW-Authenticate").split('challenge="')[1].split('"')[0]
    evidence = {"type": "pch.sth", "merkle_root_b64": base64.b64encode(b'0'*32).decode(), "cbom_hash_b64": base64.b64encode(b'1'*32).decode(), "policy_id": "v1"}
    vk_b64 = open(DATA / "keys" / "verify_key_ed25519.b64","r").read().strip()
    sess_b64 = base64.b64encode("sess123".encode()).decode()
    auth = _build_auth(vk_b64, nonce, evidence, channel_binding=f"tls-session-id:{sess_b64}")
    # Provide channel binding header referencing session id value encoded in base64
    r2 = c.get(
        "/echo",
        headers={
            "Authorization": auth,
            "PCH-Channel-Binding": f"tls-session-id:{sess_b64}",
            "x-tls-session-id": "sess123",
            "x-tls-group": "X25519",
            "x-tls-cipher": "TLS_AES_128_GCM_SHA256",
            "x-tls-protocol": "TLS1.3",
            "host": "testserver",
        },
    )
    assert r2.status_code in (200,403)
    # Poll for receipt with verified true for THIS nonce to avoid matching older receipts
    time.sleep(0.05)
    found_verified = False
    receipts_dir = DATA / "receipts"
    attempts = 160  # ~3.2s max wait
    for _ in range(attempts):
        for path in sorted(receipts_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                jd = json.loads(path.read_text())
            except Exception:
                continue
            if jd.get("kind") != "pqc.enforcement":
                continue
            pch = jd.get("pch") or {}
            if pch.get("challenge") == nonce and pch.get("verified"):
                found_verified = True
                break
        if found_verified:
            break
    time.sleep(0.02)
    assert found_verified, "Expected verified PCH receipt with session-id binding"


def test_pch_channel_binding_session_id_mismatch():
    c = TestClient(app)
    _set_policy(c, require_pch=True)
    r1 = c.get("/echo", headers={"x-tls-session-id": "sessABC"})
    assert r1.status_code == 401
    nonce = r1.headers.get("WWW-Authenticate").split('challenge="')[1].split('"')[0]
    evidence = {"type": "pch.sth", "merkle_root_b64": base64.b64encode(b'0'*32).decode(), "cbom_hash_b64": base64.b64encode(b'1'*32).decode(), "policy_id": "v1"}
    vk_b64 = open(DATA / "keys" / "verify_key_ed25519.b64","r").read().strip()
    # Correct binding would be base64("sessABC"), we sign with correct then send wrong header to force mismatch
    correct_b64 = base64.b64encode("sessABC".encode()).decode()
    auth = _build_auth(vk_b64, nonce, evidence, channel_binding=f"tls-session-id:{correct_b64}")
    # Supply a mismatching session id in binding
    wrong_b64 = base64.b64encode("other".encode()).decode()
    r2 = c.get(
        "/echo",
        headers={
            "Authorization": auth,
            "PCH-Channel-Binding": f"tls-session-id:{wrong_b64}",
            "x-tls-session-id": "sessABC",
            "x-tls-group": "X25519",
            "x-tls-cipher": "TLS_AES_128_GCM_SHA256",
            "x-tls-protocol": "TLS1.3",
            "host": "testserver",
        },
    )
    assert r2.status_code == 403, r2.text
