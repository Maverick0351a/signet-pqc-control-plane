import base64
import json
import os
import subprocess
import time
from pathlib import Path

import pytest
from nacl import signing

COMPOSE_FILE = Path(__file__).resolve().parent.parent.parent / "docker-compose.yml"
PROJECT_ROOT = COMPOSE_FILE.parent
APPDATA_VOL = PROJECT_ROOT / "appdata_mount"  # bind mount to inspect receipts

@pytest.fixture(scope="module")
def compose_env():
    # Prepare a bind mount directory so we can read receipts without docker exec.
    if APPDATA_VOL.exists():
        for p in APPDATA_VOL.rglob('*'):
            if p.is_file():
                try: p.unlink()
                except Exception: pass
    APPDATA_VOL.mkdir(exist_ok=True)
    # Create an override compose file using bind mount instead of named volume.
    override = PROJECT_ROOT / "docker-compose.pch-test.yml"
    override.write_text(
        f"""
version: '3.9'
services:
  app:
    build: .
    environment:
      - SPCP_DATA_DIR=/data
      - PCH_REQUIRED_ROUTES=/protected*
    volumes:
      - {APPDATA_VOL.as_posix()}:/data
    command: ["python","-m","uvicorn","spcp.api.main:app","--host","0.0.0.0","--port","8000"]
  pqc_proxy:
    build: ./terminators/nginx-oqs
    depends_on:
      - app
    ports:
      - "8443:443"
    environment:
      - ALLOWED_GROUPS=X25519Kyber768:X25519:P-256
        """.strip()
    )
    cmd = ["docker","compose","-f", str(COMPOSE_FILE), "-f", str(override), "up","-d","--build"]
    subprocess.check_call(cmd, cwd=PROJECT_ROOT)
    # Wait for app health
    import http.client
    for _ in range(60):
        try:
            conn = http.client.HTTPConnection("localhost", 8080, timeout=1)
            conn.request("GET","/health")
            if conn.getresponse().status == 200:
                break
        except Exception:
            time.sleep(0.5)
    yield
    subprocess.call(["docker","compose","-f", str(COMPOSE_FILE), "-f", str(override), "down","-v"], cwd=PROJECT_ROOT)


def _latest_receipt_raw():
    receipts_dir = APPDATA_VOL / "receipts"
    candidates = list(receipts_dir.glob("*.json"))
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    for p in candidates:
        try:
            return json.loads(p.read_text())
        except Exception:
            continue
    return None


def _seed_policy():
    import http.client
    conn = http.client.HTTPConnection("localhost",8080,timeout=3)
    doc = {
        "version":"vComposePCH",
        "allow_groups":[],
        "deny_groups":[],
        "mode":"hybrid",
        "description":"compose pch test",
        "require_pch": True,
    }
    body = json.dumps(doc).encode()
    conn.request("PUT","/policy", body, {"Content-Type":"application/json"})
    resp = conn.getresponse(); assert resp.status == 200, resp.read()


def _build_evidence(policy_id: str):
    ev = {
        "type":"pch.sth",
        "time": int(time.time()),
        "policy_id": policy_id,
        "merkle_root_b64": base64.b64encode(b"0"*32).decode(),
        "tree_size": 1,
        "attestation": {
            "mode":"software",
            "cbom_hash_b64": base64.b64encode(b"1"*32).decode(),
        },
    }
    raw = json.dumps(ev, separators=(",",":"), sort_keys=True).encode()
    return ":"+base64.b64encode(raw).decode()+":"


def _sign_request(path: str, chal: str, evidence: str, session_id: str, vk: signing.VerifyKey, sk: signing.SigningKey):
    authority = "localhost"
    fields = ["@method","@path","@authority","pch-challenge","pch-channel-binding","pch-evidence"]
    challenge_clean = chal.strip(":")
    binding = f"tls-session-id=:{base64.b64encode(session_id.encode()).decode()}:"
    sig_input_lines = [
        "@method:GET",
        f"@path:{path}",
        f"@authority:{authority}",
        f"pch-challenge:{chal}",
        f"pch-channel-binding:{binding}",
        f"pch-evidence:{evidence}",
    ]
    base_input = "\n".join(sig_input_lines).encode()
    signature = sk.sign(base_input).signature
    auth = (
        "PCH "
        f"keyId=\"{base64.b64encode(vk.encode()).decode()}\"," \
        f"alg=\"ed25519\",created=\"{int(time.time())}\",challenge=\"{challenge_clean}\"," \
        f"evidence=\"{base64.b64encode(json.dumps({'dummy':True}).encode()).decode()}\",signature=\"{base64.b64encode(signature).decode()}\""
    )
    sig_input = f"sig1=(\""+"\" \"".join(fields)+"\");created="+str(int(time.time()))
    headers = {
        "Host": authority,
        "Authorization": auth,
        "Signature-Input": sig_input,
        "PCH-Challenge": chal,
        "PCH-Channel-Binding": binding,
        "PCH-Evidence": evidence,
        "X-TLS-Session-ID": session_id,
        "X-TLS-Group": "X25519",  # satisfy soft policy
    }
    return headers


@pytest.mark.compose
def test_pch_roundtrip_allow(compose_env):
    _seed_policy()
    import http.client
    conn = http.client.HTTPSConnection("localhost",8443,timeout=5, context=None)  # system CA not needed (self-signed) but we pass context=None for simplicity
    conn.request("GET","/protected")
    r1 = conn.getresponse(); body1 = r1.read()
    assert r1.status == 401, body1
    chal = r1.getheader("PCH-Challenge"); assert chal
    session_id = r1.getheader("X-TLS-Session-ID") or "sessA"
    sk = signing.SigningKey.generate(); vk = sk.verify_key
    evidence = _build_evidence("vComposePCH")
    headers = _sign_request("/protected", chal, evidence, session_id, vk, sk)
    # second request
    conn2 = http.client.HTTPSConnection("localhost",8443,timeout=5, context=None)
    conn2.request("GET","/protected", headers=headers)
    r2 = conn2.getresponse(); body2 = r2.read()
    assert r2.status == 200, body2
    # allow some time for receipt flush
    for _ in range(20):
        rec = _latest_receipt_raw()
        if rec and rec.get("kind") == "pqc.enforcement" and rec.get("decision",{}).get("allow"):
            pch = rec.get("pch") or {}
            if pch.get("verified"):
                break
        time.sleep(0.25)
    assert rec, "no receipt found"
    assert rec.get("decision",{}).get("allow") is True
    assert (rec.get("pch") or {}).get("verified") is True


@pytest.mark.compose
def test_pch_deny_bad_binding(compose_env):
    _seed_policy()
    import http.client
    conn = http.client.HTTPSConnection("localhost",8443,timeout=5, context=None)
    conn.request("GET","/protected")
    r1 = conn.getresponse(); r1.read()
    chal = r1.getheader("PCH-Challenge"); assert chal
    session_id = r1.getheader("X-TLS-Session-ID") or "sessB"
    sk = signing.SigningKey.generate(); vk = sk.verify_key
    evidence = _build_evidence("vComposePCH")
    headers = _sign_request("/protected", chal, evidence, session_id, vk, sk)
    # Corrupt binding
    headers["PCH-Channel-Binding"] = "tls-session-id::bad:"  # wrong format
    conn2 = http.client.HTTPSConnection("localhost",8443,timeout=5, context=None)
    conn2.request("GET","/protected", headers=headers)
    r2 = conn2.getresponse(); r2.read()
    assert r2.status == 403
    # Look for deny receipt
    for _ in range(20):
        rec = _latest_receipt_raw()
        if rec and rec.get("kind") == "pqc.enforcement" and not rec.get("decision",{}).get("allow"):
            break
        time.sleep(0.25)
    assert rec, "no deny receipt"
    assert rec.get("decision",{}).get("allow") is False
