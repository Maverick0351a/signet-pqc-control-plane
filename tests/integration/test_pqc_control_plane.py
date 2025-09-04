"""Integration smoke test for control plane (optional, RUN_INT=1).

This test uses docker-compose to stand up the stack twice. It intentionally:
  - Calls docker via subprocess with static arguments (no untrusted input)
  - Performs an HTTPS request with verify=False against a local self-signed cert

Security linters (S603/S607/S501) are suppressed for this test file only.
"""

# ruff: noqa: S603,S607,S501

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(not os.environ.get("RUN_INT"), reason="Set RUN_INT=1 to run integration tests")
def test_allow_then_deny_flow():
    """Bring up default (allow) then restricted (deny) scenario and observe new receipt."""
    docker_exe = shutil.which("docker") or "docker"

    # Phase A: default stack
    subprocess.check_call([docker_exe, "compose", "up", "-d"], cwd=REPO_ROOT)
    try:
        time.sleep(3)
        import requests

        payload = {
            "kind": "pqc.enforcement",
            "ts_ms": int(time.time() * 1000),
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
            "decision": {"allow": True},
        }
        r = requests.post("http://localhost:8080/events", json=payload, timeout=5)
        assert r.status_code == 200
        first_hash = r.json()["payload_hash_b64"]
        rl = requests.get("http://localhost:8080/receipts/latest", timeout=5)
        assert rl.status_code == 200
        assert rl.json().get("payload_hash_b64") == first_hash

        # Phase B: restricted proxy override
        subprocess.check_call([docker_exe, "compose", "down"], cwd=REPO_ROOT)
        subprocess.check_call([
            docker_exe,
            "compose",
            "-f",
            "docker-compose.yml",
            "-f",
            "docker/compose.restricted.yml",
            "up",
            "-d",
        ], cwd=REPO_ROOT)
        time.sleep(4)
        try:
            requests.get("https://localhost/echo", verify=False, timeout=5)
        except Exception as e:  # noqa: S112
            print(f"Request to /echo failed: {e}")

        # Poll for a different latest receipt hash
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
        subprocess.call([docker_exe, "compose", "down"], cwd=REPO_ROOT)
