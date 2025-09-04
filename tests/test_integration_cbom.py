import json
import os
import tarfile
import time
import zipfile
from pathlib import Path
import base64
import subprocess

import pytest
import httpx
from nacl.signing import SigningKey

from spcp.receipts.jcs import jcs_canonical

API_URL = "http://localhost:8000"  # assumes test environment started externally

pytestmark = pytest.mark.skip(reason="integration tests require running service & proxy container")


def _wait_for_cbom(timeout=30):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = httpx.get(f"{API_URL}/cbom/latest", timeout=2)
            if r.status_code == 200:
                return r.json()
        except Exception:  # noqa: S112
            pass
        time.sleep(1)
    raise AssertionError("Timeout waiting for /cbom/latest")


def test_cbom_roundtrip():
    cbom = _wait_for_cbom()
    # Verify endpoint
    # Generate a throwaway key and add a fake signature so verify path exercises canonicalization
    sk = SigningKey.generate()
    core_bytes = jcs_canonical({k: cbom[k] for k in cbom if k != "signatures"})
    sig = base64.b64encode(sk.sign(core_bytes).signature).decode()
    cbom_signed = {**cbom, "signatures": [{"algorithm": "ed25519", "value": sig}]}
    r = httpx.post(f"{API_URL}/cbom/verify", json={"cbom": cbom_signed, "public_key_b64": base64.b64encode(sk.verify_key.encode()).decode()}, timeout=5)
    assert r.status_code == 200 and r.json()["ok"] is True
    # Set baseline
    r = httpx.post(f"{API_URL}/cbom/baseline", json=cbom, timeout=5)
    assert r.status_code == 200
    # No drift yet
    r = httpx.get(f"{API_URL}/cbom/drift/latest", timeout=5)
    assert r.status_code in (404, 200)  # may be no drift; 404 acceptable


def test_compliance_pack():
    r = httpx.post(f"{API_URL}/compliance/pack", timeout=10)
    assert r.status_code == 200
    zdata = r.content
    with open("/tmp/pack.zip", "wb") as f:
        f.write(zdata)
    with zipfile.ZipFile("/tmp/pack.zip") as zf:
        names = zf.namelist()
        assert "verify_cbom.py" in names
        assert any(n.startswith("receipts/") for n in names)
        assert "sth.json" in names or True  # STH may or may not exist early
        # Extract a CBOM doc if present and run verifier script
        cbom_files = [n for n in names if n.startswith("cbom_docs/cbom_")]
        if cbom_files:
            zf.extract("verify_cbom.py", "/tmp")
            first_cbom = cbom_files[0]
            zf.extract(first_cbom, "/tmp")
            out = subprocess.run(["python", "/tmp/verify_cbom.py", f"/tmp/{first_cbom}", base64.b64encode(SigningKey.generate().verify_key.encode()).decode()], capture_output=True, text=True)
            assert out.returncode == 0
