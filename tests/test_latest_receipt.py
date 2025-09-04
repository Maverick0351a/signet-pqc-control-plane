import json
import os
import shutil
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient

from spcp.api.main import DATA, app


def setup_module():
    if DATA.exists():
        shutil.rmtree(DATA)
    DATA.mkdir(parents=True, exist_ok=True)


def test_latest_receipt_empty():
    tmp = Path(tempfile.mkdtemp(prefix="spcp_latest_empty_"))
    os.environ["SIGNET_STORAGE_DIR"] = str(tmp)
    receipts_dir = tmp / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)
    c = TestClient(app)
    r = c.get("/receipts/latest")
    assert r.status_code == 404


def _emit_policy_change(client, version: str):
    doc = {
        "version": version,
        "allow_groups": [],
        "deny_groups": [],
        "mode": "hybrid",
        "description": "test",
    }
    assert client.put("/policy", json=doc).status_code == 200


def test_latest_receipt_picks_newest_and_ignores_malformed():
    tmp = Path(tempfile.mkdtemp(prefix="spcp_latest_newest_"))
    os.environ["SIGNET_STORAGE_DIR"] = str(tmp)
    c = TestClient(app)
    receipts_dir = tmp / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)
    # Helper to fabricate a minimal valid receipt file
    def write_receipt(name: str, kind: str, extra: dict):
        obj = {"kind": kind, **extra}
        p = receipts_dir / f"{name}.json"
        p.write_text(json.dumps(obj))
        # small sleep to vary mtime ordering
        time.sleep(0.01)
        return p

    # Two valid older receipts
    write_receipt("r1", "pqc.enforcement", {"a": 1})
    write_receipt("r2", "pqc.enforcement", {"a": 2})

    # Malformed newer file
    bad = receipts_dir / "zzz_bad.json"
    bad.write_text("{not-json")
    Path(bad).touch()
    time.sleep(0.01)

    # Newest valid receipt
    write_receipt("r3", "pqc.enforcement", {"a": 3})

    r = c.get("/receipts/latest")
    assert r.status_code == 200, r.text
    obj = r.json()
    assert obj.get("kind") == "pqc.enforcement"
