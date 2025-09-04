import base64
import hashlib
import json
import shutil

from fastapi.testclient import TestClient

from spcp.api.main import DATA, RECEIPTS, STH_FILE, app
from spcp.proxy import cbom as cbom_mod
from spcp.receipts.sign import verify_receipt_ed25519


def setup_module():
    # Fresh data dir to avoid cross-test chain effects
    if DATA.exists():
        shutil.rmtree(DATA)
    DATA.mkdir(parents=True, exist_ok=True)


def test_collect_cbom_stubbed(monkeypatch):
    c = TestClient(app)

    # Stub probe functions for deterministic test
    monkeypatch.setattr(cbom_mod, "_probe_openssl_version", lambda: "3.2.1-test")
    monkeypatch.setattr(cbom_mod, "_list_available_groups", lambda: ["grpA", "grpB"])

    # Use TestClient's .post through injection to avoid real network DNS lookup
    def _client_post(url, json, timeout):
        # url already includes base; strip base_url for TestClient relative path
        assert url.endswith("/events")
        resp = c.post("/events", json=json)
        class R:
            def __init__(self, r):
                self._r = r
            def raise_for_status(self):
                self._r.raise_for_status()
            def json(self):
                return self._r.json()
        return R(resp)

    receipt = cbom_mod.collect_cbom(
        str(c.base_url).rstrip("/"),
        node_id="node-test-1",
        _post_func=_client_post,
    )
    assert receipt["kind"] == "pqc.cbom"
    # Signature fields present
    for f in ("payload_hash_b64", "receipt_sig_b64", "sig_alg"):
        assert f in receipt
    payload = {
        k: v
        for k, v in receipt.items()
        if k not in ("payload_hash_b64", "receipt_sig_b64", "sig_alg")
    }
    assert payload["node_id"] == "node-test-1"
    assert payload["openssl_version"] == "3.2.1-test"
    entry = payload["entries"][0]
    assert entry["provider"] == "openssl"
    assert entry["version"] == "3.2.1-test"
    assert entry["algorithms"]["groups"] == ["grpA", "grpB"]

    # Ensure receipt persisted
    files = sorted(RECEIPTS.glob("pqc_cbom_*.json"))
    assert files, "Expected a stored pqc.cbom receipt file"
    obj = json.loads(files[-1].read_text())
    assert obj["kind"] == "pqc.cbom"
    # First receipt in a fresh dir should have no prev link
    assert obj.get("prev_receipt_hash_b64") in (None,)

    # Verify signature using stored public key
    import spcp.api.main as main_mod
    vk_b64 = main_mod.VK_FILE.read_text().strip()
    vk_bytes = base64.b64decode(vk_b64)
    assert verify_receipt_ed25519(obj, vk_bytes)

    # STH updated
    assert STH_FILE.exists(), "STH file missing after cbom event"
    sth = json.loads(STH_FILE.read_text())
    assert sth["tree_size"] >= 1

    # Root consistency: recompute leaf hash and compare with inclusion in tree_size 1 case
    if sth["tree_size"] == 1:
        # Recompute leaf hash as done in _refresh_sth
        core = {
            k: v
            for k, v in obj.items()
            if k not in ("payload_hash_b64", "receipt_sig_b64", "sig_alg")
        }
        payload_bytes = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
        leaf_hash = hashlib.sha256(payload_bytes).digest()
        root_b64 = sth["root_sha256_b64"]
        assert base64.b64encode(leaf_hash).decode() == root_b64
