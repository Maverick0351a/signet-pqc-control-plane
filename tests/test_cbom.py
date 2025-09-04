from fastapi.testclient import TestClient
from spcp.api.main import app, DATA, RECEIPTS
from spcp.proxy import cbom as cbom_mod
import json, shutil


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
        assert url.endswith('/events')
        resp = c.post('/events', json=json)
        class R:
            def __init__(self, r):
                self._r = r
            def raise_for_status(self):
                self._r.raise_for_status()
            def json(self):
                return self._r.json()
        return R(resp)

    receipt = cbom_mod.collect_cbom(str(c.base_url).rstrip('/'), node_id="node-test-1", _post_func=_client_post)
    assert receipt["kind"] == "pqc.cbom"
    payload = {k: v for k, v in receipt.items() if k not in ("payload_hash_b64", "receipt_sig_b64", "sig_alg")}
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
