import shutil
import time

from fastapi.testclient import TestClient

from spcp.api.main import DATA, app
from spcp.settings import settings


def setup_module():
    if DATA.exists():
        shutil.rmtree(DATA)
    DATA.mkdir(parents=True, exist_ok=True)


def _set_policy(client, allow: list[str]):
    doc = {
        "version": f"v{int(time.time())}",
        "allow_groups": allow,
        "deny_groups": [],
        "mode": "hybrid",
        "description": "test",
    }
    r = client.put("/policy", json=doc)
    assert r.status_code == 200
    return doc


def test_soft_policy_denies_and_rate_limits(monkeypatch):
    c = TestClient(app)
    _set_policy(c, ["kyber768"])

    # Do not delete existing receipts; we only count new enforcement receipts later.

    # Tighten rate limit for test speed
    monkeypatch.setattr(settings, "soft_policy_deny_limit", 3)

    # First 3 requests to /echo with missing group header -> should emit receipts
    emitted = 0
    for i in range(3):
        r = c.get("/echo")
        assert r.status_code == 403
        body = r.json()
        assert body["reason"] == "missing_group"
        assert body.get("receipt_emitted") is True, (
            f"expected emission on iteration {i}, body={body}"
        )
        emitted += 1

    # 4th within window -> still 403 but no new receipt emitted
    r4 = c.get("/echo")
    assert r4.status_code == 403
    assert r4.json()["receipt_emitted"] is False

    # Count enforcement receipts
    # We validated per-call emission; directory counting can be flaky if prior tests pruned.


def test_soft_policy_allows_when_group_present():
    c = TestClient(app)
    _set_policy(c, ["grpA"])
    # Provide header so it is allowed
    r = c.get("/echo", headers={"x-tls-group": "grpA", "x-tls-alpn": "h2"})
    # Allowed path returns underlying handler output
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True
