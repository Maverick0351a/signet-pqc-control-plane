import base64
import json
from pathlib import Path

from spcp.receipts.jcs import jcs_canonical
from spcp.receipts.sign import gen_ed25519_keypair, sign_receipt_ed25519, verify_receipt_ed25519
from control_plane.receipts import compute_json_patch, write_cbom_receipt, CBOM_DIR
from spcp.api.main import _read_prev_hash, _refresh_sth, RECEIPTS, DATA  # internal helpers


def test_jcs_stability_and_number_forms():
    obj = {"b": 2, "a": 1, "arr": [1, 2, 3], "nested": {"y": True, "x": False}, "float": 1.50}
    first = jcs_canonical(obj)
    for _ in range(5):
        assert jcs_canonical(obj) == first
    assert b'"float":1.5' in first  # trimmed fractional zeros


def test_ed25519_roundtrip():
    sk, vk = gen_ed25519_keypair()
    receipt = {"kind": "pqc.test", "ts_ms": 1234567890123, "value": {"x": 1}}
    signed = sign_receipt_ed25519(receipt, sk)
    assert verify_receipt_ed25519(signed, vk)
    # Tamper
    tampered = dict(signed)
    tampered["value"] = {"x": 2}
    assert not verify_receipt_ed25519(tampered, vk)


def test_json_patch_generation():
    before = {"components": [{"name": "openssl", "version": "3.0.0"}], "services": []}
    after = {"components": [{"name": "openssl", "version": "3.0.1"}], "services": []}
    patch = compute_json_patch(before, after)
    # Current diff logic replaces entire list when any element differs
    assert any(op.get("op") == "replace" and op.get("path") == "/components" for op in patch)


def test_receipt_hash_linking_with_cbom(tmp_path, monkeypatch):
    # Use isolated data dir (manually override globals)
    data_dir = tmp_path / "data"
    receipts_dir = data_dir / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)
    from spcp.receipts.sign import gen_ed25519_keypair
    sk, _vk = gen_ed25519_keypair()
    r1 = sign_receipt_ed25519({"kind": "pqc.test", "ts_ms": 1}, sk)
    (receipts_dir / "r1.json").write_text(json.dumps(r1))
    r2 = sign_receipt_ed25519({"kind": "pqc.test", "ts_ms": 2, "prev_receipt_hash_b64": r1["payload_hash_b64"]}, sk)
    (receipts_dir / "r2.json").write_text(json.dumps(r2))
    # Monkeypatch _read_prev_hash to point to our temp receipts
    def fake_read_prev_local():
        return r2["payload_hash_b64"]
    from control_plane import receipts as cp_receipts
    monkeypatch.setattr(cp_receipts, "_read_prev_hash", fake_read_prev_local)
    # Monkeypatch storage directories used inside receipts module
    monkeypatch.setattr(cp_receipts, "DATA", data_dir)
    monkeypatch.setattr(cp_receipts, "CBOM_DIR", data_dir / "cbom_docs")
    (data_dir / "cbom_docs").mkdir(exist_ok=True)
    # Issue CBOM receipt
    cbom_signed = write_cbom_receipt("abc123==", None, None, {"os": "Linux"})
    assert cbom_signed["prev_receipt_hash_b64"] == r2["payload_hash_b64"]
    assert "payload_hash_b64" in cbom_signed and "receipt_sig_b64" in cbom_signed
