import json, base64, hashlib, time, shutil, subprocess, sys
from pathlib import Path
from fastapi.testclient import TestClient


def test_cli_pack_and_verify(tmp_path):
    """End-to-end: generate receipts, pack via CLI, verify hashes from ZIP extraction."""
    # Repoint data dir dynamically
    from spcp import settings as settings_mod
    from spcp.settings import settings
    import importlib
    # Adjust settings data dir
    data_dir = tmp_path / 'data'
    settings.spcp_data_dir = data_dir
    data_dir.mkdir(parents=True, exist_ok=True)

    # Re-import main to rebuild path constants with new data dir
    import spcp.api.main as main_mod
    # Manually patch path globals (since module already imported earlier in suite)
    main_mod.DATA = data_dir
    main_mod.RECEIPTS = data_dir / 'receipts'
    main_mod.PROOFS = data_dir / 'proofs'
    main_mod.STH_FILE = data_dir / 'sth.json'
    main_mod.KEY_DIR = data_dir / 'keys'
    for d in (main_mod.RECEIPTS, main_mod.PROOFS, main_mod.KEY_DIR):
        d.mkdir(parents=True, exist_ok=True)

    c = TestClient(main_mod.app)

    # Create policy
    policy = {"version":"v1","allow_groups":["grp"],"deny_groups":[],"mode":"hybrid","description":"demo"}
    r = c.put('/policy', json=policy)
    assert r.status_code == 200
    policy_hash_b64 = base64.b64encode(hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(',', ':')).encode()).digest()).decode()

    def emit(group: str, allow: bool):
        evt = {
            "kind": "pqc.enforcement",
            "ts_ms": int(time.time()*1000),
            "policy_version": policy['version'],
            "policy_hash_b64": policy_hash_b64,
            "negotiated": {
                "tls_version": "TLS1.3",
                "cipher": "TLS_AES_128_GCM_SHA256",
                "group_or_kem": group,
                "sig_alg": "ed25519",
                "sni": "svc.local",
                "peer_ip": "203.0.113.5"
            },
            "decision": {"allow": allow, "reason": None if allow else "blocked"}
        }
        rr = c.post('/events', json=evt)
        assert rr.status_code == 200

    # Generate a few receipts
    emit('grp', True)
    emit('grp', True)
    emit('bad', False)

    assert len(list(main_mod.RECEIPTS.glob('*.json'))) >= 3
    assert main_mod.STH_FILE.exists()

    # Run CLI pack using module invocation
    zip_path = tmp_path / 'compliance.zip'
    proc_pack = subprocess.run([sys.executable, '-m', 'spcp.spcp_cli', 'pack', '--out', str(zip_path)], capture_output=True, text=True)
    assert proc_pack.returncode == 0, proc_pack.stderr
    assert zip_path.exists()

    # Run CLI verify on the produced zip
    proc_verify = subprocess.run([sys.executable, '-m', 'spcp.spcp_cli', 'verify', '--zip', str(zip_path), '--work', str(tmp_path / 'unpacked')], capture_output=True, text=True)
    assert proc_verify.returncode == 0, proc_verify.stderr + '\n' + proc_verify.stdout
    assert 'All receipt payload hashes OK.' in proc_verify.stdout
