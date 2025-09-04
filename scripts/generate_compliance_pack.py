"""Generate a demo compliance pack.

Steps performed:
1. Reset data directory (./data).
2. PUT policy v1 (hybrid) allowing p256_kyber768.
3. Emit one allowed pqc.enforcement receipt.
4. Emit 25 denied enforcement receipts (group p256) to trip circuit breaker.
5. Produce compliance.zip via CLI pack command.

Run:
    python scripts/generate_compliance_pack.py

Outputs:
  - Prints summary (total receipts, presence of policy_change v1-cb, STH tree size).
  - Writes compliance.zip in repo root.
"""
from __future__ import annotations

import base64, hashlib, json, time, shutil, subprocess, sys
from pathlib import Path
from fastapi.testclient import TestClient

from spcp.api.main import app, DATA, RECEIPTS, STH_FILE


def main() -> int:
    # 1. Reset data dir
    if DATA.exists():
        shutil.rmtree(DATA)
    DATA.mkdir(parents=True, exist_ok=True)

    client = TestClient(app)

    # 2. Policy
    policy = {
        "version": "v1",
        "mode": "hybrid",
        "allow_groups": ["p256_kyber768"],
        "deny_groups": [],
        "description": "pilot",
    }
    r = client.put("/policy", json=policy)
    if r.status_code != 200:
        print("Failed to set policy:", r.status_code, r.text)
        return 1
    policy_hash_b64 = base64.b64encode(
        hashlib.sha256(
            json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
        ).digest()
    ).decode()

    # 3. Allow event
    allow_ev = {
        "kind": "pqc.enforcement",
        "ts_ms": int(time.time() * 1000),
        "policy_version": "v1",
        "policy_hash_b64": policy_hash_b64,
        "negotiated": {
            "tls_version": "TLS1.3",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "group_or_kem": "p256_kyber768",
            "sig_alg": "ed25519",
            "sni": "svc.local",
        },
        "decision": {"allow": True},
    }
    client.post("/events", json=allow_ev)

    # 4. Deny burst (25) to trip breaker (>=20 events & >10% failure rate)
    deny_ev = dict(allow_ev)
    deny_ev["negotiated"] = dict(allow_ev["negotiated"])
    deny_ev["negotiated"]["group_or_kem"] = "p256"
    deny_ev["decision"] = {"allow": False, "reason": "not in allowlist"}
    for _ in range(25):
        client.post("/events", json=deny_ev)

    files = sorted(RECEIPTS.glob("*.json"))
    print("Total receipts:", len(files))
    policy_change = [f for f in files if "policy_change_v1-cb" in f.name]
    print("Policy change present:", bool(policy_change))
    print("Last 5 receipts:", [f.name for f in files[-5:]])
    if STH_FILE.exists():
        sth = json.loads(STH_FILE.read_text())
        print("STH tree_size:", sth["tree_size"])
    else:
        print("STH missing")

    # 5. Pack compliance.zip
    zip_path = Path("compliance.zip")
    if zip_path.exists():
        zip_path.unlink()
    ret = subprocess.run([sys.executable, "-m", "spcp.spcp_cli", "pack", "--out", str(zip_path)])
    print("Pack exit code:", ret.returncode)
    print("ZIP present:", zip_path.exists())
    return ret.returncode


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
