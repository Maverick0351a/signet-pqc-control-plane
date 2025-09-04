"""Receipt hash audit comparing legacy deterministic JSON vs RFC8785 JCS.

Outputs CSV to stdout:
filename,stored_hash,old_algo_hash,new_jcs_hash,stored_eq_old,stored_eq_new

At end prints SUMMARY: migration_needed=<true|false> if any stored hash != new hash.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from spcp.receipts.jcs import jcs_canonical

DATA = Path("data")
RECEIPTS = DATA / "receipts"

def sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()

def main():
    if not RECEIPTS.exists():
        print("NO_RECEIPTS")
        return
    rows = []
    for f in sorted(RECEIPTS.glob("*.json")):
        obj = json.loads(f.read_text())
        stored = obj.get("payload_hash_b64") or ""
        core = {
            k: v
            for k, v in obj.items()
            if k not in ("payload_hash_b64", "receipt_sig_b64", "sig_alg")
        }
        old_payload = json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
        old_hash = sha256_b64(old_payload)
        new_payload = jcs_canonical(core)
        new_hash = sha256_b64(new_payload)
        rows.append((f.name, stored, old_hash, new_hash, stored == old_hash, stored == new_hash))
    print("filename,stored_hash,old_hash,new_hash,stored_eq_old,stored_eq_new")
    migration_needed = False
    for r in rows:
        print(",".join([r[0], r[1], r[2], r[3], str(r[4]).lower(), str(r[5]).lower()]))
        if r[1] and not r[5]:
            migration_needed = True
    print(f"SUMMARY:migration_needed={str(migration_needed).lower()}")

if __name__ == "__main__":
    main()
