
from __future__ import annotations
import json, zipfile
from pathlib import Path
from typing import Iterable

def pack_compliance_zip(out_path: Path, receipts_dir: Path, sth_file: Path, proofs_dir: Path | None = None) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        # Receipts
        for p in sorted(receipts_dir.glob("*.json")):
            z.write(p, arcname=f"receipts/{p.name}")
        # STH
        z.write(sth_file, arcname=f"sth/{sth_file.name}")
        # Proofs (optional)
        if proofs_dir and proofs_dir.exists():
            for p in sorted(proofs_dir.glob("*.json")):
                z.write(p, arcname=f"proofs/{p.name}")
        # Add a tiny offline verifier script
        z.writestr("verify_offline.py", """
import json, base64, hashlib, sys, os

def sha256(b): return hashlib.sha256(b).digest()
def b64(b): return base64.b64encode(b).decode()

def main(root_dir):
    # naive check: recompute hashes of receipts and list them
    rec_dir = os.path.join(root_dir, "receipts")
    names = sorted([n for n in os.listdir(rec_dir) if n.endswith(".json")])
    for n in names:
        with open(os.path.join(rec_dir, n), "r", encoding="utf-8") as f:
            obj = json.load(f)
        core = {k: v for k, v in obj.items() if k not in ("payload_hash_b64", "receipt_sig_b64", "sig_alg")}
        payload = json.dumps(core, sort_keys=True, separators=(',', ':')).encode()
        h = b64(sha256(payload))
        ok = (h == obj.get("payload_hash_b64"))
        print(f"{n}: payload hash {'OK' if ok else 'MISMATCH'}")
    print("Done.")
if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
""")
    return out_path
