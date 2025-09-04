from __future__ import annotations

import argparse
import json
import shutil
import sys
import zipfile
from pathlib import Path

from .receipts.pack import pack_compliance_zip
from .settings import settings


def cmd_pack(args: argparse.Namespace) -> int:
    out = Path(args.out)
    data = settings.spcp_data_dir
    receipts = data / "receipts"
    sth = data / "sth.json"
    proofs = data / "proofs"
    if not receipts.exists() or not list(receipts.glob("*.json")):
        print("No receipts found to pack.", file=sys.stderr)
        return 1
    if not sth.exists():
        print("sth.json not found; run the service to generate receipts first.", file=sys.stderr)
        return 1
    pack_compliance_zip(out, receipts, sth, proofs if proofs.exists() else None)
    print(f"Wrote {out}")
    return 0


def _extract_zip(zpath: Path, dest: Path) -> Path:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    with zipfile.ZipFile(zpath, "r") as z:
        z.extractall(dest)
    return dest


def cmd_verify(args: argparse.Namespace) -> int:
    target_dir: Path
    if args.dir:
        target_dir = Path(args.dir)
    else:
        # if a zip is provided, extract; else error
        if not args.zip:
            print("Provide --dir or --zip", file=sys.stderr)
            return 2
        z = Path(args.zip)
        if not z.exists():
            print(f"Zip not found: {z}", file=sys.stderr)
            return 2
        target_dir = _extract_zip(z, Path(args.work) if args.work else Path("compliance-unpacked"))

    receipts = target_dir / "receipts"
    if not receipts.exists():
        print("Missing receipts directory", file=sys.stderr)
        return 3
    # Simple inline verification replicating offline script logic
    # (avoid executing bundled python blindly)
    import base64
    import hashlib
    def sha256(b): return hashlib.sha256(b).digest()
    def b64(b): return base64.b64encode(b).decode()
    failures = 0
    for p in sorted(receipts.glob("*.json")):
        obj = json.loads(p.read_text())
        core = {
            k: v
            for k, v in obj.items()
            if k not in ("payload_hash_b64", "receipt_sig_b64", "sig_alg")
        }
        payload = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
        h = b64(sha256(payload))
        ok = h == obj.get("payload_hash_b64")
        print(f"{p.name}: {'OK' if ok else 'MISMATCH'}")
        if not ok:
            failures += 1
    if failures:
        print(f"FAIL: {failures} mismatches", file=sys.stderr)
        return 4
    print("All receipt payload hashes OK.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="spcp_cli",
        description="Signet PQC Control Plane CLI utilities",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_pack = sub.add_parser(
        "pack",
        help="Create compliance ZIP (receipts + STH + proofs)",
    )
    p_pack.add_argument("--out", required=True, help="Output zip path (e.g. compliance.zip)")
    p_pack.set_defaults(func=cmd_pack)

    p_verify = sub.add_parser("verify", help="Verify receipt hashes offline")
    g = p_verify.add_mutually_exclusive_group(required=False)
    g.add_argument("--dir", help="Directory containing receipts/ sth/ proofs/")
    g.add_argument("--zip", help="Compliance zip to extract and verify")
    p_verify.add_argument(
        "--work",
        help="Work directory for extraction (default: compliance-unpacked)",
    )
    p_verify.set_defaults(func=cmd_verify)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
