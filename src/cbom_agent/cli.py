import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any

from nacl import signing

from .builder import build_cyclonedx_cbom, canonicalize_cbom
from .signer import sign_cbom_document, verify_cbom_signature


def _load_key(path: Path) -> signing.SigningKey:
    raw = path.read_bytes()
    if len(raw) == 32:
        return signing.SigningKey(raw)
    try:
        raw = base64.b64decode(raw)
        return signing.SigningKey(raw)
    except Exception:  # pragma: no cover
        raise SystemExit("Unsupported key format; provide 32-byte raw or base64")


def cmd_collect(_: argparse.Namespace) -> int:
    doc = build_cyclonedx_cbom()
    print(json.dumps(doc, indent=2))
    return 0


def cmd_sign(ns: argparse.Namespace) -> int:
    doc = json.loads(Path(ns.input).read_text())
    key = _load_key(Path(ns.key))
    signed = sign_cbom_document(doc, key)
    Path(ns.output).write_text(json.dumps(signed, indent=2))
    print(f"Signed CBOM written to {ns.output}")
    return 0


def cmd_verify(ns: argparse.Namespace) -> int:
    doc = json.loads(Path(ns.input).read_text())
    verify_key = signing.VerifyKey(base64.b64decode(ns.key)) if ns.key.startswith("MC") else signing.VerifyKey(base64.b64decode(ns.key))
    ok = verify_cbom_signature(doc, verify_key)
    print("OK" if ok else "FAIL")
    return 0 if ok else 2


def cmd_hash(ns: argparse.Namespace) -> int:
    doc = json.loads(Path(ns.input).read_text())
    canonical = canonicalize_cbom(doc)
    import hashlib
    h = hashlib.sha256(canonical.encode("utf-8")).digest()
    print(base64.b64encode(h).decode("ascii"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cbom-agent", description="CycloneDX CBOM agent tooling")
    sub = p.add_subparsers(dest="cmd", required=True)

    collect_p = sub.add_parser("collect", help="Collect and emit unsigned CBOM JSON")
    collect_p.set_defaults(func=cmd_collect)

    sign_p = sub.add_parser("sign", help="Sign a CBOM JSON file")
    sign_p.add_argument("--input", required=True)
    sign_p.add_argument("--output", required=True)
    sign_p.add_argument("--key", required=True, help="Path to 32-byte Ed25519 private key (raw or base64)")
    sign_p.set_defaults(func=cmd_sign)

    verify_p = sub.add_parser("verify", help="Verify CBOM signature")
    verify_p.add_argument("--input", required=True)
    verify_p.add_argument("--key", required=True, help="Base64 Ed25519 public key")
    verify_p.set_defaults(func=cmd_verify)

    hash_p = sub.add_parser("hash", help="Compute canonical hash (sha256 b64) of CBOM doc")
    hash_p.add_argument("--input", required=True)
    hash_p.set_defaults(func=cmd_hash)

    return p


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - thin wrapper
    ns = build_parser().parse_args(argv)
    return ns.func(ns)

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
