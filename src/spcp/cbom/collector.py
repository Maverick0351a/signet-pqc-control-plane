from __future__ import annotations

import base64
import json
import platform
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable

from ..settings import settings
from ..policy.tuple_policy import load_tuple_policy
from ..policy.store import load_policy
from ..receipts.sign import sign_receipt_ed25519


def _run(cmd: list[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=5)
        return out.decode(errors="replace")
    except Exception:  # pragma: no cover - best effort
        return ""


def _parse_providers(text: str) -> list[str]:
    # Lines like:  provider: default
    provs: list[str] = []
    for line in text.splitlines():
        m = re.search(r"provider:\s*(\w+)", line)
        if m:
            provs.append(m.group(1))
    return sorted(set(provs))


def _fingerprint_file(path: Path) -> str | None:
    if not path.exists():
        return None
    import hashlib
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return base64.b64encode(h.digest()).decode()
    except Exception:  # pragma: no cover
        return None


def collect_cbom(proxy_kind: str = "nginx", proxy_config: Path | None = None) -> dict[str, Any]:
    openssl_ver = _run(["openssl", "version", "-v"]).strip() or None
    providers_raw = _run(["openssl", "list", "-providers", "-verbose"]) if openssl_ver else ""
    sig_algs_raw = _run(["openssl", "list", "-signature-algorithms"]) if openssl_ver else ""
    pk_algs_raw = _run(["openssl", "list", "-public-key-algorithms"]) if openssl_ver else ""
    groups_raw = _run(["openssl", "list", "-groups"]) if openssl_ver else ""
    providers = _parse_providers(providers_raw)
    enabled_groups = []
    for line in groups_raw.splitlines():
        line = line.strip().split()[0] if line.strip() else ""
        if line:
            enabled_groups.append(line)
    enabled_ciphers: list[str] = []  # Not trivial to parse from OpenSSL CLI; placeholder
    # Policy context
    tuple_policy = load_tuple_policy()
    policy = load_policy()
    proxy_fp = _fingerprint_file(proxy_config) if proxy_config else None
    node_id = platform.node() or "node"
    kernel = platform.release()
    os_name = platform.system().lower()
    arch = platform.machine()
    receipt_core = {
        "kind": "pqc.cbom",
        "ts_ms": int(time.time() * 1000),
        "node_id": node_id,
        "prev_receipt_hash_b64": None,  # caller fills
        # Extended fields (not enforced by PQCCBOMReceipt yet; outward mapping uses them):
        "platform": {"os": os_name, "arch": arch, "kernel": kernel},
        "openssl": {"version": openssl_ver, "providers": providers},
        "tls": {"enabled_ciphers": enabled_ciphers, "enabled_groups": enabled_groups},
        "proxy": {
            "kind": proxy_kind,
            "config_fingerprint": proxy_fp,
            "policy_id": tuple_policy.policy_id if tuple_policy else policy.version,
        },
        "signature_b64": None,  # filled after signing convenience outward view
    }
    return receipt_core


def sign_and_store_cbom(core: dict[str, Any], sk: bytes, prev_hash: str | None) -> dict[str, Any]:
    # Compose minimal canonical subset for signing (exclude outward convenience fields)
    rec = {k: v for k, v in core.items() if k not in ("signature_b64",)}
    rec["prev_receipt_hash_b64"] = prev_hash
    signed = sign_receipt_ed25519(rec, sk)
    return signed
