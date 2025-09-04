from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from spcp.receipts.sign import sign_receipt_ed25519
from spcp.receipts.jcs import jcs_canonical
from spcp.api.main import (
    _read_prev_hash,  # noqa: WPS450 (reuse internal helpers)
    _store_signed_receipt,
    _refresh_sth,
    _load_keys,
    DATA,
)


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def write_cbom_receipt(
    cbom_hash_b64: str,
    signature_b64: str | None,
    policy_id: str | None,
    platform: dict[str, Any] | None,
    attestation: dict[str, Any] | None = None,
    classification: str | None = None,
) -> dict:
    sk, _ = _load_keys()
    rec: dict[str, Any] = {
        "kind": "pqc.cbom",
        "ts_ms": int(time.time() * 1000),
        "cbom_hash_b64": cbom_hash_b64,
        "policy_id": policy_id,
        "platform": platform or {},
        "prev_receipt_hash_b64": _read_prev_hash(),
    }
    if signature_b64:
        rec["cbom_sig_b64"] = signature_b64
    if attestation:
        rec["attestation"] = attestation
    if classification:
        rec["classification"] = classification
    signed = sign_receipt_ed25519(rec, sk)
    hash_prefix = signed["payload_hash_b64"][:8].replace("/", "_").replace("+", "-")
    _store_signed_receipt(f"pqc_cbom_{hash_prefix}", signed)
    _refresh_sth()
    return signed


def write_drift_receipt(
    delta_json_patch: list[dict[str, Any]],
    classification: str,
    cbom_hash_b64: str,
    baseline_hash_b64: str,
) -> dict:
    sk, _ = _load_keys()
    rec: dict[str, Any] = {
        "kind": "pqc.drift",
        "ts_ms": int(time.time() * 1000),
        "delta": delta_json_patch,
        "classification": classification,
        "cbom_hash_b64": cbom_hash_b64,
        "baseline_hash_b64": baseline_hash_b64,
        "prev_receipt_hash_b64": _read_prev_hash(),
    }
    signed = sign_receipt_ed25519(rec, sk)
    hash_prefix = signed["payload_hash_b64"][:8].replace("/", "_").replace("+", "-")
    _store_signed_receipt(f"pqc_drift_{hash_prefix}", signed)
    _refresh_sth()
    return signed


def write_policy_change_receipt(kind: str, previous: str | None, new: str) -> dict:
    """Emit a policy.change receipt referencing baseline or tuple policy evolution.

    Parameters
    ----------
    kind : Descriptor of changed artifact (e.g., 'cbom.baseline').
    previous : Prior fingerprint/hash (if any).
    new : New fingerprint/hash.
    """
    sk, _ = _load_keys()
    rec: dict[str, Any] = {
        "kind": "policy.change",
        "ts_ms": int(time.time()*1000),
        "change_kind": kind,
        "previous": previous,
        "new": new,
        "prev_receipt_hash_b64": _read_prev_hash(),
    }
    signed = sign_receipt_ed25519(rec, sk)
    hash_prefix = signed["payload_hash_b64"][:8].replace("/", "_").replace("+", "-")
    _store_signed_receipt(f"policy_change_{hash_prefix}", signed)
    _refresh_sth()
    return signed


# Storage helpers for CBOM/baseline/documents
CBOM_DIR = DATA / "cbom_docs"
DRIFT_DIR = DATA / "drift_reports"
BASELINE_FILE = CBOM_DIR / "baseline.json"
for _d in (CBOM_DIR, DRIFT_DIR):
    _d.mkdir(parents=True, exist_ok=True)


def store_cbom_document(doc: dict) -> tuple[Path, str]:
    core_bytes = jcs_canonical(doc)
    cbom_hash_b64 = _sha256_b64(core_bytes)
    fname = f"cbom_{cbom_hash_b64[:12].replace('/', '_').replace('+', '-')}.json"
    path = CBOM_DIR / fname
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2))
    return path, cbom_hash_b64


def load_latest_cbom() -> dict | None:
    files = sorted(CBOM_DIR.glob("cbom_*.json"))
    if not files:
        return None
    try:
        return json.loads(files[-1].read_text())
    except Exception:  # noqa: S112
        return None


def load_baseline() -> dict | None:
    if not BASELINE_FILE.exists():
        return None
    try:
        return json.loads(BASELINE_FILE.read_text())
    except Exception:  # noqa: S112
        return None


def set_baseline(doc: dict) -> str:
    core_bytes = jcs_canonical(doc)
    h = _sha256_b64(core_bytes)
    previous = None
    if BASELINE_FILE.exists():
        try:
            previous = json.loads(BASELINE_FILE.read_text()).get("fingerprint")
        except Exception:  # noqa: S112
            previous = None
    CBOM_DIR.mkdir(parents=True, exist_ok=True)
    BASELINE_FILE.write_text(json.dumps({"fingerprint": h, "document": doc}, indent=2))
    # Log policy change
    write_policy_change_receipt("cbom.baseline", previous, h)
    return h


def load_latest_drift_report() -> dict | None:
    files = sorted(DRIFT_DIR.glob("drift_*.json"))
    if not files:
        return None
    try:
        return json.loads(files[-1].read_text())
    except Exception:  # noqa: S112
        return None


def store_drift_report(report: dict) -> Path:
    DRIFT_DIR.mkdir(parents=True, exist_ok=True)
    fname = f"drift_{int(time.time())}.json"
    path = DRIFT_DIR / fname
    path.write_text(json.dumps(report, indent=2))
    return path


def compute_json_patch(a: Any, b: Any, path: str = "") -> list[dict[str, Any]]:  # noqa: D401
    """Compute a minimal JSON Patch (RFC 6902 subset) using replace/add/remove."""
    ops: list[dict[str, Any]] = []
    if type(a) != type(b):  # noqa: E721
        ops.append({"op": "replace", "path": path or "/", "value": b})
        return ops
    if isinstance(a, dict):
        a_keys = set(a.keys())
        b_keys = set(b.keys())
        for k in sorted(a_keys - b_keys):
            ops.append({"op": "remove", "path": f"{path}/{k}" if path else f"/{k}"})
        for k in sorted(b_keys - a_keys):
            ops.append({"op": "add", "path": f"{path}/{k}" if path else f"/{k}", "value": b[k]})
        for k in sorted(a_keys & b_keys):
            ops.extend(compute_json_patch(a[k], b[k], f"{path}/{k}" if path else f"/{k}"))
        return ops
    if isinstance(a, list):
        # naive list diff: replace when different length or element mismatch
        if len(a) != len(b) or any(x != y for x, y in zip(a, b)):
            ops.append({"op": "replace", "path": path or "/", "value": b})
        return ops
    if a != b:
        ops.append({"op": "replace", "path": path or "/", "value": b})
    return ops
