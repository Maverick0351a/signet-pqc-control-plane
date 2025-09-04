from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from spcp.api.main import DATA, _load_keys, _read_prev_hash, _store_signed_receipt
from spcp.receipts.jcs import jcs_canonical
from spcp.receipts.merkle import build_sth
from spcp.receipts.sign import sign_receipt_ed25519


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
    return signed


# ---------------------------------------------------------------------------
# Enforcement Receipts + Batched Merkle STH Generation (control-plane flavor)
# ---------------------------------------------------------------------------

PROOFS_DIR = DATA / "proofs"
STH_DIR = DATA / "sth"
for _d in (PROOFS_DIR, STH_DIR):
    _d.mkdir(parents=True, exist_ok=True)

_batch_lock = threading.Lock()
_batch_leaf_hashes: list[bytes] = []  # raw sha256 payload hashes
_batch_receipt_paths: list[Path] = []
_last_sth_root: str | None = None

_STH_INTERVAL_SECONDS = int(os.getenv("PQC_STH_INTERVAL_SECONDS", "60"))


def write_enforcement_receipt(
    decision: bool,
    reason: str | None,
    caller_id: str | None,
    route: str | None,
    pch_present: bool,
    pch_verified: bool,
    binding_type: str | None,
    evidence_ref: dict[str, Any] | None,
    failure_reason: str | None,
    negotiated: dict[str, Any] | None = None,
    policy_version: str | None = None,
    policy_hash_b64: str | None = None,
) -> dict:
    """Create and persist a pqc.enforcement receipt and enqueue leaf for next STH.

    Parameters mirror enforcement context. Only minimal negotiated tuple is stored
    if provided. prev_receipt_hash_b64 forms a hash-linked chain referencing the
    previous receipt's payload hash.
    """
    sk, _ = _load_keys()
    rec: dict[str, Any] = {
        "kind": "pqc.enforcement",
        "ts_ms": int(time.time() * 1000),
        "decision": {"allow": bool(decision), **({"reason": reason} if reason else {})},
        "prev_receipt_hash_b64": _read_prev_hash(),
        "caller_id": caller_id,
        "route": route,
    }
    if policy_version:
        rec["policy_version"] = policy_version
    if policy_hash_b64:
        rec["policy_hash_b64"] = policy_hash_b64
    if negotiated:
        rec["negotiated"] = negotiated
    if pch_present:
        rec["pch_present"] = True
        rec["pch"] = {
            "present": True,
            "verified": pch_verified,
            "channel_binding": binding_type,
            "evidence_ref": evidence_ref,
            "failure_reason": failure_reason,
        }
    signed = sign_receipt_ed25519(rec, sk)
    hash_prefix = signed["payload_hash_b64"][:8].replace("/", "_").replace("+", "-")
    path = _store_signed_receipt(f"pqc_enforcement_{hash_prefix}", signed)
    # Enqueue for next STH batch
    try:
        raw_hash = base64.b64decode(signed["payload_hash_b64"])  # 32 bytes
        with _batch_lock:
            _batch_leaf_hashes.append(raw_hash)
            _batch_receipt_paths.append(path)
    except Exception:  # pragma: no cover - defensive
        import logging as _log
        _log.debug("enqueue enforcement receipt failed", exc_info=True)
    return signed


def _flush_sth_batch() -> None:
    """Build Merkle tree for current batch and persist STH + inclusion proofs."""
    global _batch_leaf_hashes, _batch_receipt_paths, _last_sth_root
    with _batch_lock:
        if not _batch_leaf_hashes:
            return
        leaf_hashes = _batch_leaf_hashes
        paths = _batch_receipt_paths
        _batch_leaf_hashes = []
        _batch_receipt_paths = []
    # Build STH
    leaves_b64 = [base64.b64encode(h).decode() for h in leaf_hashes]
    sth = build_sth(leaves_b64)
    sth["kind"] = "pqc.sth"
    # Sign STH (treat as receipt-like object)
    sk, _ = _load_keys()
    signed_sth = sign_receipt_ed25519(sth, sk)
    root = signed_sth.get("root_sha256_b64") or sth.get("root_sha256_b64")
    _last_sth_root = root
    ts = signed_sth.get("timestamp") or int(time.time() * 1000)
    STH_DIR.mkdir(parents=True, exist_ok=True)
    sth_file = STH_DIR / f"sth_{ts}.json"
    sth_file.write_text(json.dumps(signed_sth, indent=2))
    # Inclusion proofs per leaf
    from spcp.receipts.merkle import inclusion_proof as _inc
    for idx, (leaf_raw, path) in enumerate(zip(leaf_hashes, paths, strict=False)):
        try:
            proof = _inc(idx, leaf_hashes)
            proof_doc = {
                "kind": "pqc.proof.inclusion",
                "leaf_index": idx,
                "leaf_hash_b64": base64.b64encode(leaf_raw).decode(),
                "sth_root_b64": root,
                "tree_size": len(leaf_hashes),
                "proof": proof,
                "receipt_file": path.name,
            }
            proof_file = PROOFS_DIR / f"proof_{path.stem}.json"
            proof_file.write_text(json.dumps(proof_doc, indent=2))
        except Exception:  # pragma: no cover
            import logging as _log
            _log.debug("failed writing inclusion proof", exc_info=True)
            continue


def _sth_loop() -> None:  # pragma: no cover - background
    while True:
        time.sleep(_STH_INTERVAL_SECONDS)
        try:
            _flush_sth_batch()
        except Exception:  # pragma: no cover
            import logging as _log
            _log.debug("STH batch flush error", exc_info=True)
            continue


# Start background thread on module import
_sth_thread = threading.Thread(target=_sth_loop, name="sth-batch-loop", daemon=True)
_sth_thread.start()

__all__ = [
    "write_cbom_receipt",
    "write_drift_receipt",
    "write_policy_change_receipt",
    "write_enforcement_receipt",
]


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
        if len(a) != len(b) or any(x != y for x, y in zip(a, b, strict=False)):
            ops.append({"op": "replace", "path": path or "/", "value": b})
        return ops
    if a != b:
        ops.append({"op": "replace", "path": path or "/", "value": b})
    return ops
