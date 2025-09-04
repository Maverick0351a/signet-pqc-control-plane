from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from fastapi import APIRouter, Body, HTTPException

from spcp.receipts.jcs import jcs_canonical
from spcp.receipts.sign import sign_receipt_ed25519
from spcp.api.main import app, _load_keys  # reuse base app
from .receipts import (
    compute_json_patch,
    load_baseline,
    load_latest_cbom,
    load_latest_drift_report,
    set_baseline,
    store_cbom_document,
    store_drift_report,
    write_cbom_receipt,
    write_drift_receipt,
)

router = APIRouter()


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def _extract_platform(doc: dict) -> dict[str, Any]:
    meta = doc.get("metadata", {})
    props = {p.get("name"): p.get("value") for p in meta.get("properties", []) if isinstance(p, dict)}
    return {
        "os": props.get("signet:platform:os"),
        "machine": props.get("signet:platform:machine"),
        "python_version": props.get("signet:python:version"),
    }


def _redact(doc: dict) -> dict:
    # Shallow copy with property filtering for sensitive entries
    clone = json.loads(json.dumps(doc))  # deep copy
    props = clone.get("metadata", {}).get("properties")
    if isinstance(props, list):
        filtered = []
        for p in props:
            name = p.get("name", "") if isinstance(p, dict) else ""
            if any(tok in name for tok in ("binary", "path")):
                continue
            filtered.append(p)
        clone["metadata"]["properties"] = filtered
    # Redact hostnames or paths inside properties values (simple heuristic)
    for section in (clone.get("components"), clone.get("services")):
        if isinstance(section, list):
            for item in section:
                if isinstance(item, dict):
                    props = item.get("properties")
                    if isinstance(props, list):
                        for p in props:
                            if isinstance(p, dict):
                                val = p.get("value")
                                if isinstance(val, str) and ("/" in val or ".local" in val):
                                    p["value"] = "REDACTED"
    return clone


@router.get("/cbom/latest")
def cbom_latest():  # pragma: no cover - simple retrieval
    doc = load_latest_cbom()
    if not doc:
        raise HTTPException(404, "no cbom document")
    # Add trust marker (software-only signature assurance)
    doc.setdefault("signet_trust", {"signature_trust": "software-only"})
    return _redact(doc)


@router.post("/cbom/verify")
def cbom_verify(body: dict = Body(...)):
    """Verify a CBOM document's canonical hash and Ed25519 signature.

    Accepted body shapes:
    1. {"cbom": <doc>, "public_key_b64": "..."}
    2. {"document": <doc>, "public_key_b64": "..."}
    3. (legacy) direct CBOM JSON object with optional key via query not implemented (will error).
    """
    if not isinstance(body, dict):
        raise HTTPException(400, "body must be object")
    doc = body.get("cbom") or body.get("document") or None
    if doc is None and "signatures" in body:
        doc = body
    if not isinstance(doc, dict):
        raise HTTPException(400, "missing cbom/document object")
    try:
        core_bytes = jcs_canonical({k: doc[k] for k in doc if k != "signatures"})
    except Exception as e:  # noqa: S112
        raise HTTPException(400, f"canonicalization_failed: {e}")
    digest_b64 = _sha256_b64(core_bytes)
    public_key_b64: str | None = body.get("public_key_b64")
    ok = False
    signer_key_fp = None
    if public_key_b64:
        try:
            from nacl.signing import VerifyKey
            from nacl.encoding import RawEncoder
            vk = VerifyKey(base64.b64decode(public_key_b64))
            signer_key_fp = hashlib.sha256(vk.encode()).hexdigest()[:16]
            sigs = doc.get("signatures") or []
            for s in sigs:
                if not isinstance(s, dict) or s.get("algorithm") != "ed25519":
                    continue
                val = s.get("value")
                if not val:
                    continue
                try:
                    vk.verify(core_bytes, base64.b64decode(val), encoder=RawEncoder)
                    ok = True
                    break
                except Exception:  # noqa: S112
                    continue
        except Exception:  # noqa: S112
            pass
    return {"ok": ok, "digest_b64": digest_b64, "signer_key_fp": signer_key_fp}


@router.post("/cbom/baseline")
def cbom_set_baseline(body: dict = Body(...)):
    # Accept signed or unsigned doc; compute fingerprint on unsigned core
    core = {k: body[k] for k in body if k != "signatures"}
    fp_bytes = jcs_canonical(core)
    fingerprint = _sha256_b64(fp_bytes)
    set_baseline(core)
    # Optionally create a cbom receipt (classification baseline)
    platform = _extract_platform(core)
    write_cbom_receipt(fingerprint, None, None, platform, classification="baseline")
    return {"ok": True, "fingerprint": fingerprint}


@router.get("/cbom/baseline")
def cbom_get_baseline():  # pragma: no cover
    data = load_baseline()
    if not data:
        raise HTTPException(404, "no baseline")
    # stored format: {fingerprint, document}
    doc = data.get("document") if isinstance(data, dict) else None
    if not isinstance(doc, dict):
        raise HTTPException(500, "baseline corrupt")
    return {"fingerprint": data.get("fingerprint"), "document": _redact(doc)}


@router.get("/cbom/drift/latest")
def cbom_drift_latest():  # pragma: no cover
    rep = load_latest_drift_report()
    if not rep:
        raise HTTPException(404, "no drift report")
    return rep


@router.post("/cbom/ingest")
def cbom_ingest(body: dict = Body(...)):
    """Ingest a signed (or unsigned) CBOM, verify signature if provided, detect drift.

    Drift classification rules:
      - If any patch path touches /metadata/properties entry containing tls.enabled_groups or
        tls.enabled_ciphers => policy-violation
      - Else if OpenSSL component version changes => unauthorized
      - Else informational
    Patch limited to /components, /services, /metadata/properties scopes.
    """
    if not isinstance(body, dict):
        raise HTTPException(400, "body must be object")
    core = {k: body[k] for k in body if k != "signatures"}
    core_bytes = jcs_canonical(core)
    cbom_hash = _sha256_b64(core_bytes)
    # Signature verification (expect key provided optionally)
    sig_valid = False
    sig_b64_first: str | None = None
    vk_b64 = None
    provided_key_b64 = body.get("public_key_b64")  # optional inline key
    sigs = body.get("signatures") or []
    if provided_key_b64 and sigs:
        from nacl.signing import VerifyKey
        from nacl.encoding import RawEncoder
        try:
            vk = VerifyKey(base64.b64decode(provided_key_b64))
            vk_b64 = provided_key_b64
            for s in sigs:
                if not isinstance(s, dict) or s.get("algorithm") != "ed25519":
                    continue
                val = s.get("value")
                if not val:
                    continue
                try:
                    vk.verify(core_bytes, base64.b64decode(val), encoder=RawEncoder)
                    sig_valid = True
                    sig_b64_first = val
                    break
                except Exception:  # noqa: S112
                    continue
        except Exception:  # noqa: S112
            pass
    path, stored_hash = store_cbom_document(body)
    platform = _extract_platform(body)
    cbom_receipt = write_cbom_receipt(stored_hash, sig_b64_first if sig_valid else None, None, platform)

    baseline_record = load_baseline()
    drift_receipt = None
    drift_report = None
    if baseline_record and isinstance(baseline_record, dict):
        baseline_doc = baseline_record.get("document")
        if isinstance(baseline_doc, dict):
            # compute restricted patch
            # Canonicalize (ordering) before diff to avoid spurious key-order noise
            baseline_core_bytes = jcs_canonical({k: baseline_doc[k] for k in baseline_doc if k != "signatures"})
            current_core_bytes = jcs_canonical(core)
            # Re-load canonical structures for diff (they are strings; parse back)
            import json as _json
            baseline_for_diff = _json.loads(baseline_core_bytes)
            current_for_diff = _json.loads(current_core_bytes)
            full_patch = compute_json_patch(baseline_for_diff, current_for_diff)
            allowed_prefixes = ("/components", "/services", "/metadata/properties")
            patch = [op for op in full_patch if any(op.get("path", "").startswith(pfx) for pfx in allowed_prefixes)]
            if patch:
                classification = "informational"
                # Examine patch for policy violations
                for op in patch:
                    path_p = op.get("path", "")
                    if any(tok in path_p for tok in ("tls.enabled_groups", "tls.enabled_ciphers")):
                        classification = "policy-violation"
                        break
                # If not policy violation, check OpenSSL version drift
                if classification == "informational":
                    def _openssl_version(doc_: dict) -> str | None:
                        comps = doc_.get("components") or []
                        if isinstance(comps, list):
                            for c in comps:
                                if isinstance(c, dict) and c.get("name") == "openssl":
                                    return c.get("version")
                        return None
                    if _openssl_version(baseline_doc) != _openssl_version(core):
                        classification = "unauthorized"
                drift_report = {
                    "baseline_fingerprint": baseline_record.get("fingerprint"),
                    "cbom_hash_b64": cbom_hash,
                    "delta": patch,
                    "classification": classification,
                }
                store_drift_report(drift_report)
                drift_receipt = write_drift_receipt(
                    patch,
                    classification,
                    cbom_hash_b64=cbom_hash,
                    baseline_hash_b64=baseline_record.get("fingerprint"),
                )
    return {
        "stored": True,
        "cbom_path": str(path),
        "cbom_hash_b64": cbom_hash,
        "signature_verified": sig_valid,
        "cbom_receipt": cbom_receipt,
        "drift_receipt": drift_receipt,
        "drift_report": drift_report,
        "verify_key_b64": vk_b64,
    }


app.include_router(router)
