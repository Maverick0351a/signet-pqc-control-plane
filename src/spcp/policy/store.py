
from __future__ import annotations

import json
import logging
import time

from ..api.models import PolicyChangeReceipt, PolicyDoc
from ..receipts.sign import sign_receipt_ed25519
from ..settings import settings

POLICY_FILE = settings.spcp_data_dir / "policy.json"
RECEIPTS_DIR = settings.spcp_data_dir / "receipts"
RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)

def _read_prev_hash() -> str | None:
    """Return the payload hash of the newest valid receipt, skipping malformed files."""
    files = sorted(RECEIPTS_DIR.glob("*.json"))
    for p in reversed(files):  # newest first
        try:
            obj = json.loads(p.read_text())
        except Exception as e:  # noqa: S112
            logging.exception("Failed to parse receipt file %s while finding prev hash: %s", p, e)
            continue
        if isinstance(obj, dict) and "payload_hash_b64" in obj:
            return obj.get("payload_hash_b64")
    return None

def load_policy() -> PolicyDoc:
    if not POLICY_FILE.exists():
        doc = PolicyDoc(
            version="v0",
            allow_groups=[],
            deny_groups=[],
            mode="hybrid",
            description="default",
        )
        POLICY_FILE.write_text(doc.model_dump_json(indent=2))
        return doc
    return PolicyDoc.model_validate_json(POLICY_FILE.read_text())

def set_policy(new_doc: PolicyDoc, signer_sk: bytes) -> dict:
    prev = load_policy()
    POLICY_FILE.write_text(new_doc.model_dump_json(indent=2))
    rec = PolicyChangeReceipt(
        kind="policy.change",
        ts_ms=int(time.time()*1000),
        actor="control-plane",
        from_version=prev.version,
        to_version=new_doc.version,
        reason="update",
        prev_receipt_hash_b64=_read_prev_hash()
    ).model_dump()
    signed = sign_receipt_ed25519(rec, signer_sk)
    # Tests may remove the data directory after module import; recreate lazily.
    RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RECEIPTS_DIR / f"policy_change_{new_doc.version}.json"
    out.write_text(json.dumps(signed, indent=2))
    return signed
