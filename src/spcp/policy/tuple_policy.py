from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..api.models import TuplePolicy, PQCNegotiated
from ..settings import settings

TUPLE_POLICY_FILE = settings.spcp_data_dir / "tuple-policy.json"

DEFAULT_POLICY = TuplePolicy(
    policy_id="pqc-default-001",
    allowed={
        "tls_version": ["1.3"],
        "kx_groups": ["X25519", "X25519Kyber768"],
        "sig_algs": ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "ed25519"],
    },
    deny_on_mismatch=True,
)


def load_tuple_policy() -> TuplePolicy:
    if not TUPLE_POLICY_FILE.exists():
        TUPLE_POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
        TUPLE_POLICY_FILE.write_text(DEFAULT_POLICY.model_dump_json(indent=2))
        return DEFAULT_POLICY
    return TuplePolicy.model_validate_json(TUPLE_POLICY_FILE.read_text())


def set_tuple_policy(p: TuplePolicy) -> TuplePolicy:
    TUPLE_POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
    TUPLE_POLICY_FILE.write_text(p.model_dump_json(indent=2))
    return p


def evaluate_tuple_policy(negotiated: PQCNegotiated) -> tuple[bool, Optional[str]]:
    pol = load_tuple_policy()
    allow, reason = pol.evaluate(negotiated)
    if not allow and pol.deny_on_mismatch:
        return False, reason or "policy_mismatch"
    return True, None
