
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class PQCNegotiated(BaseModel):
    tls_version: str
    cipher: str
    group_or_kem: str
    sig_alg: str
    sni: str | None = None
    peer_ip: str | None = None
    alpn: str | None = None  # negotiated application protocol (e.g., h2, http/1.1)
    client_cert_sha256: str | None = None  # future mTLS support (hex or b64 digest)
    client_cert_sig_alg: str | None = None  # signature algorithm of client cert

class EnforcementDecision(BaseModel):
    allow: bool
    reason: str | None = None

class PQCEnforcementReceipt(BaseModel):
    kind: Literal["pqc.enforcement"] = "pqc.enforcement"
    ts_ms: int
    policy_version: str
    policy_hash_b64: str
    negotiated: PQCNegotiated
    decision: EnforcementDecision
    prev_receipt_hash_b64: str | None = None

class CBOMEntry(BaseModel):
    provider: str
    version: str
    algorithms: dict[str, Any] = Field(default_factory=dict)

class PQCCBOMReceipt(BaseModel):
    kind: Literal["pqc.cbom"] = "pqc.cbom"
    ts_ms: int
    node_id: str
    openssl_version: str | None = None
    entries: list[CBOMEntry]
    prev_receipt_hash_b64: str | None = None

class PolicyDoc(BaseModel):
    version: str
    allow_groups: list[str] = Field(default_factory=list)  # e.g., ["kyber768","p256_kyber768"]
    deny_groups: list[str] = Field(default_factory=list)   # explicit denies win
    mode: Literal["classical", "hybrid", "pqc"] = "hybrid"
    description: str | None = None

class PolicyChangeReceipt(BaseModel):
    kind: Literal["policy.change"] = "policy.change"
    ts_ms: int
    actor: str
    from_version: str | None = None
    to_version: str
    reason: str | None = None
    prev_receipt_hash_b64: str | None = None
