
from __future__ import annotations
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, Dict, Any, Literal

class PQCNegotiated(BaseModel):
    tls_version: str
    cipher: str
    group_or_kem: str
    sig_alg: str
    sni: Optional[str] = None
    peer_ip: Optional[str] = None

class EnforcementDecision(BaseModel):
    allow: bool
    reason: Optional[str] = None

class PQCEnforcementReceipt(BaseModel):
    kind: Literal["pqc.enforcement"] = "pqc.enforcement"
    ts_ms: int
    policy_version: str
    policy_hash_b64: str
    negotiated: PQCNegotiated
    decision: EnforcementDecision
    prev_receipt_hash_b64: Optional[str] = None

class CBOMEntry(BaseModel):
    provider: str
    version: str
    algorithms: Dict[str, Any] = Field(default_factory=dict)

class PQCCBOMReceipt(BaseModel):
    kind: Literal["pqc.cbom"] = "pqc.cbom"
    ts_ms: int
    node_id: str
    openssl_version: Optional[str] = None
    entries: list[CBOMEntry]
    prev_receipt_hash_b64: Optional[str] = None

class PolicyDoc(BaseModel):
    version: str
    allow_groups: list[str] = Field(default_factory=list)  # e.g., ["kyber768","p256_kyber768"]
    deny_groups: list[str] = Field(default_factory=list)   # explicit denies win
    mode: Literal["classical", "hybrid", "pqc"] = "hybrid"
    description: Optional[str] = None

class PolicyChangeReceipt(BaseModel):
    kind: Literal["policy.change"] = "policy.change"
    ts_ms: int
    actor: str
    from_version: Optional[str] = None
    to_version: str
    reason: Optional[str] = None
    prev_receipt_hash_b64: Optional[str] = None
