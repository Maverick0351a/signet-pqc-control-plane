
from __future__ import annotations

from typing import Any, Literal, Optional

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
    # Optional post-handshake challenge (PCH) verification block
    pch: Optional[dict] = None  # kept generic for backward compatibility; enriched schema below
    # Extended metadata (route path and caller identifier like client IP)
    route: str | None = None
    caller_id: str | None = None


class PCHEvidenceRef(BaseModel):
    type: str
    merkle_root_b64: str
    cbom_hash_b64: str


class PCHBlock(BaseModel):
    present: bool
    verified: bool
    created: int | None = None  # epoch seconds from Authorization header
    challenge: str | None = None  # base64 challenge/nonce value
    key_id_b64: str | None = None
    signature_b64: str | None = None
    channel_binding: str | None = None
    evidence_ref: PCHEvidenceRef | None = None
    failure_reason: str | None = None
    method: str | None = None
    path: str | None = None
    authority: str | None = None

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
    require_pch: bool = False  # if true, PCH auth required for allow

class PolicyChangeReceipt(BaseModel):
    kind: Literal["policy.change"] = "policy.change"
    ts_ms: int
    actor: str
    from_version: str | None = None
    to_version: str
    reason: str | None = None
    prev_receipt_hash_b64: str | None = None


# --- Tuple-based policy (MVP) ---

class AllowedTuples(BaseModel):
    tls_version: list[str] = Field(default_factory=list)
    kx_groups: list[str] = Field(default_factory=list)
    sig_algs: list[str] = Field(default_factory=list)

class TuplePolicy(BaseModel):
    policy_id: str
    allowed: AllowedTuples
    deny_on_mismatch: bool = True

    def evaluate(self, negotiated: PQCNegotiated) -> tuple[bool, str | None]:  # (allow, reason)
        # Check each dimension; if list empty treat as wildcard.
        if self.allowed.tls_version and negotiated.tls_version.replace("TLS","" ).replace("tls","" ) not in [v.replace("TLS","" ) for v in self.allowed.tls_version]:
            return False, "tls_version_mismatch"
        if self.allowed.kx_groups and negotiated.group_or_kem not in self.allowed.kx_groups:
            return False, "kx_group_mismatch"
        if self.allowed.sig_algs and negotiated.sig_alg not in self.allowed.sig_algs:
            return False, "sig_alg_mismatch"
        return True, None

