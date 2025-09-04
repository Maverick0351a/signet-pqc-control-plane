
from __future__ import annotations

import base64
import hashlib
import time
from typing import Any

import httpx


def sha256_b64(b: bytes) -> str:
    return base64.b64encode(hashlib.sha256(b).digest()).decode()

def emit_enforcement_event(api_url: str, policy_version: str, policy_hash_b64: str,
                           negotiated: dict[str, Any], allow: bool, reason: str | None = None):
    """Low-level helper to send a pre-built enforcement receipt.

    Parameters
    ----------
    api_url : str
        Base URL of control plane (no trailing slash), e.g. http://localhost:8000
    policy_version : str
        Current policy version string.
    policy_hash_b64 : str
        Base64 hash (e.g. sha256) of policy document for audit linking.
    negotiated : dict
        Dict containing negotiated TLS/PQC parameters.
    allow : bool
        Decision outcome.
    reason : str | None
        Optional human-readable reason.
    """
    body = {
        "kind": "pqc.enforcement",
        "ts_ms": int(time.time()*1000),
        "policy_version": policy_version,
        "policy_hash_b64": policy_hash_b64,
        "negotiated": negotiated,
        "decision": {"allow": allow, "reason": reason},
    }
    r = httpx.post(f"{api_url}/events", json=body, timeout=5.0)
    r.raise_for_status()
    return r.json()


def from_handshake(api_url: str, *, policy_version: str, policy_hash_b64: str,
                   tls_version: str, cipher: str, group_or_kem: str, sig_alg: str,
                   sni: str | None, peer_ip: str, allow: bool, reason: str | None = None):
    """Build and emit a `pqc.enforcement` receipt from raw handshake metadata.

    This is a convenience layer for proxies or tap scripts parsing TLS handshakes.

    Example
    -------
    >>> from spcp.proxy.runner import from_handshake
    >>> from_handshake(
    ...     api_url="http://localhost:8000",
    ...     policy_version="v3",
    ...     policy_hash_b64="3q2+7w==",
    ...     tls_version="TLS1.3",
    ...     cipher="TLS_AES_128_GCM_SHA256",
    ...     group_or_kem="x25519_kyber768",
    ...     sig_alg="ed25519",
    ...     sni="example.com",
    ...     peer_ip="203.0.113.10",
    ...     allow=True,
    ...     reason=None,
    ... )
    {... signed receipt ...}

    Parameters mirror the negotiated section fields plus decision outcome.
    """
    negotiated = {
        "tls_version": tls_version,
        "cipher": cipher,
        "group_or_kem": group_or_kem,
        "sig_alg": sig_alg,
        "sni": sni,
        "peer_ip": peer_ip,
    }
    return emit_enforcement_event(
        api_url=api_url,
        policy_version=policy_version,
        policy_hash_b64=policy_hash_b64,
        negotiated=negotiated,
        allow=allow,
        reason=reason,
    )
