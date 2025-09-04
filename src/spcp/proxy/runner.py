
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import httpx

CBOM_OUTPUT_DIR = Path(os.getenv("CBOM_OUTPUT_DIR", "/var/lib/signet/cbom"))
CBOM_INTERVAL_SECONDS = int(os.getenv("CBOM_INTERVAL_SECONDS", "900"))  # default 15m
TLS_SNAPSHOT_PATH = Path(os.getenv("TLS_SNAPSHOT_PATH", "/var/run/proxy_tls.json"))

# State for change-detection gating (avoid reposting identical CBOMs)
_last_cbom_emit: float = 0.0
_last_cbom_digest: str | None = None


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


def write_tls_snapshot(enabled_ciphers: list[str], enabled_groups: list[str]):
    TLS_SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    snapshot = {
        "enabled_ciphers": enabled_ciphers,
        "enabled_groups": enabled_groups,
        "ts": int(time.time()),
    }
    TLS_SNAPSHOT_PATH.write_text(json.dumps(snapshot, indent=2))
    return snapshot


def _run_cbom_cycle(api_url: str):  # pragma: no cover - integration path
    global _last_cbom_emit, _last_cbom_digest
    CBOM_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(["cbom-agent", "collect"], capture_output=True, text=True, timeout=20)
        if proc.returncode != 0 or not proc.stdout.strip():
            return
        # Parse and canonicalize for digest
        doc = json.loads(proc.stdout)
        canonical = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
        digest = base64.b64encode(hashlib.sha256(canonical).digest()).decode()
        if digest == _last_cbom_digest:
            return  # unchanged -> skip write/post
        ts = int(time.time())
        out_path = CBOM_OUTPUT_DIR / f"cbom.{ts}.json"
        out_path.write_text(proc.stdout)
        try:
            httpx.post(f"{api_url}/cbom/ingest", json=doc, timeout=10)
            _last_cbom_emit = time.time()
            _last_cbom_digest = digest
        except Exception:  # noqa: S112
            pass
    except Exception:  # noqa: S112
        pass


def start_cbom_scheduler(api_url: str):  # pragma: no cover
    def loop():
        while True:
            _run_cbom_cycle(api_url)
            time.sleep(CBOM_INTERVAL_SECONDS)
    t = threading.Thread(target=loop, name="cbom-agent-loop", daemon=True)
    t.start()
    return t


__all__ = [
    "emit_enforcement_event",
    "from_handshake",
    "write_tls_snapshot",
    "start_cbom_scheduler",
    "proxy_config_fingerprint",
]


def proxy_config_fingerprint(
    nginx_conf_path: str = "/etc/nginx/nginx.conf",
    snapshot_path: str | None = None,
) -> dict[str, Any]:  # pragma: no cover - logic tested separately
    """Compute a composite fingerprint of runtime TLS proxy configuration.

    Steps:
      1. Load TLS snapshot JSON (enabled ciphers/groups) written by proxy.
      2. Extract canonical server { ... } block from nginx.conf (first occurrence).
      3. Canonicalize both (sorted JSON keys for snapshot; trimmed lines for server block).
      4. Produce individual hashes and a combined hash.

    Returns dict with snapshot_hash_b64, server_block_hash_b64, fingerprint_b64.
    On any failure, missing elements are omitted but function still returns structure.
    """
    snap_path = Path(snapshot_path) if snapshot_path else TLS_SNAPSHOT_PATH
    snapshot_obj: Any = {}
    try:
        if snap_path.exists():
            snapshot_obj = json.loads(snap_path.read_text())
    except Exception:  # noqa: S112
        snapshot_obj = {}
    # Canonical snapshot serialization
    try:
        snapshot_canon = json.dumps(snapshot_obj, sort_keys=True, separators=(",", ":")).encode()
    except Exception:
        snapshot_canon = b"{}"
    snapshot_hash_b64 = sha256_b64(snapshot_canon)

    server_block_text = ""
    try:
        if Path(nginx_conf_path).exists():
            lines = Path(nginx_conf_path).read_text().splitlines()
            capturing = False
            brace_depth = 0
            collected: list[str] = []
            for line in lines:
                stripped = line.strip()
                if not capturing and stripped.startswith("server") and "{" in stripped:
                    capturing = True
                    brace_depth = stripped.count("{") - stripped.count("}")
                    collected.append(stripped)
                    continue
                if capturing:
                    brace_depth += stripped.count("{") - stripped.count("}")
                    collected.append(stripped)
                    if brace_depth <= 0:
                        break
            # Filter comments and blank lines
            filtered = [line for line in collected if line and not line.startswith("#")] if collected else []
            server_block_text = "\n".join(filtered).strip()
    except Exception:  # noqa: S112
        server_block_text = ""
    server_block_hash_b64 = sha256_b64(server_block_text.encode()) if server_block_text else sha256_b64(b"")

    combined = snapshot_hash_b64.encode() + b"." + server_block_hash_b64.encode()
    fingerprint_b64 = sha256_b64(combined)
    return {
        "snapshot_path": str(snap_path),
        "nginx_conf_path": nginx_conf_path,
        "snapshot_hash_b64": snapshot_hash_b64,
        "server_block_hash_b64": server_block_hash_b64,
        "fingerprint_b64": fingerprint_b64,
    }
