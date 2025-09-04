from __future__ import annotations

import subprocess
import time
from typing import Any

import httpx

# Lightweight, stub-friendly runtime configuration attestation ("CBOM") helper.
# This intentionally keeps probing logic minimal and side-effect free so tests can
# monkeypatch the private probe functions without invoking real system tools.


def _run_cmd(args: list[str], timeout: float = 2.0) -> tuple[int, str, str]:
    """Execute a command safely (no shell) and capture output.

    Returns (returncode, stdout, stderr). Never raises; on failure returns (-1, "", msg).
    """
    try:
        proc = subprocess.run(  # noqa: S603 safe static args (no shell)
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError as e:  # pragma: no cover
        return -1, "", f"not found: {e}"
    except subprocess.TimeoutExpired:  # pragma: no cover
        return -1, "", "timeout"
    except Exception as e:  # pragma: no cover (defensive)
        return -1, "", f"error: {e}"  # keep it opaque but recorded


def _probe_openssl_version() -> str | None:
    rc, out, _ = _run_cmd(["openssl", "version"])
    if rc != 0 or not out:
        return None
    # Example: OpenSSL 3.2.1 30 Jan 2024
    return out.split()[1] if len(out.split()) >= 2 else out


def _list_available_groups() -> list[str]:
    """Return a placeholder list of PQ/TLS groups.

    TODO: Extend to actually probe supported key exchange & KEM groups once
    running in an environment with hybrid/PQC OpenSSL builds.
    """
    return ["x25519", "p256_kyber768", "x25519_kyber768"]


def collect_cbom(api_url: str, node_id: str, *, _post_func=None) -> dict[str, Any]:
    """Collect a minimal cryptographic BOM (CBOM) and POST as `pqc.cbom` event.

    Parameters
    ----------
    api_url : str
        Base URL of the control plane API (no trailing slash), e.g. http://localhost:8000
    node_id : str
        Logical identifier of the node / proxy performing the attestation.

    Returns
    -------
    dict
        Signed receipt returned by the control plane.
    """
    openssl_version = _probe_openssl_version()
    groups = _list_available_groups()
    body = {
        "kind": "pqc.cbom",
        "ts_ms": int(time.time() * 1000),
        "node_id": node_id,
        "openssl_version": openssl_version,
        "entries": [
            {
                "provider": "openssl",
                "version": openssl_version or "unknown",
                "algorithms": {"groups": groups},
            }
        ],
    }
    post = _post_func or httpx.post
    r = post(f"{api_url}/events", json=body, timeout=5.0)
    r.raise_for_status()
    return r.json()


__all__ = ["collect_cbom"]
