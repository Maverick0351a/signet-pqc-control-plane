from __future__ import annotations

import base64
from typing import Any, Dict, Tuple, Optional


def parse_pch_authorization(header_value: str) -> Dict[str, str]:
    """Parse an Authorization: PCH header into a dict of parameters.

    Expected format:
        PCH keyId="<b64pub>", alg="ed25519", created="<epoch>", challenge="<nonce>", evidence="<b64>", signature="<b64>"

    Returns empty dict if scheme isn't PCH or parse fails.
    """
    if not header_value:
        return {}
    parts = header_value.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "pch":
        return {}
    params: Dict[str, str] = {}
    for seg in parts[1].split(","):
        if "=" not in seg:
            continue
        k, v = seg.split("=", 1)
        params[k.strip()] = v.strip().strip('"')
    return params


def get_channel_binding(request) -> Tuple[Optional[str], Optional[bytes], Optional[str]]:
    """Extract and decode channel binding from headers.

    Looks at 'PCH-Channel-Binding'. Format:
        tls-session-id:<b64> or tls-exporter:<b64>

    Returns (kind, raw_bytes, original_header_value) or (None, None, None).
    """
    hdr = request.headers.get("pch-channel-binding")
    if not hdr:
        return None, None, None
    if ":" not in hdr:
        return None, None, hdr
    kind, b64v = hdr.split(":", 1)
    kind = kind.strip().lower()
    try:
        raw = base64.b64decode(b64v.strip() + "==")
    except Exception:
        raw = None
    return kind, raw, hdr


__all__ = ["parse_pch_authorization", "get_channel_binding"]
