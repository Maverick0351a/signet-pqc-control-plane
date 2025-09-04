from __future__ import annotations

import base64


def parse_pch_authorization(header_value: str) -> dict[str, str]:
    """Parse an Authorization: PCH header into a dict.

    Fields (order not strict): keyId, alg, created, challenge, evidence, signature.
    Returns empty dict on parse failure or non-PCH scheme.
    """
    if not header_value:
        return {}
    parts = header_value.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "pch":
        return {}
    params: dict[str, str] = {}
    for seg in parts[1].split(","):
        if "=" not in seg:
            continue
        k, v = seg.split("=", 1)
        params[k.strip()] = v.strip().strip('"')
    return params


def get_channel_binding(request) -> tuple[str | None, bytes | None, str | None]:
    """Decode channel binding header (tls-session-id or tls-exporter)."""
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
