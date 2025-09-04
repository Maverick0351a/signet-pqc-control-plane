from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
import time
from collections import OrderedDict
from typing import Any

from ..settings import settings

SIG_INPUT_RE = re.compile(
    r"^(?P<keyid>[^=]+)=\((?P<fields>[^)]*)\);created=(?P<created>\d+)"
    r"(?:;nonce=(?P<nonce>[^;]+))?"
    r"(?:;alg=(?P<alg>[^;]+))?$"
)


class NonceCache:
    def __init__(self, max_size: int, ttl: int):
        self.max_size = max_size
        self.ttl = ttl
        self._data: OrderedDict[str, float] = OrderedDict()

    def add(self, nonce: str) -> None:
        now = time.time()
        self._prune(now)
        self._data[nonce] = now
        self._data.move_to_end(nonce)
        if len(self._data) > self.max_size:
            self._data.popitem(last=False)

    def seen(self, nonce: str) -> bool:
        now = time.time()
        self._prune(now)
        return nonce in self._data

    def _prune(self, now: float) -> None:
        expire_before = now - self.ttl
        for k, ts in list(self._data.items()):
            if ts < expire_before:
                self._data.pop(k, None)


_nonce_cache = NonceCache(settings.pch_nonce_cache_size, settings.pch_nonce_ttl_seconds)


def parse_signature_input(header: str) -> dict[str, Any] | None:
    m = SIG_INPUT_RE.match(header.strip())
    if not m:
        return None
    fields_raw = m.group("fields") or ""
    field_list = [f.strip() for f in fields_raw.split(" ") if f.strip()]
    return {
        "key_id": m.group("keyid"),
        "fields": field_list,
        "created": int(m.group("created")),
        "nonce": m.group("nonce"),
        "alg": (m.group("alg") or "ed25519").lower(),
    }


def _build_sig_base(sig_input: dict[str, Any], request: Any) -> bytes:
    lines: list[str] = []
    for f in sig_input["fields"]:
        if f == "@method":
            lines.append(f"@method: {request.method.lower()}")
        elif f == "@path":
            # Assume raw path without query for MVP
            path = request.url.path
            lines.append(f"@path: {path}")
        elif f == "@authority":
            host = request.headers.get("host", "")
            lines.append(f"@authority: {host}")
        else:
            v = request.headers.get(f)
            if v is None:
                lines.append(f"{f}: ")
            else:
                lines.append(f"{f}: {v}")
    fields_joined = " ".join(sig_input["fields"])
    lines.append(
        f"@signature-params: {sig_input['key_id']}=({fields_joined});created={sig_input['created']}"
    )
    return "\n".join(lines).encode()


def verify_pch(request) -> dict[str, Any]:  # pragma: no cover - exercised indirectly
    if not settings.pch_verify_only:
        return {"present": False}
    sig_input_header = request.headers.get("signature-input")
    sig_header = request.headers.get("signature")
    if not sig_input_header or not sig_header:
        return {"present": False}
    parsed = parse_signature_input(sig_input_header)
    if not parsed:
        return {"present": True, "verify": "fail", "reason": "parse_error"}
    now = int(time.time())
    if abs(now - parsed["created"]) > settings.pch_max_age_seconds:
        return {"present": True, "verify": "fail", "reason": "stale"}
    if parsed.get("nonce"):
        if _nonce_cache.seen(parsed["nonce"]):
            # Replay (informational only)
            replay = True
        else:
            _nonce_cache.add(parsed["nonce"])
            replay = False
    else:
        replay = False
    alg = parsed["alg"]
    sig_b64 = sig_header.strip()
    try:
        sig = base64.b64decode(sig_b64)
    except Exception:
        return {"present": True, "verify": "fail", "alg": alg, "reason": "bad_b64"}
    base = _build_sig_base(parsed, request)
    ok = False
    if alg == "hmac-sha256":
        # Demo: derive shared secret from env or default (not secure, verify-only)
        secret = (settings.__dict__.get("pch_demo_hmac_secret") or "demo-secret").encode()
        digest = hmac.new(secret, base, hashlib.sha256).digest()
        ok = hmac.compare_digest(digest, sig)
    elif alg == "ed25519":
        try:
            from nacl.signing import VerifyKey
            # In verify-only mode we don't know real key; treat key_id as base64 vk if decodable
            try:
                vk_bytes = base64.b64decode(parsed["key_id"], validate=True)
            except Exception:
                return {"present": True, "verify": "fail", "alg": alg, "reason": "bad_key_id"}
            vk = VerifyKey(vk_bytes)
            vk.verify(base, sig)
            ok = True
        except Exception as e:  # noqa: S112
            logging.debug("Ed25519 verify failed: %s", e)
            ok = False
    else:
        return {"present": True, "verify": "fail", "reason": "unsupported_alg", "alg": alg}
    return {
        "present": True,
        "verify": "ok" if ok else "fail",
        "alg": alg,
        "key_id": parsed.get("key_id"),
        "reason": "replay" if ok and replay else (None if ok else "verify_failed"),
    }
