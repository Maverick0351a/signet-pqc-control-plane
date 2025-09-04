import base64
import datetime as dt
import json

from nacl import signing
from nacl.encoding import RawEncoder

RFC3339_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def _now_rfc3339() -> str:
    # Truncate microseconds to milliseconds for shorter string while valid RFC3339 fraction (3-6 digits allowed)
    now = dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)
    return now.isoformat().replace("+00:00", "Z")


def build_pch_evidence(policy_id: str, merkle_root_b64: str, cbom_hash_b64: str, tree_size: int) -> bytes:
    """Build minimal PCH evidence object and return canonicalized bytes.

    Canonicalization (JCS-like minimal subset):
      - Sort object keys lexicographically.
      - Use separators (',', ':') without spaces.
      - Ensure deterministic ordering of inner attestation object.
    """
    evidence = {
        "attestation": {
            "cbom_hash_b64": cbom_hash_b64,
            "mode": "software",
        },
        "merkle_root_b64": merkle_root_b64,
        "policy_id": policy_id,
        "time": _now_rfc3339(),
        "tree_size": tree_size,
        "type": "pch.sth",
    }
    # Deterministic dump: sort keys at all levels
    # For inner dict(s), json.dumps with sort_keys handles recursively.
    return json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _canonical_header_name(name: str) -> str:
    return name.lower()


def _add_content_digest(prepared_request) -> str | None:
    body = prepared_request.body
    if not body:
        return None
    if isinstance(body, str):
        body_bytes = body.encode("utf-8")
    else:
        body_bytes = body
    # For simplicity, use sha-256 as content digest algorithm (matches server expectation if any)
    import hashlib

    digest = hashlib.sha256(body_bytes).digest()
    b64 = base64.b64encode(digest).decode()
    prepared_request.headers["Content-Digest"] = f"sha-256=:{b64}:"
    return prepared_request.headers["Content-Digest"]


def sign_http_request(
    prepared_request,
    key_id: str,
    ed25519_private_key_pem: str,
    pch_challenge_b64: str,
    tls_session_id_bytes: bytes,
    evidence_bytes: bytes,
):
    """Attach PCH headers and HTTP Message Signature to an httpx PreparedRequest.

    Headers added:
      PCH-Challenge: :<pch_challenge_b64>:
      PCH-Channel-Binding: tls-session-id=:<base64(tls_session_id_bytes)>:
      PCH-Evidence: :<base64(evidence_bytes)>:
      Content-Digest: (if body present)

    Signature covers: @method, @path, @authority, content-digest (if present), pch-challenge, pch-channel-binding, pch-evidence
    """
    # Set PCH headers
    prepared_request.headers["PCH-Challenge"] = f":{pch_challenge_b64}:"
    prepared_request.headers["PCH-Channel-Binding"] = (
        "tls-session-id=:" + base64.b64encode(tls_session_id_bytes).decode() + ":"
    )
    prepared_request.headers["PCH-Evidence"] = ":" + base64.b64encode(evidence_bytes).decode() + ":"

    content_digest = _add_content_digest(prepared_request)

    # Build signature base per draft-cavage / HTTP Message Signatures subset used server-side.
    method = prepared_request.method.upper()
    # httpx PreparedRequest URL components
    url = prepared_request.url
    path_with_query = url.raw_path.decode()
    authority = url.netloc.decode() if isinstance(url.netloc, bytes) else url.netloc

    covered_components = ["@method", "@path", "@authority"]
    if content_digest:
        covered_components.append("content-digest")
    covered_components.extend(["pch-challenge", "pch-channel-binding", "pch-evidence"])

    def _component_value(name: str) -> str:
        if name == "@method":
            return method
        if name == "@path":
            return path_with_query
        if name == "@authority":
            return authority
        # header lookup
        return prepared_request.headers[_canonical_header_name(name)]

    lines = []
    for comp in covered_components:
        if comp.startswith("@"):
            value = _component_value(comp)
            lines.append(f"{comp}: {value}")
        else:
            header_value = _component_value(comp)
            lines.append(f"{comp}: {header_value}")

    # Build signature-input value (avoid nested f-string quoting not available in py310)
    created_ts = int(dt.datetime.utcnow().timestamp())
    components_str = " ".join(f'"{c}"' for c in covered_components)
    signature_input_value = f"sig1=({components_str});created={created_ts}"

    signature_base = "\n".join(lines) + f"\n{signature_input_value}"

    # Load Ed25519 private key (expecting raw 32-byte seed inside PEM '-----BEGIN PRIVATE KEY-----' PKCS8 or raw base64 seed)
    # Simple approach: try to extract base64 payload lines and decode; if 32 bytes use as seed.
    key_material = ed25519_private_key_pem.strip()
    if "BEGIN" in key_material:
        # PEM format
    pem_lines = [line for line in key_material.splitlines() if not line.startswith("---")]  # drop headers
    b64_join = "".join(pem_lines)
        try:
            raw = base64.b64decode(b64_join)
            # PKCS8 Ed25519 private key structure: last 32 bytes typically the seed
            seed = raw[-32:]
        except Exception as e:  # pragma: no cover
            raise ValueError("Invalid PEM private key") from e
    else:
        raw = base64.b64decode(key_material)
        seed = raw
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes after decoding")

    signer = signing.SigningKey(seed)
    sig = signer.sign(signature_base.encode(), encoder=RawEncoder).signature
    sig_b64 = base64.b64encode(sig).decode()

    prepared_request.headers[
        "Signature-Input"
    ] = signature_input_value  # sig1=("@method" "@path" ...);created=timestamp
    prepared_request.headers["Signature"] = f"sig1=:{sig_b64}:"  # cavage-style wrapper
    prepared_request.headers["Authorization"] = f"PCH keyId={key_id}"  # existing server expects this style
    return prepared_request
