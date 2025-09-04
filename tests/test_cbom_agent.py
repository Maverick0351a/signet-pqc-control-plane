import json
import base64
from nacl import signing

from cbom_agent.builder import build_cyclonedx_cbom, canonicalize_cbom
from cbom_agent.signer import sign_cbom_document, verify_cbom_signature


def test_build_and_sign_cbom_roundtrip():
    doc = build_cyclonedx_cbom()
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["profile"] == "cdx:cbom:1.0-draft"

    sk = signing.SigningKey.generate()
    signed = sign_cbom_document(doc, sk)
    assert "signatures" in signed
    vk = sk.verify_key
    assert verify_cbom_signature(signed, vk)

    # Remove signatures and recompute canonical hash for deterministic behavior
    unsigned = {k: signed[k] for k in signed if k != "signatures"}
    canonical = canonicalize_cbom(unsigned)
    import hashlib
    h = hashlib.sha256(canonical.encode("utf-8")).digest()
    b64 = base64.b64encode(h).decode("ascii")
    assert len(b64) > 10
