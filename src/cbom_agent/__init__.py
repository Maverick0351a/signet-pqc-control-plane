"""cbom_agent package: collect, build, sign, emit, verify CycloneDX-profile CBOMs.

This agent is intentionally decoupled from the control plane so that runtime collection
can occur out-of-process and be transported (e.g. via HTTP POST) to the control plane
for attested receipt minting.
"""
from .builder import build_cyclonedx_cbom  # noqa: F401
from .signer import sign_cbom_document, verify_cbom_signature  # noqa: F401
