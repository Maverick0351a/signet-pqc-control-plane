import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .collectors.linux_openssl import collect_all


def _tool_descriptor() -> Dict[str, Any]:
    return {
        "vendor": "signet",
        "name": "cbom_agent",
        "version": "0.1.0",
    }


def build_cyclonedx_cbom(extra_components: Optional[List[Dict[str, Any]]] = None,
                          extra_services: Optional[List[Dict[str, Any]]] = None,
                          runtime_snapshot: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build a minimal CycloneDX CBOM profile document (draft).

    This intentionally focuses on crypto-relevant runtime artifacts rather than software deps.
    """
    snapshot = runtime_snapshot or collect_all()
    components: List[Dict[str, Any]] = []

    # Represent OpenSSL library if present
    openssl = snapshot.get("openssl", {})
    if openssl.get("present") and openssl.get("version"):
        components.append({
            "type": "library",
            "name": "openssl",
            "version": openssl.get("version"),
            "properties": [
                {"name": "signet:openssl:binary", "value": openssl.get("binary")},
                {"name": "signet:openssl:raw", "value": openssl.get("raw")},
            ],
        })

    # Represent TLS terminator/proxy runtime
    runtime = snapshot.get("runtime", {})
    terminator = runtime.get("terminator", {})
    if terminator:
        components.append({
            "type": "application",
            "name": terminator.get("kind", "terminator"),
            "properties": [
                {"name": "signet:terminator:integrated", "value": str(terminator.get("integrated"))},
            ],
        })

    if extra_components:
        components.extend(extra_components)

    services: List[Dict[str, Any]] = []
    if extra_services:
        services.extend(extra_services)

    doc: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "profile": "cdx:cbom:1.0-draft",
        "cbom": {  # schema evolution container
            "profile": "cdx:cbom:1.0-draft",
            "schemaVersion": 1,
        },
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"components": [_tool_descriptor()]}],
            "properties": [
                {"name": "signet:platform:os", "value": snapshot.get("platform", {}).get("os")},
                {"name": "signet:platform:machine", "value": snapshot.get("platform", {}).get("machine")},
                {"name": "signet:python:version", "value": snapshot.get("platform", {}).get("python_version")},
                {"name": "cbom.profile", "value": "cdx:cbom:1.0-draft"},
                {"name": "cbom.schemaVersion", "value": "1"},
            ],
        },
        "components": components,
    }

    if services:
        doc["services"] = services

    return doc


def canonicalize_cbom(doc: Dict[str, Any]) -> str:
    # For now, rely on RFC8785 canonical form using sorted keys (Python's json.dumps with sort_keys + separators)
    # A future improvement could plug into a dedicated JCS implementation reused from receipts.
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
