import json
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

OPENSSL_BIN_CANDIDATES = ["openssl", "/usr/bin/openssl", "/usr/local/bin/openssl"]


def _which_openssl() -> str | None:
    for cand in OPENSSL_BIN_CANDIDATES:
        path = shutil.which(cand) if cand == "openssl" else cand
        if path and Path(path).exists():
            return path
    return None


def collect_openssl_version(openssl_bin: str | None = None) -> Dict[str, Any]:
    bin_path = openssl_bin or _which_openssl()
    if not bin_path:
        return {"present": False}
    try:
        proc = subprocess.run([bin_path, "version"], capture_output=True, text=True, timeout=3)
        ver = proc.stdout.strip()
        # Extract version core (e.g., OpenSSL 3.0.13 30 Jan 2024)
        m = re.match(r"OpenSSL\\s+([0-9]+\.[0-9]+\.[0-9]+)(.*)", ver)
        version = m.group(1) if m else ver
        return {"present": True, "binary": bin_path, "raw": ver, "version": version}
    except Exception as e:  # pragma: no cover - defensive
        return {"present": True, "binary": bin_path, "error": str(e)}


def collect_platform() -> Dict[str, Any]:
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
    }


def collect_tls_runtime() -> Dict[str, Any]:
    # Placeholder for future: query running proxy / terminator if accessible.
    return {"terminator": {"kind": "nginx-oqs", "integrated": True}}


def collect_all() -> Dict[str, Any]:
    return {
        "platform": collect_platform(),
        "openssl": collect_openssl_version(),
        "runtime": collect_tls_runtime(),
    }


def main() -> None:  # pragma: no cover - CLI utility
    data = collect_all()
    print(json.dumps(data, indent=2))

if __name__ == "__main__":  # pragma: no cover
    main()
