
import json
from typing import Any

def jcs_canonical(obj: Any) -> bytes:
    """Deterministic JSON encoding with sorted keys and minimal separators.

    NOTE: This is a pragmatic stand-in. For strict RFC 8785 JCS compliance
    (esp. number formatting), replace with a proven JCS implementation.
    We avoid floats in receipts to keep behavior stable.
    """
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')
