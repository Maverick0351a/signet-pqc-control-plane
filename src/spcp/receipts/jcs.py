
"""RFC 8785 JSON Canonicalization Scheme (JCS) encoder.

Summary of canonical form rules (abridged to satisfy line length limits):
* UTF-8 output; object member names sorted lexicographically by codepoint.
* No insignificant whitespace.
* Strings: escape quotation mark, reverse solidus, control chars (U+0000..001F)
    using ``\\uXXXX``; do not escape solidus '/'; lowercase hex preferred.
* Numbers: no leading zeros (except 0), no plus sign, minimal exponent form,
    no trailing decimal point; remove fractional part if integral.

Limitations: Only int & float supported. Floats use a shortest round‑trip
format similar to ECMAScript/JCS guidance. NaN/Infinity are rejected.
"""
from __future__ import annotations

import math
from typing import Any


def _escape_string(s: str) -> str:
    out_chars = []
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            out_chars.append('\\"')
        elif ch == "\\":
            out_chars.append("\\\\")
        elif 0x00 <= cp <= 0x1F:
            out_chars.append(f"\\u{cp:04x}")
        else:
            out_chars.append(ch)
    return '"' + "".join(out_chars) + '"'

def _canonical_number(n: Any) -> str:
    if isinstance(n, bool):
        # bool is subclass of int; exclude
        raise TypeError("Boolean not expected in _canonical_number")
    if isinstance(n, int):
        return str(n)
    if not isinstance(n, float):
        raise TypeError("Unsupported numeric type")
    if math.isnan(n) or math.isinf(n):
        raise ValueError("NaN/Infinity not permitted in JSON per RFC 8785")
    # Zero normalization (handles -0.0)
    if n == 0:
        return "0"
    # Use repr to get a precise representation, then adjust.
    # Python's repr(float) gives 17-digit precision shortest roundtrip.
    s = repr(n)
    # Convert any exponent 'e+0X' or 'e-0X' forms to canonical minimal form.
    if "e" in s or "E" in s:
        mantissa, exp = s.lower().split("e")
        exp_val = int(exp)
        s = f"{mantissa}e{exp_val}"
    # Remove leading plus in exponent (already removed by int())
    # Remove trailing .0 if integer value and not in exponent form
    if "e" not in s:
        if "." in s:
            if float(s) == int(float(s)):
                s = str(int(float(s)))
            else:
                # Trim trailing zeros in fraction
                int_part, frac = s.split(".")
                frac = frac.rstrip("0")
                s = int_part + ("." + frac if frac else "")
    else:
        # Normalize mantissa fraction zeros
        mantissa, exp = s.split("e")
        if "." in mantissa:
            int_part, frac = mantissa.split(".")
            frac = frac.rstrip("0")
            if frac:
                mantissa = int_part + "." + frac
            else:
                mantissa = int_part
        # If mantissa is integer and length > 1 maybe switch to non-exp if small?
        # JCS chooses plain form if 1e-6 < abs(n) < 1e21.
        abs_n = abs(n)
        if 1e-6 <= abs_n < 1e21:
            # Use non-exponent decimal form
            dec_str = f"{n:.17g}"  # shortest
            if "e" in dec_str:
                # fallback keep existing
                s = mantissa + "e" + exp
            else:
                s = dec_str
        else:
            s = mantissa + "e" + exp.lstrip("+")
    return s

def _serialize(obj: Any) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int | float) and not isinstance(obj, bool):  # noqa: UP038
        return _canonical_number(obj)
    if isinstance(obj, str):
        return _escape_string(obj)
    if isinstance(obj, list):
        return "[" + ",".join(_serialize(v) for v in obj) + "]"
    if isinstance(obj, tuple):
        return "[" + ",".join(_serialize(v) for v in obj) + "]"
    if isinstance(obj, dict):
        # Keys must be strings
        items = []
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TypeError("Object keys must be strings for JSON")
            items.append((k, _serialize(v)))
        # Sort by codepoint order of key
        items.sort(key=lambda kv: kv[0])
        return "{" + ",".join(_escape_string(kv[0]) + ":" + kv[1] for kv in items) + "}"
    raise TypeError(f"Unsupported type for JCS canonicalization: {type(obj)!r}")

def jcs_canonical(obj: Any) -> bytes:
    return _serialize(obj).encode("utf-8")

__all__ = ["jcs_canonical"]
