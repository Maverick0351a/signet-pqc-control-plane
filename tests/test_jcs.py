from spcp.receipts.jcs import jcs_canonical
import math
import random


def test_object_key_ordering():
    obj = {"b": 1, "a": 2, "ä": 3}
    # Codepoint order: 'a'(0x61) < 'b'(0x62) < 'ä'(0xe4)
    assert jcs_canonical(obj) == '{"a":2,"b":1,"ä":3}'.encode()


def test_string_escaping_control_chars():
    original = 'line\nTAB\tQUOTE"BS\\'
    obj = {"k": original}
    out = jcs_canonical(obj)
    # Expected JSON string components
    # Represent expected bytes via decode of escaped string for clarity
    expected = b'{"k":"line\\u000aTAB\\u0009QUOTE\\"BS\\\\"}'
    assert out == expected


def test_number_canonical_forms():
    cases = [
        (0, b"0"),
        (1, b"1"),
        (-1, b"-1"),
        (1.0, b"1"),  # drop .0
        (1.50, b"1.5"),
        (1.2500, b"1.25"),
        (1000000.0, b"1000000"),
    ]
    for n, expect in cases:
        assert jcs_canonical(n) == expect


def test_array_and_nested():
    obj = {"z": [1, 2, 3], "a": {"x": 5, "b": "str"}}
    # Keys in outer object: 'a' < 'z'
    out = jcs_canonical(obj)
    assert out.startswith(b'{"a":')
    assert b',"z":[1,2,3]}' in out


def test_stability_across_runs():
    base = {f"k{i}": i for i in range(60)}
    items = list(base.items())
    random.shuffle(items)
    obj = {k: v for k, v in items}
    first = jcs_canonical(obj)
    for _ in range(20):
        assert jcs_canonical(obj) == first


def test_reject_nan_and_infinity():
    for bad in [math.nan, math.inf, -math.inf]:
        try:
            jcs_canonical({"x": bad})
        except ValueError:
            continue
        else:  # pragma: no cover
            raise AssertionError("Expected ValueError for NaN/Infinity")
