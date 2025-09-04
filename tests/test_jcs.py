from spcp.receipts.jcs import jcs_canonical


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
    ]
    for n, expect in cases:
        assert jcs_canonical(n) == expect


def test_array_and_nested():
    obj = {"z": [1, 2, 3], "a": {"x": 5, "b": "str"}}
    # Keys in outer object: 'a' < 'z'
    out = jcs_canonical(obj)
    assert out.startswith(b'{"a":')
    assert b',"z":[1,2,3]}' in out
