from answerproof.canonical import canonical_str, canonicalize


def test_key_order_is_normalized():
    a = canonicalize({"b": 1, "a": 2})
    b = canonicalize({"a": 2, "b": 1})
    assert a == b
    assert a == b'{"a":2,"b":1}'


def test_no_insignificant_whitespace():
    assert canonicalize({"x": [1, 2, 3]}) == b'{"x":[1,2,3]}'


def test_nested_objects_sorted_recursively():
    out = canonical_str({"z": {"d": 1, "c": 2}, "a": 1})
    assert out == '{"a":1,"z":{"c":2,"d":1}}'


def test_unicode_preserved():
    out = canonical_str({"name": "café"})
    assert out == '{"name":"café"}'


def test_stable_across_calls():
    obj = {"sources": [{"id": "s1", "score": 1}], "query": "q"}
    assert canonicalize(obj) == canonicalize(obj)
