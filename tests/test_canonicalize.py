"""Unit tests for RFC 8785 canonicalization behaviors the corpus relies on."""

import math

import pytest

from ario_proof.canonicalize import canonical_json, normalize_floats


def test_sorts_keys_lexicographically_at_every_level() -> None:
    obj = {"b": {"z": 1, "a": 2}, "a": [{"y": 1, "x": 2}]}
    assert canonical_json(obj) == b'{"a":[{"x":2,"y":1}],"b":{"a":2,"z":1}}'


def test_sorts_by_utf16_code_units() -> None:
    # RFC 8785 §3.2.3 sorts on UTF-16 code units. "é" (é, one unit 0x00E9)
    # sorts before "😀" (emoji surrogate pair, first unit 0xD83D).
    obj = {"\U0001f600": 1, "é": 2}
    assert canonical_json(obj) == '{"é":2,"😀":1}'.encode("utf-8")


def test_emits_utf8_not_ascii_escapes() -> None:
    assert canonical_json({"k": "héllo"}) == '{"k":"héllo"}'.encode("utf-8")


def test_no_whitespace_and_minimal_escapes() -> None:
    assert canonical_json({"a": 'quote " and \\'}) == b'{"a":"quote \\" and \\\\"}'


def test_number_serialization_is_ecma262() -> None:
    assert canonical_json([1, 1.0, 0.5, 1e21]) == b"[1,1,0.5,1e+21]"


def test_rejects_non_finite_floats() -> None:
    with pytest.raises(Exception):
        canonical_json({"a": math.inf})


def test_normalize_floats_rounds_recursively() -> None:
    obj = {"m": [0.1234567, {"n": 2.7182818}], "t": (1.9999999,)}
    assert normalize_floats(obj) == {"m": [0.123457, {"n": 2.718282}], "t": [2.0]}


def test_normalize_floats_leaves_ints_and_strings() -> None:
    assert normalize_floats({"a": 7, "b": "0.1234567"}) == {"a": 7, "b": "0.1234567"}
