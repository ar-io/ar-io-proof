"""Regression: the cross-kernel canonicalization deep-nesting divergence.

An unbounded recursive canonicalizer overflows at a runtime-specific depth, so
the same deeply-nested bytes could verify on the TS kernel (large V8 stack) while
this Python kernel hits CPython's ~1000-frame recursion limit -- a verdict that
depends on which verifier you run, on a depth the byte-supplier controls. Both
kernels now bound canonicalization nesting to ``MAX_CANONICAL_DEPTH`` and reject
a deeper input as ``malformed`` (envelope-spec s2 invariant 7). The shared corpus
vector ``deep-nesting.json`` MUST verify as ``malformed`` here AND in the TS
kernel (ts/test/canonicalization-depth.test.ts) -- same bytes, same verdict.
"""

import json
import pathlib
import sys

import pytest

from ario_proof.canonicalize import (
    MAX_CANONICAL_DEPTH,
    CanonicalDepthError,
    canonical_json,
    exceeds_depth,
)
from ario_proof.evidence import verify_evidence_bundle

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_DEEP = _ROOT / "test-vectors/evidence-export/negatives/deep-nesting.json"

# Comfortably past CPython's default 1000-frame recursion limit (so a *recursive*
# depth-walk would raise RecursionError here) but shallow enough to build and
# deallocate safely. This is the value that proves the guard is iterative.
_PAST_RECURSION_LIMIT = sys.getrecursionlimit() + 1000


def _nest(levels: int) -> dict:
    """A dict nested ``levels`` wrappers deep around a scalar leaf; the deepest
    container sits at depth ``levels + 1``."""
    node: dict = {"end": 0}
    for _ in range(levels):
        node = {"nest": node}
    return node


def test_deep_corpus_bundle_is_malformed() -> None:
    bundle = json.loads(_DEEP.read_text())
    result = verify_evidence_bundle(bundle)
    assert result.status == "malformed"
    assert any("nesting exceeds" in e for e in result.errors)


def test_exceeds_depth_exact_boundary() -> None:
    # _nest(k) puts the deepest container at depth k+1: k = MAX-1 → deepest MAX
    # (allowed); k = MAX → deepest MAX+1 (over).
    assert exceeds_depth(_nest(MAX_CANONICAL_DEPTH - 1), MAX_CANONICAL_DEPTH) is False
    assert exceeds_depth(_nest(MAX_CANONICAL_DEPTH), MAX_CANONICAL_DEPTH) is True


def test_exceeds_depth_past_recursion_limit_no_recursionerror() -> None:
    # A recursive depth-walk would raise RecursionError at ~1000 frames; the
    # iterative guard returns cleanly after short-circuiting at the bound.
    assert exceeds_depth(_nest(_PAST_RECURSION_LIMIT), MAX_CANONICAL_DEPTH) is True


def test_canonical_json_raises_on_over_deep_input() -> None:
    with pytest.raises(CanonicalDepthError):
        canonical_json(_nest(_PAST_RECURSION_LIMIT))


def test_canonical_json_still_serializes_shallow() -> None:
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
