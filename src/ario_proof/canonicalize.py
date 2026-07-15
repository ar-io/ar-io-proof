"""RFC 8785 (JSON Canonicalization Scheme) serialization.

Strict JCS via the reference ``jcs`` package — deterministic UTF-8 bytes that
any RFC 8785 implementation in any language reproduces. Numbers serialize per
ECMA-262 ``Number.prototype.toString``; floats are NOT pre-rounded, so callers
hashing values that may differ at floating-point precision across
measurements apply :func:`normalize_floats` first (the producer's choice,
never the verifier's).
"""

from typing import Any

import jcs

__all__ = [
    "canonical_json",
    "normalize_floats",
    "MAX_CANONICAL_DEPTH",
    "CanonicalDepthError",
    "exceeds_depth",
]

# Maximum JSON container-nesting depth a verifier will canonicalize. Inputs
# nested deeper are rejected BEFORE canonicalization runs. This is a NORMATIVE
# cross-kernel invariant (envelope-spec §2 shared-invariant 7): the same fixed
# constant in every kernel. Without it, a deeply-nested body one kernel
# canonicalizes on its large native stack while this one hits CPython's default
# ~1000-frame recursion limit yields a split verdict — the same bytes reported
# ``verified``/``failed`` by one kernel and ``RecursionError``/``malformed`` by
# another, on a depth the producer of the bytes fully controls. 128 is >10x any
# legitimate evidence structure (which nests <15) and safely under CPython's
# recursion limit, with headroom for the ``jcs`` package's own frames-per-level.
# Mirrors the TS kernel's ``MAX_CANONICAL_DEPTH``.
MAX_CANONICAL_DEPTH = 128


class CanonicalDepthError(ValueError):
    """Input nests JSON containers deeper than :data:`MAX_CANONICAL_DEPTH`.

    A malformed-input condition (like unparseable hex or an unimportable key):
    the callers bucket it as ``malformed``, not as a failed verification.
    """


def exceeds_depth(value: Any, max_depth: int) -> bool:
    """Test whether ``value`` nests JSON containers deeper than ``max_depth``
    levels; short-circuits on the first over-deep path.

    Deliberately **iterative, not recursive**: this guard runs on already-parsed,
    possibly-hostile input, so it must never itself raise ``RecursionError`` — it
    walks an explicit heap stack instead. The root container is depth 1; each
    nested list/dict is one deeper; scalars have no children and never increase
    depth.
    """
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if not isinstance(node, (dict, list)):
            continue  # scalar — always fine
        if depth > max_depth:
            return True  # a container nested past the bound
        children = node.values() if isinstance(node, dict) else node
        for child in children:
            stack.append((child, depth + 1))
    return False


def canonical_json(obj: Any) -> bytes:
    """Serialize ``obj`` to RFC 8785 JCS-canonical UTF-8 bytes.

    Nesting is bounded FIRST (:data:`MAX_CANONICAL_DEPTH`): the depth guard
    raises before ``jcs.canonicalize`` (recursive) can hit CPython's recursion
    limit, so a too-deep input is a deterministic :class:`CanonicalDepthError`
    (malformed) rather than a stack-limit-dependent crash.
    """
    if exceeds_depth(obj, MAX_CANONICAL_DEPTH):
        raise CanonicalDepthError(
            f"input nesting exceeds the {MAX_CANONICAL_DEPTH}-level "
            "canonicalization depth bound"
        )
    return jcs.canonicalize(obj)


def normalize_floats(obj: Any, precision: int = 6) -> Any:
    """Recursively round floats to ``precision`` decimal places.

    Apply BEFORE :func:`canonical_json` when hashing values re-derived from a
    source that may drift at floating-point precision (e.g. metrics re-read
    from MLflow). Tuples are returned as lists, matching their JSON shape.
    """
    if isinstance(obj, float):
        return round(obj, precision)
    if isinstance(obj, dict):
        return {k: normalize_floats(v, precision) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [normalize_floats(v, precision) for v in obj]
    return obj
