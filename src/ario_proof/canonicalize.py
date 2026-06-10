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

__all__ = ["canonical_json", "normalize_floats"]


def canonical_json(obj: Any) -> bytes:
    """Serialize ``obj`` to RFC 8785 JCS-canonical UTF-8 bytes."""
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
