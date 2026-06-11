"""Verifiable Event Envelope assembly and verification.

Implements the family contract (``envelope-spec.md`` v1.1 — ratified v1.0
2026-06-10, amended 2026-06-11, additive, same conformance corpus) for the
two accepted profiles:

- ``ario.agent/v1`` — inline payload binding: the envelope carries
  ``payload`` and ``payload_hash = SHA-256(JCS(payload))``.
- ``ario.mlflow/v1`` — external commitment binding: the envelope carries
  only ``payload_hash``; callers supply the committed canonical bytes to
  check it.

The signed scope is the envelope minus ``signature``, minus the reserved
``co_signatures`` field (envelope-spec §7.1 — reserved and excluded from
the signed scope from day one, even though the v1.0 corpus has no co-signed
vectors), and — **for the mlflow profile and legacy envelopes only** —
minus underscore-prefixed annotation keys (out-of-band routing metadata by
mlflow convention, e.g. ``_tx_id``). The ``ario.agent/v1`` signed scope has
no annotation convention and matches the Go reference exactly: an agent
envelope with an injected ``_*`` key must FAIL signature verification, the
same way any other unsigned-field injection does.

Verification never raises on adversarial input — malformed envelopes return
a failed :class:`VerificationResult`.
"""

from dataclasses import asdict, dataclass
from typing import Any, Literal

from nacl.signing import SigningKey

from .canonicalize import canonical_json
from .hash import sha256_hex
from .sign import public_key_hex
from .sign import sign as _sign
from .verify import verify_signature

__all__ = [
    "ACCEPTED_SPEC_VERSIONS",
    "ContentRole",
    "VerificationResult",
    "spec_version_supported",
    "envelope_for_signature",
    "content_hashes",
    "verify_envelope",
    "sign_envelope",
]

# The accepted-spec_version registry (architecture.md §3 primitive 5): the
# single list of recognized profile MAJORS. Fail-closed on anything else — a
# future major is added here deliberately, never inferred. Matching is on
# the v<major> token boundary per envelope-spec v1.1 §2 (grammar
# ``<namespace>/v<major>[.<minor>]``): a v1 verifier accepts additive
# minors (``ario.agent/v1.3``) but never a different major
# (``ario.agent/v10``) or a non-numeric minor (malformed).
ACCEPTED_SPEC_VERSIONS = frozenset({"ario.agent/v1", "ario.mlflow/v1"})

# Fields excluded from the signed scope. ``signature`` is appended after
# signing; ``co_signatures`` is reserved by envelope-spec §7.1 for
# countersignatures attached after the producer signed.
_UNSIGNED_FIELDS = frozenset({"signature", "co_signatures"})

ContentRole = Literal["asset", "baseline", "observed"]


@dataclass
class VerificationResult:
    """Outcome of envelope verification.

    Field-for-field parity with the JS sibling verifier's
    ``VerificationResult`` (ar-io-proof-checker ``src/types.ts``), plus
    ``legacy_envelope`` for pre-``spec_version`` mlflow envelopes.

    ``ok`` is the cryptographic verdict: ``spec_version_ok`` and
    ``signature_ok`` and ``payload_hash_ok is not False`` (``None`` means the
    binding was not checkable — commitment-only verification — and does not
    fail the verdict). The content bind never affects ``ok``.
    """

    ok: bool
    spec_version_ok: bool
    payload_hash_ok: bool | None
    signature_ok: bool
    content_hash_ok: bool | None
    content_role: ContentRole | None
    legacy_envelope: bool
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _matches_major(spec_version: str, major: str) -> bool:
    """True iff ``spec_version`` is ``major`` exactly or ``major`` plus a
    numeric ``.<minor>`` token (envelope-spec v1.1 §2). Mirrors the Go
    reference's prefix-on-token-boundary semantics; a non-numeric or empty
    minor is malformed and rejected (fail-closed)."""
    if spec_version == major:
        return True
    prefix = major + "."
    if not spec_version.startswith(prefix):
        return False
    minor = spec_version[len(prefix) :]
    return bool(minor) and all(c in "0123456789" for c in minor)


def spec_version_supported(spec_version: Any) -> bool:
    """True iff ``spec_version``'s major token is in the accepted registry."""
    if not isinstance(spec_version, str):
        return False
    return any(_matches_major(spec_version, major) for major in ACCEPTED_SPEC_VERSIONS)


def envelope_for_signature(envelope: dict[str, Any]) -> dict[str, Any]:
    """The signed scope: the envelope minus ``signature``/``co_signatures``.

    Underscore-prefixed annotation keys are additionally stripped for the
    ``ario.mlflow/v1`` profile and for legacy envelopes (no ``spec_version``)
    — the mlflow convention treats ``_*`` as unsigned routing metadata. The
    ``ario.agent/v1`` profile has no such convention: its ``_*`` keys (if
    any) stay inside the signed scope, matching the Go reference.
    """
    spec_version = envelope.get("spec_version")
    strip_annotations = spec_version is None or (
        isinstance(spec_version, str) and _matches_major(spec_version, "ario.mlflow/v1")
    )
    return {
        k: v
        for k, v in envelope.items()
        if k not in _UNSIGNED_FIELDS and not (strip_annotations and k.startswith("_"))
    }


def content_hashes(envelope: dict[str, Any]) -> list[tuple[ContentRole, str]]:
    """The asset content hashes an ``ario.agent/v1`` envelope commits to,
    by role — what powers artifact→provenance (reverse) lookups."""
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return []
    out: list[tuple[ContentRole, str]] = []
    event_type = envelope.get("event_type")
    if event_type == "asset_registered":
        if isinstance(payload.get("hash"), str):
            out.append(("asset", payload["hash"]))
    elif event_type == "asset_missing":
        baseline = payload.get("baseline")
        if isinstance(baseline, dict) and isinstance(baseline.get("hash"), str):
            out.append(("baseline", baseline["hash"]))
    elif event_type == "tamper_detected":
        observed = payload.get("observed")
        if isinstance(observed, dict) and isinstance(observed.get("hash"), str):
            out.append(("observed", observed["hash"]))
        baseline = payload.get("baseline")
        if isinstance(baseline, dict) and isinstance(baseline.get("hash"), str):
            out.append(("baseline", baseline["hash"]))
    return out


def verify_envelope(
    envelope: Any,
    *,
    payload_bytes: bytes | None = None,
    expected_content_hash: str | None = None,
    allow_legacy: bool = False,
) -> VerificationResult:
    """Verify a signed envelope.

    Checks, in order:

    1. **spec_version** — must be in :data:`ACCEPTED_SPEC_VERSIONS`
       (fail-closed). ``allow_legacy=True`` additionally accepts envelopes
       with no ``spec_version`` field (mlflow envelopes anchored before the
       field existed); these are flagged ``legacy_envelope=True``.
    2. **payload binding** — inline mode when the envelope carries
       ``payload`` (recompute ``SHA-256(JCS(payload))``); external mode when
       the caller supplies ``payload_bytes``. Both are checked when both are
       available; ``payload_hash_ok`` is ``None`` when neither is.
    3. **signature** — Ed25519 over ``JCS(envelope_for_signature(envelope))``
       under the envelope's own ``public_key``. (This proves the holder of
       that key signed it; trusting *whose* key it is comes from out of
       band.)
    4. **content bind** (optional) — when ``expected_content_hash`` is given,
       match it case-insensitively against the hashes the envelope commits
       to (:func:`content_hashes`). Reported via ``content_hash_ok`` /
       ``content_role``; never affects ``ok``.
    """
    errors: list[str] = []

    if not isinstance(envelope, dict):
        return VerificationResult(
            ok=False,
            spec_version_ok=False,
            payload_hash_ok=None,
            signature_ok=False,
            content_hash_ok=None if expected_content_hash is None else False,
            content_role=None,
            legacy_envelope=False,
            errors=["envelope is not a JSON object"],
        )

    # -- 1. spec_version (fail-closed registry) -------------------------
    spec_version = envelope.get("spec_version")
    legacy = spec_version is None
    if legacy:
        spec_version_ok = allow_legacy
        if not allow_legacy:
            errors.append("missing spec_version (pass allow_legacy=True to accept)")
    else:
        spec_version_ok = spec_version_supported(spec_version)
        if not spec_version_ok:
            errors.append(f"unsupported spec_version: {spec_version!r}")

    # -- 2. payload binding ---------------------------------------------
    stored_hash = envelope.get("payload_hash")
    checks: list[bool] = []
    if "payload" in envelope:
        try:
            computed = sha256_hex(canonical_json(envelope["payload"]))
            checks.append(computed == stored_hash)
        except Exception:
            checks.append(False)
            errors.append("payload is not JCS-canonicalizable")
    if payload_bytes is not None:
        checks.append(sha256_hex(payload_bytes) == stored_hash)
    payload_hash_ok: bool | None = all(checks) if checks else None
    if payload_hash_ok is False and not any(
        e.startswith("payload is not") for e in errors
    ):
        errors.append("payload_hash does not match the committed bytes")

    # -- 3. signature ----------------------------------------------------
    signature_ok = False
    try:
        message = canonical_json(envelope_for_signature(envelope))
        signature_ok = verify_signature(
            message,
            envelope.get("signature", ""),
            envelope.get("public_key", ""),
        )
    except Exception:
        signature_ok = False
    if not signature_ok:
        errors.append("Ed25519 signature verification failed")

    # -- 4. optional content bind -----------------------------------------
    content_hash_ok: bool | None = None
    content_role: ContentRole | None = None
    if expected_content_hash is not None:
        content_hash_ok = False
        wanted = expected_content_hash.lower()
        for role, candidate in content_hashes(envelope):
            if candidate.lower() == wanted:
                content_hash_ok = True
                content_role = role
                break
        if not content_hash_ok:
            errors.append(
                "expected_content_hash matches no hash this envelope commits to"
            )

    ok = spec_version_ok and signature_ok and payload_hash_ok is not False
    return VerificationResult(
        ok=ok,
        spec_version_ok=spec_version_ok,
        payload_hash_ok=payload_hash_ok,
        signature_ok=signature_ok,
        content_hash_ok=content_hash_ok,
        content_role=content_role,
        legacy_envelope=legacy,
        errors=errors,
    )


def sign_envelope(envelope: dict[str, Any], key: SigningKey) -> dict[str, Any]:
    """Complete and sign an envelope; returns a new dict, input untouched.

    For inline-payload envelopes (``payload`` present), ``payload_hash`` is
    computed if absent. ``public_key`` is filled in from ``key`` if absent.
    The signature covers :func:`envelope_for_signature` of the completed
    envelope.

    Raises ``ValueError`` if the envelope is already signed, if a present
    ``payload_hash`` disagrees with the inline payload, or if a present
    ``public_key`` is not ``key``'s — silently re-signing or key-swapping is
    how producers corrupt chains.
    """
    if "signature" in envelope:
        raise ValueError("envelope already carries a signature")
    env = dict(envelope)

    if "payload" in env:
        computed = sha256_hex(canonical_json(env["payload"]))
        stored = env.setdefault("payload_hash", computed)
        if stored != computed:
            raise ValueError("payload_hash does not match SHA-256(JCS(payload))")
    elif "payload_hash" not in env:
        raise ValueError("envelope needs payload (inline) or payload_hash (external)")

    expected_pub = public_key_hex(key)
    stored_pub = env.setdefault("public_key", expected_pub)
    if stored_pub != expected_pub:
        raise ValueError("envelope public_key does not match the signing key")

    env["signature"] = _sign(canonical_json(envelope_for_signature(env)), key).hex()
    return env
