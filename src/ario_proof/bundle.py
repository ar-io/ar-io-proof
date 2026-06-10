"""Inclusion-proof bundle verification (``ario.agent.proof/v1``).

The ~1.4 KB bundle emitted by ``ariod proof`` proves a single asset's leaf
was part of a signed daily checkpoint. Mirrors the Go reference
(``ar-io-agent/internal/checkpoint/proof.go``) and artifact.md §10:

1. Verify the embedded checkpoint envelope (payload binding + signature).
2. Hash the leaf with the RFC 9162 leaf-domain prefix.
3.+4. Walk the audit path and confirm the reconstructed root equals the
   checkpoint envelope's claimed ``merkle_root``.
5. Confirming ``checkpoint_tx_id`` matches the bytes on Arweave is the
   caller's job — the kernel does no networking; pair this with a gateway
   fetch and byte-compare (or re-verify) of the embedded envelope.

Verification never raises on adversarial input.
"""

from dataclasses import asdict, dataclass, field
from typing import Any

from .canonicalize import canonical_json
from .envelope import VerificationResult, verify_envelope
from .merkle import leaf_hash, verify_inclusion

__all__ = ["BUNDLE_SPEC_VERSION", "BundleVerificationResult", "verify_proof_bundle"]

BUNDLE_SPEC_VERSION = "ario.agent.proof/v1"


@dataclass
class BundleVerificationResult:
    """Outcome of inclusion-proof bundle verification.

    ``ok`` requires the bundle shape and spec_version to be right, the
    embedded checkpoint envelope to verify, and the audit path to
    reconstruct the envelope's ``merkle_root``.
    """

    ok: bool
    spec_version_ok: bool
    envelope: VerificationResult | None
    inclusion_ok: bool
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _fail(
    errors: list[str],
    *,
    spec_version_ok: bool = False,
    envelope: VerificationResult | None = None,
) -> BundleVerificationResult:
    return BundleVerificationResult(
        ok=False,
        spec_version_ok=spec_version_ok,
        envelope=envelope,
        inclusion_ok=False,
        errors=errors,
    )


def verify_proof_bundle(bundle: Any) -> BundleVerificationResult:
    """Verify an ``ario.agent.proof/v1`` inclusion-proof bundle in-process."""
    if not isinstance(bundle, dict):
        return _fail(["bundle is not a JSON object"])

    spec_version = bundle.get("spec_version")
    if spec_version != BUNDLE_SPEC_VERSION:
        return _fail([f"unsupported bundle spec_version: {spec_version!r}"])

    envelope = bundle.get("checkpoint_envelope")
    leaf = bundle.get("leaf")
    if not isinstance(envelope, dict):
        return _fail(["bundle missing checkpoint_envelope"], spec_version_ok=True)
    if not isinstance(leaf, dict):
        return _fail(["bundle missing leaf"], spec_version_ok=True)
    tx_id = bundle.get("checkpoint_tx_id")
    if not isinstance(tx_id, str) or not tx_id:
        return _fail(["bundle missing checkpoint_tx_id"], spec_version_ok=True)

    # 1. The embedded checkpoint envelope must itself verify.
    env_result = verify_envelope(envelope)
    errors = list(env_result.errors)
    if not env_result.ok:
        errors.append("checkpoint envelope verification failed")

    # 2. Hash the leaf with the RFC 9162 leaf-domain prefix.
    try:
        computed_leaf_hash = leaf_hash(canonical_json(leaf))
    except Exception:
        errors.append("leaf is not JCS-canonicalizable")
        return _fail(errors, spec_version_ok=True, envelope=env_result)

    # 3+4. Walk the audit path against the envelope's claimed root.
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        errors.append("checkpoint envelope payload missing or wrong shape")
        return _fail(errors, spec_version_ok=True, envelope=env_result)
    leaf_count = payload.get("leaf_count")
    if isinstance(leaf_count, bool) or not isinstance(leaf_count, int):
        errors.append("checkpoint payload.leaf_count missing or wrong type")
        return _fail(errors, spec_version_ok=True, envelope=env_result)
    root_hex = payload.get("merkle_root")
    audit_path = bundle.get("audit_path")
    leaf_index = bundle.get("leaf_index")
    try:
        expected_root = bytes.fromhex(root_hex)
        path = [bytes.fromhex(h) for h in audit_path]
        if len(expected_root) != 32 or any(len(h) != 32 for h in path):
            raise ValueError
        if isinstance(leaf_index, bool) or not isinstance(leaf_index, int):
            raise ValueError
    except (TypeError, ValueError):
        errors.append("merkle_root / audit_path / leaf_index malformed")
        return _fail(errors, spec_version_ok=True, envelope=env_result)

    inclusion_ok = verify_inclusion(
        computed_leaf_hash, leaf_index, leaf_count, path, expected_root
    )
    if not inclusion_ok:
        errors.append("audit_path does not reconstruct merkle_root")

    return BundleVerificationResult(
        ok=env_result.ok and inclusion_ok,
        spec_version_ok=True,
        envelope=env_result,
        inclusion_ok=inclusion_ok,
        errors=errors,
    )
