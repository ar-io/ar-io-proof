"""ar-io-proof: verification kernel for the ar.io verification stack.

Implements the Verifiable Event Envelope family contract (envelope-spec.md
v1.0, ratified 2026-06-10) for the ``ario.agent/v1`` and ``ario.mlflow/v1``
profiles, plus the RFC 9162 binary Merkle tree behind agent verification
checkpoints. Conformance-gated against the ``test-vectors-v1.0`` corpus.
"""

from .bundle import BUNDLE_SPEC_VERSION, BundleVerificationResult, verify_proof_bundle
from .canonicalize import canonical_json, normalize_floats
from .envelope import (
    ACCEPTED_SPEC_VERSIONS,
    VerificationResult,
    content_hashes,
    envelope_for_signature,
    sign_envelope,
    spec_version_supported,
    verify_envelope,
)
from .hash import sha256_hex
from .merkle import (
    EMPTY_TREE_ROOT_HEX,
    audit_path,
    leaf_hash,
    merkle_root,
    node_hash,
    verify_inclusion,
)
from .sign import public_key_hex, sign, signing_key_from_seed_hex
from .verify import verify_signature

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "ACCEPTED_SPEC_VERSIONS",
    "BUNDLE_SPEC_VERSION",
    "BundleVerificationResult",
    "EMPTY_TREE_ROOT_HEX",
    "VerificationResult",
    "audit_path",
    "leaf_hash",
    "merkle_root",
    "node_hash",
    "verify_inclusion",
    "verify_proof_bundle",
    "canonical_json",
    "content_hashes",
    "envelope_for_signature",
    "normalize_floats",
    "public_key_hex",
    "sha256_hex",
    "sign",
    "sign_envelope",
    "signing_key_from_seed_hex",
    "spec_version_supported",
    "verify_envelope",
    "verify_signature",
]
