"""ar-io-proof: verification kernel for the ar.io verification stack.

Implements the Verifiable Event Envelope family contract (envelope-spec.md
v1.1 — ratified v1.0 2026-06-10, amended 2026-06-11) for the
``ario.agent/v1`` and ``ario.mlflow/v1`` profiles, plus the RFC 9162 binary
Merkle tree behind agent verification checkpoints. Conformance-gated against
the ``test-vectors-v1.0`` corpus.
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
from .evidence import (
    ACCEPTED_EVIDENCE_MAJORS,
    ANCHOR_TRACE_BODY_TYPE,
    EXPORT_BODY_TYPE,
    VERDICT_SCHEMA_VERSION,
    AttestationResult,
    CheckpointResult,
    EventResult,
    EvidenceBundleResult,
    ExportResult,
    OnChainResult,
    PerGatewayOutcome,
    verify_evidence_bundle,
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
from .rsa_pss import (
    RSA_PSS_SALT_LENGTH,
    MalformedRsaError,
    derive_operator_address,
    verify_rsa_pss_sha256,
)
from .sign import public_key_hex, sign, signing_key_from_seed_hex
from .verify import verify_signature

__version__ = "0.3.0"

__all__ = [
    "__version__",
    "ACCEPTED_SPEC_VERSIONS",
    "ACCEPTED_EVIDENCE_MAJORS",
    "ANCHOR_TRACE_BODY_TYPE",
    "EXPORT_BODY_TYPE",
    "VERDICT_SCHEMA_VERSION",
    "BUNDLE_SPEC_VERSION",
    "BundleVerificationResult",
    "EMPTY_TREE_ROOT_HEX",
    "VerificationResult",
    "AttestationResult",
    "CheckpointResult",
    "EventResult",
    "EvidenceBundleResult",
    "ExportResult",
    "OnChainResult",
    "PerGatewayOutcome",
    "MalformedRsaError",
    "RSA_PSS_SALT_LENGTH",
    "audit_path",
    "leaf_hash",
    "merkle_root",
    "node_hash",
    "verify_inclusion",
    "verify_proof_bundle",
    "verify_evidence_bundle",
    "canonical_json",
    "content_hashes",
    "derive_operator_address",
    "envelope_for_signature",
    "normalize_floats",
    "public_key_hex",
    "sha256_hex",
    "sign",
    "sign_envelope",
    "signing_key_from_seed_hex",
    "spec_version_supported",
    "verify_envelope",
    "verify_rsa_pss_sha256",
    "verify_signature",
]
