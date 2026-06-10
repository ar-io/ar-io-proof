"""ar-io-proof: verification kernel for the ar.io verification stack.

Implements the Verifiable Event Envelope family contract (envelope-spec.md
v1.0, ratified 2026-06-10) for the ``ario.agent/v1`` and ``ario.mlflow/v1``
profiles, plus the RFC 9162 binary Merkle tree behind agent verification
checkpoints. Conformance-gated against the ``test-vectors-v1.0`` corpus.
"""

__version__ = "0.1.0.dev0"
