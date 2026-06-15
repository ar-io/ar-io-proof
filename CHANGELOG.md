# Changelog — `ar-io-proof` (Python kernel)

All notable changes to the Python verification kernel. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project is pre-1.0, so
minor versions may include behavior changes.

## [0.2.0] — 2026-06-15

Full-family verifier + `ario.events/v1` ratified (kernel-ratification lane).

### Added

- **`ario.events/v1` accepted.** `ACCEPTED_SPEC_VERSIONS` now includes
  `ario.events/v1` (external commitment + Minimal disclosure), alongside
  `ario.agent/v1` and `ario.mlflow/v1` — ratified at envelope-spec v1.3.

### Changed

- **`payload_hash` is required (envelope-spec §2).** A missing `payload_hash`
  is now a hard reject in every mode, independent of whether there is material
  to compare it against. The prior compare-only-if-present lenience is fixed
  (BDFL ruling; §2 is binding). A *present* `payload_hash` with no inline
  payload and no supplied bytes remains **undetermined** (`payload_hash_ok is
  None`) — "signature-valid, semantics-undetermined."

### Conformance

- The `ario.events/v1` corpus vectors now gate through `verify_envelope`
  (full bind with the committed record bytes; signature-only → undetermined),
  not just at the primitive level.
- Corpus advanced to `test-vectors-v1.2`: chained two-checkpoint vector +
  `negatives/` (malformed `spec_version` minors, lone UTF-16 surrogate,
  missing `payload_hash`).

## [0.1.1] — 2026-06-11

- Grammar-strict `spec_version` minor matching (numeric minor only).

## [0.1.0] — 2026-06-11

- Initial extraction of the Python kernel: JCS canonicalization, SHA-256,
  Ed25519 envelope sign/verify, RFC 9162 Merkle inclusion proofs; dual-profile
  `{ario.agent/v1, ario.mlflow/v1}`.
