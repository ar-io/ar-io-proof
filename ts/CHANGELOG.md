# Changelog — `@ar.io/proof` (TypeScript kernel)

All notable changes to the TypeScript verification kernel. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/); this project is
pre-1.0, so minor versions may include behavior changes.

## [Unreleased]

## [0.2.1] — 2026-06-22

Evidence-bundle verifier + turnkey CLI (evidence-bundle + verify-CLI lane).

### Added

- **`verifyEvidenceBundle(bundle, { gateways?, fetchImpl? })`** — verifies a
  signed `ario.evidence/v1` wrapper carrying the `ario.anchor.trace/v1` body
  (the `@ar.io/anchor` SDK trace: per-event signed envelopes + their
  checkpoints + RFC 9162 inclusion proofs). Reject-unknown-major → verify the
  wrapper signature + recompute `body_hash` → per-checkpoint envelope +
  `merkle_root` recompute → per-event signature + payload binding +
  inclusion-against-its-checkpoint-root, with the asserted `verdict` surfaced
  but never trusted. Optional on-chain re-fetch of each `checkpoint_tx_id`.
  `payloadHashOk === null` (a withheld record) is semantics-undetermined, not a
  failure. New exported types: `EvidenceBundle`, `EvidenceBundleResult`,
  `AnchorTraceBody`, `TraceCheckpoint`, `TraceEvent`, `TraceInclusion`,
  `CheckpointResult`, `EventResult`, `EvidenceStatus`, `VerifyEvidenceOptions`,
  plus the `ANCHOR_TRACE_BODY_TYPE` constant.
- **`verifyAgentProofBundle(bundle, { gateways?, fetchImpl? })`** +
  `isAgentProofSpec` — verifies the agent's `ario.agent.proof/v1` inclusion
  bundle (ar-io-agent artifact.md §10), so one verifier covers both anchor and
  agent producers.
- **CLI `bin`: `npx @ar.io/proof verify <bundle.json> [comma,sep,gateways]`.**
  Sniffs `spec_version` to route between the two bundle shapes; pretty
  per-event + rollup output; pinned exit codes (mirror `ariod verify-status`):
  `0` verified · `1` failed · `2` malformed · `3` gateway-unavailable. No new
  runtime deps — Node ≥18 built-in `fetch`.

## [0.2.0] — 2026-06-15

Full-family verifier + `ario.events/v1` ratified (kernel-ratification lane).

### Changed (potentially breaking)

- **`VerificationResult.payloadHashOk` widened `boolean` → `boolean | null`.**
  `null` means the payload binding was not checkable (an external-commitment
  envelope verified without its committed record) — "signature-valid,
  semantics-undetermined." It does **not** fail the verdict (`ok` stays
  `spec && signature && payloadHashOk !== false`). Consumers that read
  `payloadHashOk` should handle the `null` case.

### Added

- **External-commitment verification (full-family).** `verifyEnvelope` detects
  the binding mode structurally: inline `payload` → recompute; supply
  `payloadBytes` (new `VerifyOptions` second argument) → external check; both →
  both must pass; neither → undetermined. The legacy `(env, expectedContentHash)`
  string form still works.
- **`ario.events/v1` accepted.** `ACCEPTED_SPEC_MAJORS` now includes
  `ario.events/v1` (ratified at envelope-spec v1.3).

### Fixed

- **#13 — grammar-strict `spec_version` minors.** A non-numeric minor suffix
  (`v1.x`, `v1.3abc`, `v1.`) is now rejected, matching the Python kernel.
- **Lone UTF-16 surrogates rejected.** `jcs()` rejects unpaired surrogates in
  input strings (not representable as UTF-8), the one behavior all three
  kernels share.
- **`payload_hash` required (envelope-spec §2).** A missing `payload_hash` is a
  hard reject in every mode.

### Conformance

- Corpus advanced to `test-vectors-v1.2`; the `ario.events/v1` vectors gate
  through `verifyEnvelope`. A standing Python⇄TS⇄Go agreement gate pins
  cross-kernel agreement.

## [0.1.2] — 2026-06-12

- Fix published ESM: emit explicit `.js` import extensions so plain-Node
  consumers can load the package.

## [0.1.1] — 2026-06-11

- Republish.

## [0.1.0] — 2026-06-11

- Initial publish of the TS kernel: JCS canonicalization, SHA-256, Ed25519
  envelope verification, RFC 9162 Merkle primitives; `ario.agent/v1`.
