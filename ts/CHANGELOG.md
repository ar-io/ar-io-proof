# Changelog — `@ar.io/proof` (TypeScript kernel)

All notable changes to the TypeScript verification kernel. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/); this project is
pre-1.0, so minor versions may include behavior changes.

## [Unreleased]

### Added

- **Attested-evidence-export verification (`ario.evidence.export/v1`,
  specs/evidence-export.md §5).** `verifyEvidenceBundle` now dispatches on the
  issuer-composed export `body_type` to a new `verifyExportBody` implementing the
  9-step offline algorithm: wrapper `body_hash` + Ed25519 signature (existing),
  source-bundle linkage (`SHA-256(JCS(source_bundle)) == source_bundle_hash`), a
  recomputed source verdict (recursive `verifyEvidenceBundle` over the inline
  source bundle), verdict agreement, embedded **RSA-PSS-SHA-256 operator
  attestations** (reusing the slice-1 `verifyRsaPssSha256` + `deriveOperatorAddress`
  primitives — operator-address binding `base64url(SHA-256(modulus)) ==
  payload.operator`; `data_hash` bound to `SHA-256(JCS(checkpoint envelope))`;
  `subject_ref` §3.2 well-formedness), and per-gateway on-chain fold-in. New
  `EvidenceBundleResult.export?: ExportResult` (present only for an export body),
  a recomputed §4 `VerdictObject` (snake_case, with the §4.3 `content_ok`
  tri-state), and CLI rendering of the attested-export block. Exit codes 0/1/2/3
  unchanged.
- **Per-gateway on-chain outcomes (§4.2), ADDITIVE.** `CheckpointResult` gains
  `onChain: { rollup, onChainOk, perGateway[] } | null` recording each gateway's
  `confirm` / `mismatch` / `unreachable` outcome (worst-finding-wins rollup); the
  collapsed `onChainOk: boolean | null` is **retained** as a derived field, so
  existing consumers and the anchor-trace / agent-proof paths are unchanged.
- **§5 step-5 verdict-agreement is over the DETERMINISTIC dimensions only.** The
  cached-vs-recomputed comparison excludes the environment/time-dependent
  on-chain per-gateway dimension (an offline verifier legitimately sees `null`),
  so a cached on-chain observation never by itself triggers an exit-1 tamper
  verdict; the verifier's own on-chain outcomes fold in at step 7 only if it
  re-fetches.

## [0.3.0] — 2026-06-30

### Added

- **Raw-log (content) verification for evidence bundles.** `verifyEvidenceBundle`
  now closes the final `rawLog → content_hash` link of the anchor-trace chain:
  it recomputes `SHA-256` of disclosed raw bytes and binds them to the committed
  `event.content_hash` (read from `record_bytes`; for a promoted-disclosure
  envelope, the envelope's own committed hash via `contentHashes`). New
  `EventResult.contentOk: boolean | null` (`true` match · `false` mismatch →
  the event and rollup fail · `null` undetermined when nothing is disclosed or
  nothing is committed — never a failure, mirroring `payloadBindingOk`).
  Disclosed bytes resolve from the signed in-body `events[].content` (new
  `TraceEvent.content` hex field) first, then the out-of-band
  `VerifyEvidenceOptions.content` (`Record<event_id, Uint8Array | string>`); an
  in-body-vs-side-input disagreement fails the event.
- **CLI `--logs <file.json>`** — feeds the out-of-band side input (a JSON object
  mapping `event_id` → bytes; even-length lowercase hex is treated as hex, else
  utf8 text). Per-event output gains a `logs ✓/✗/~` mark and a
  `logs: N/M disclosed verified` rollup note. **Exit codes are unchanged** — a
  content mismatch reaches exit `1` via the failed rollup. In-body
  `events[].content` is verified automatically (no flag).

  _Reported by Will Kempster ([@kempsterrrr](https://github.com/kempsterrrr)), with a
  working consumer-side reference at `kempsterrrr/verifiable-vercel`._

## [0.2.2] — 2026-06-22

### Fixed

- **CLI `npx @ar.io/proof verify` was a silent no-op.** The `is-main` guard
  compared `import.meta.url` to `process.argv[1]`, which differ when the bin
  runs through a symlink (`npx` / `node_modules/.bin/proof` → `dist/cli.js`):
  `main()` was skipped, so the command exited 0 with no output. The guard now
  `realpath`s both sides. Added a CLI e2e test that invokes via a symlink so
  this can't regress. **0.2.1's CLI does not work; use 0.2.2.**

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
