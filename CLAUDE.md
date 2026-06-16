# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`ar-io-proof` — the **polyglot verification home** of the ar.io verification stack: the family
specs (`specs/`), the one authoritative conformance corpus (`test-vectors/`), and two conformant
kernels that reproduce it byte-for-byte:

- **Python** (`ario_proof`, repo root) — extracted from `ar-io-mlflow`'s proof engine; this is the
  kernel most of this CLAUDE.md is about.
- **TypeScript** (`@ar.io/proof`, [`ts/`](ts/)) — moved here 2026-06-11 from the proof-checker app
  (an app never owns a kernel — same principle that extracted the Python kernel from mlflow).

Both implement exactly the five kernel primitives from
`ar-io-agent/docs/stack/architecture.md` §3: RFC 8785 (JCS) canonicalization, SHA-256, Ed25519
sign/verify, RFC 9162 binary Merkle (incl. inclusion-proof bundles), and the
accepted-`spec_version` registry. **No I/O, no networking, no key lifecycle** — those belong to
producers (`ar-io-agent`, `ar-io-mlflow`), not the kernel. The Go reference stays MIT-carved in
`ar-io-agent/pkg/proof`.

### Working in the TS kernel (`ts/`)

Standalone npm package, separate from the Python tooling:

```bash
cd ts && npm ci
npm run build        # tsc -p tsconfig.build.json → dist/ (ESM + .d.ts; the published shape)
npm run typecheck    # tsc --noEmit
npm test             # vitest — conformance vs ../test-vectors (the same corpus), byte-for-byte
```

CI runs a dedicated `ts` job (`ci.yml`). Releases go through `release-ts.yml` (npm OIDC trusted
publishing, provenance on, tags `ts-v*` — distinct from Python's `v*` / `release.yml`). Source
relative imports MUST carry explicit `.js` extensions (Node-ESM requirement; `moduleResolution:
bundler` won't add them — this bit `0.1.1`, fixed in `0.1.2`). Kernel changes are spec-layer
changes: byte-for-byte conformance is the gate, and the Python and Go kernels must stay in
lockstep (escalate divergences per `specs/governance.md` §6).

## Commands

```bash
python3 -m venv .venv && .venv/bin/pip install -e .[dev]   # one-time setup
.venv/bin/pytest -q                                        # all tests (conformance is the contract)
.venv/bin/pytest tests/test_conformance.py -q              # corpus gate only
.venv/bin/black src tests                                  # format (CI runs black --check)
```

## The conformance contract

`test-vectors/` is the authoritative home of the family conformance corpus, at tag
**`test-vectors-v1.2`** (provenance: `test-vectors/VENDORING.md`; downstreams like
`ar-io-agent` vendor byte-for-byte from here). `tests/test_conformance.py`
asserts, for every vector: SHA-256 corpus integrity against the CORPUS-v1.md table, JCS-canonical
payload bytes, `payload_hash`, envelope-for-signature bytes, deterministic Ed25519 signatures, and
Merkle roots / audit paths. **If the kernel disagrees with a vector, the kernel is wrong — never
the vector.** Never edit vector files; re-sync only at a published corpus tag per
`VENDORING.md`.

## Spec pins (do not drift)

- `envelope-spec.md` **v1.3 (ratified v1.0 2026-06-10, amended through 2026-06-15 — additive,
  no wire change)** — the family contract. Profiles accepted: `ario.agent/v1` (inline payload),
  `ario.mlflow/v1` (external commitment, **Python kernel only** — the TS kernel omits it), and
  `ario.events/v1` (external commitment, Minimal disclosure; both kernels). Fail-closed on
  unknown majors.
- Signed scope = the envelope minus **`signature`**, minus the reserved **`co_signatures`**
  (envelope-spec §7.1), and — **profile-conditional** — minus underscore-prefixed annotation
  keys for `ario.mlflow/v1` + legacy envelopes ONLY (mlflow convention, e.g. `_tx_id`). The
  `ario.agent/v1` and `ario.events/v1` scopes are minus-signature/co_signatures only, matching
  Go: an injected `_*` key on an agent or events envelope MUST fail verification. The corpus can
  catch neither the co_signatures strip nor the profile-conditionality — unit tests in
  `tests/test_envelope.py`
  are the only guard; do not remove them because conformance still passes without them.
- Merkle: RFC 9162 §2.1 domain separation (`0x00` leaf / `0x01` node), empty-tree root =
  `SHA-256("")`. Never the Bitcoin duplicate-last-leaf variant.
- Ed25519 is strict RFC 8032 (libsodium via PyNaCl) — matches Go `crypto/ed25519` and the JS
  sibling's `zip215: false`.

## Working rules

- Verifiers must never raise on adversarial input — malformed envelopes return a failed
  `VerificationResult`, they don't throw.
- Each commit lands one primitive, CI-green, with tests in the same commit.
- Dependencies are pinned to two load-bearing packages: `PyNaCl` and `jcs`. Adding a dependency
  is a design decision, not a convenience.
- Source siblings for cross-checks (read-only): Go reference `ar-io-agent/internal/{proof,merkle}`,
  JS verifier `ar-io-proof-checker/src/{crypto,verifier}.ts`, origin kernel
  `ar-io-mlflow/ario_mlflow/proof.py`.

## Release

`release.yml` publishes to PyPI via Trusted Publishing (OIDC) on a `v*` tag pushed by a
maintainer. Version lives in `pyproject.toml` + `src/ario_proof/__init__.py`; bump both together.
