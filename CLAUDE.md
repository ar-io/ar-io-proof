# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`ar-io-proof` (import: `ario_proof`) — the standalone Python verification kernel of the ar.io
verification stack, extracted from `ar-io-mlflow`'s proof engine. It implements exactly the five
kernel primitives from `ar-io-agent/docs/stack/architecture.md` §3: RFC 8785 (JCS)
canonicalization, SHA-256, Ed25519 sign/verify, RFC 9162 binary Merkle (incl. inclusion-proof
bundles), and the accepted-`spec_version` registry. **No I/O, no networking, no key lifecycle** —
those belong to producers (`ar-io-agent`, `ar-io-mlflow`), not the kernel.

## Commands

```bash
python3 -m venv .venv && .venv/bin/pip install -e .[dev]   # one-time setup
.venv/bin/pytest -q                                        # all tests (conformance is the contract)
.venv/bin/pytest tests/test_conformance.py -q              # corpus gate only
.venv/bin/black src tests                                  # format (CI runs black --check)
```

## The conformance contract

`test-vectors/` is a byte-for-byte vendored copy of `ar-io-agent/test-vectors/` at tag
**`test-vectors-v1.0`** (provenance: `test-vectors/VENDORING.md`). `tests/test_conformance.py`
asserts, for every vector: SHA-256 corpus integrity against the CORPUS-v1.md table, JCS-canonical
payload bytes, `payload_hash`, envelope-for-signature bytes, deterministic Ed25519 signatures, and
Merkle roots / audit paths. **If the kernel disagrees with a vector, the kernel is wrong — never
the vector.** Never edit vector files; re-sync only at a published corpus tag per
`VENDORING.md`.

## Spec pins (do not drift)

- `envelope-spec.md` **v1.1 (ratified v1.0 2026-06-10, amended 2026-06-11 — additive, same
  corpus tag)** — the family contract. Profiles accepted: `ario.agent/v1` (inline payload) and
  `ario.mlflow/v1` (external commitment). Fail-closed on unknown majors.
- Signed scope = the envelope minus **`signature`**, minus the reserved **`co_signatures`**
  (envelope-spec §7.1), and — **profile-conditional** — minus underscore-prefixed annotation
  keys for `ario.mlflow/v1` + legacy envelopes ONLY (mlflow convention, e.g. `_tx_id`). The
  `ario.agent/v1` scope is minus-signature/co_signatures only, matching Go: an injected `_*`
  key on an agent envelope MUST fail verification. The corpus can catch neither the
  co_signatures strip nor the profile-conditionality — unit tests in `tests/test_envelope.py`
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
