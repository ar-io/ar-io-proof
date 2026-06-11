# ar-io-proof

The **polyglot verification home** of the [ar.io verification stack](https://github.com/ar-io):
RFC 8785 (JCS) canonicalization, SHA-256 hashing, Ed25519 envelope sign/verify, and RFC 9162
binary Merkle inclusion proofs — as standalone, dependency-light kernels in two languages,
plus the family specs and the one authoritative conformance corpus. An app never owns a
kernel; producers and verifiers import these.

- **Python** — `ario_proof` (PyPI [`ar-io-proof`](https://pypi.org/project/ar-io-proof/)), at the repo root.
- **TypeScript** — [`@ar.io/proof`](https://www.npmjs.com/package/@ar.io/proof) (npm), in [`ts/`](ts/).

Both reproduce the same `test-vectors-v1.0` corpus byte-for-byte; that mutual conformance
gate is the point — anyone can verify ar.io provenance with no ar.io code in the trust path.

```bash
pip install ar-io-proof        # Python
npm install @ar.io/proof       # TypeScript
```

## Quickstart

Verify a signed envelope fetched from any Arweave gateway:

```python
import json
import urllib.request

from ario_proof import verify_envelope

raw = urllib.request.urlopen("https://arweave.net/raw/<tx_id>").read()
result = verify_envelope(json.loads(raw))

assert result.ok            # spec_version + payload binding + Ed25519 signature
print(result.to_dict())
```

Bind an artifact you hold to the provenance an envelope commits to (reverse lookup):

```python
import hashlib

artifact_hash = hashlib.sha256(open("model.pkl", "rb").read()).hexdigest()
result = verify_envelope(envelope, expected_content_hash=artifact_hash)
print(result.content_hash_ok, result.content_role)   # True, "asset"
```

Verify an external-commitment (`ario.mlflow/v1`) envelope against the committed bytes:

```python
result = verify_envelope(envelope, payload_bytes=canonical_bytes)
```

Verify an inclusion-proof bundle (`ariod proof` output — proves a leaf was in a signed
daily checkpoint):

```python
from ario_proof import verify_proof_bundle

bundle = json.load(open("proof-bundle.json"))
result = verify_proof_bundle(bundle)
assert result.ok and result.inclusion_ok
```

Sign an envelope (producers):

```python
from ario_proof import sign_envelope, signing_key_from_seed_hex

key = signing_key_from_seed_hex("<32-byte seed hex>")
envelope = sign_envelope(
    {
        "spec_version": "ario.mlflow/v1",
        "event_id": "...",
        "event_type": "training_complete",
        "subject": {"type": "mlflow_run", "run_id": "..."},
        "payload_hash": "<sha256 of the committed canonical bytes>",
        "previous_hash": "GENESIS",
        "signed_at": "2026-06-10T00:00:00.000Z",
    },
    key,
)
```

### TypeScript (`@ar.io/proof`)

The same algorithm, conformance-gated against the same corpus (`ts/test/conformance.test.ts`
reads the authoritative `test-vectors/` directly). Browser + Node ≥ 20, ESM, two small deps
(`@noble/ed25519`, `canonicalize`):

```ts
import { verifyEnvelope, sha256Hex, contentHashes } from "@ar.io/proof";

const env = await (await fetch("https://arweave.net/raw/<tx_id>")).json();
const result = await verifyEnvelope(env);
result.ok; // spec_version + payload_hash + Ed25519 all passed

// Reverse lookup: bind an artifact you hold to what an envelope commits to.
const bound = await verifyEnvelope(env, await sha256Hex(fileBytes));
bound.contentHashOk; // true ⇔ the envelope commits to exactly these bytes
```

It also ships the RFC 9162 Merkle primitives (`leafHash` / `merkleRoot` / `auditPath` /
`verifyInclusion`) for full parity with the Python kernel. See [`ts/README.md`](ts/README.md).

## What these kernels implement

- The **Verifiable Event Envelope** family contract, `envelope-spec.md` **v1.1 (ratified
  v1.0 2026-06-10, amended 2026-06-11 — additive, same conformance corpus)**, for two
  profiles:
  - **`ario.agent/v1`** — inline-payload envelopes minted by
    [`ar-io-agent`](https://github.com/ar-io/ar-io-agent) (byte-level format:
    `docs/artifact.md`).
  - **`ario.mlflow/v1`** — external-commitment envelopes minted by
    [`ar-io-mlflow`](https://github.com/ar-io/ar-io-mlflow).
- The **RFC 9162** binary Merkle tree (leaf/node domain separation, audit paths, pinned
  empty-tree root) and the **`ario.agent.proof/v1`** inclusion-proof bundle behind agent
  verification checkpoints.
- The **accepted-version registry**: `{ario.agent/v1, ario.mlflow/v1}`, matched on the
  `v<major>` token boundary per envelope-spec §2 — additive minors (`ario.agent/v1.3`)
  are accepted within a major; different majors (`ario.agent/v10`) and malformed minors
  fail closed. Envelopes that predate `spec_version` verify only with an explicit
  `allow_legacy=True`.
- The signed scope per the ratified contract: the envelope minus `signature`, minus the
  reserved `co_signatures` field (envelope-spec §7.1), and — for `ario.mlflow/v1` and
  legacy envelopes only — minus underscore-prefixed annotation keys. The `ario.agent/v1`
  signed scope is minus `signature`/`co_signatures` only, matching the Go reference
  byte-for-byte.

The kernel is exactly the five primitives in the stack architecture's kernel scope — **no
I/O, no networking, no key lifecycle**. Gateway fetching, attestation polling, and key
storage belong to the products that import this.

## Conformance

This package is conformance-gated against the `ario.agent/v1` corpus at tag
**`test-vectors-v1.0`**, vendored under [`test-vectors/`](test-vectors/) byte-for-byte (see
[`test-vectors/VENDORING.md`](test-vectors/VENDORING.md) for provenance). CI asserts, for
every vector: JCS-canonical bytes, payload hashes, envelope-for-signature bytes,
deterministic signatures, Merkle roots, and audit paths — exact to the byte. If this
package disagrees with a vector, the package is wrong — never the vector.

mlflow-profile-specific behaviors (external commitment, underscore stripping, legacy
acceptance) are covered by unit tests; the bidirectional cross-product gate against
`ar-io-mlflow`'s production verifier lands when mlflow migrates to import this package.

## Trust model

`result.ok` proves: *the holder of the private key matching the envelope's `public_key`
signed exactly these bytes, and the payload binding holds.* It does **not** prove whose key
that is, or that the envelope is on Arweave — trust in the key comes from out of band (e.g.
the agent's registration chain), and on-chain presence comes from fetching the TX yourself
and re-verifying, which is exactly what the quickstart does. `signed_at` is the signer's
claim, not a trusted timestamp; witnessed time comes from the Arweave block.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e .[dev]
.venv/bin/pytest -q          # the conformance gate is the contract
.venv/bin/black src tests
```

Dependencies are deliberately two: [`PyNaCl`](https://pypi.org/project/PyNaCl/) (Ed25519,
strict RFC 8032 — matches Go `crypto/ed25519` and the JS sibling verifier) and
[`jcs`](https://pypi.org/project/jcs/) (reference RFC 8785).

## License

MIT — verifier-relevant code is deliberately MIT-licensed so third-party auditors can verify
independently of ar.io.

## Standards home

As of 2026-06-11 this repo is the **authoritative home of the verification stack's
standards layer** (moved from `ar-io-agent` so the contract is public alongside the
reference verifiers) — and, with the TypeScript kernel's move from the proof-checker app,
the **single home of every conformant kernel** the stack ships (the Go reference stays in
`ar-io-agent/pkg/proof`, MIT-carved):

- [`specs/envelope-spec.md`](specs/envelope-spec.md) — the producer-neutral Verifiable
  Event Envelope family contract (ratified v1.0, amended v1.1)
- [`specs/evidence-bundle.md`](specs/evidence-bundle.md) — `ario.evidence/v1` report
  wrapper (ratified v1.0, not yet implemented)
- [`specs/architecture.md`](specs/architecture.md) — kernel / producer / connector /
  transport factoring standard (ratified v1.0)
- [`specs/governance.md`](specs/governance.md) — who decides, how (BDFL, async docs-PR,
  corpus-tag governance, amendment log)
- [`test-vectors/`](test-vectors/) — the conformance corpus, locked at
  `test-vectors-v1.0` (per-file SHA-256 in [`CORPUS-v1.md`](test-vectors/CORPUS-v1.md)),
  generated by [`tools/gen-vectors/`](tools/gen-vectors/) — generated, never hand-edited
- [`ts/`](ts/) — the **TypeScript kernel** (`@ar.io/proof` on npm), conformance-gated
  against the same `test-vectors/` corpus; moved here 2026-06-11 from the proof-checker app
  (an app never owns a kernel — the same principle that extracted the Python kernel from
  mlflow). The proof-checker now consumes it as an ordinary npm dependency.
- Producer *profiles* stay with their producers: `ario.agent/v1` is
  [`artifact.md`](https://github.com/ar-io/ar-io-agent/blob/main/docs/artifact.md) in
  `ar-io-agent`; `ario.mlflow/v1` lives in `ar-io-mlflow`.

**Tag namespaces** (no overlap): `v*` = Python release · `ts-v*` = TypeScript release ·
`test-vectors-v*` = corpus. Python publishes to PyPI via `release.yml`; TypeScript publishes
to npm via `release-ts.yml` (OIDC trusted publishing, provenance on).

Contract conflicts: open an issue here titled `contract conflict: <spec> §<section>` with
the smallest reproduction (see [`specs/governance.md`](specs/governance.md) §6).
