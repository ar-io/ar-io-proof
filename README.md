# ar-io-proof

Verification kernel for the [ar.io verification stack](https://github.com/ar-io): RFC 8785
(JCS) canonicalization, SHA-256 hashing, Ed25519 envelope sign/verify, and RFC 9162 binary
Merkle inclusion proofs — as a standalone, dependency-light Python package.

```bash
pip install ar-io-proof
```

```python
import ario_proof
```

## What this package implements

- The **Verifiable Event Envelope** family contract, `envelope-spec.md` **v1.0 (ratified
  2026-06-10)**, for two profiles:
  - **`ario.agent/v1`** — inline-payload envelopes minted by
    [`ar-io-agent`](https://github.com/ar-io/ar-io-agent) (byte-level format:
    `docs/artifact.md`).
  - **`ario.mlflow/v1`** — external-commitment envelopes minted by
    [`ar-io-mlflow`](https://github.com/ar-io/ar-io-mlflow).
- The RFC 9162 binary Merkle tree and inclusion-proof bundle (`ario.agent.proof/v1`) used by
  agent verification checkpoints.

## Conformance

This package is conformance-gated against the `ario.agent/v1` corpus at tag
**`test-vectors-v1.0`**, vendored under [`test-vectors/`](test-vectors/) byte-for-byte (see
[`test-vectors/VENDORING.md`](test-vectors/VENDORING.md) for provenance). CI fails on any
mismatch in JCS-canonical bytes, payload hashes, envelope-for-signature bytes, or signatures.
If this package disagrees with a vector, the package is wrong — never the vector.

## Status

Scaffold. Primitives land one CI-green commit at a time; see the repo history.

## License

MIT — verifier-relevant code is deliberately MIT-licensed so third-party auditors can verify
independently of ar.io.
