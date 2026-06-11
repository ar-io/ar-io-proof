# gen-vectors — cross-language conformance test vector generator

Generates the JSON test vectors in `../../test-vectors/` that every conforming
verifier (Go, Python, JavaScript, Rust, etc.) MUST reproduce byte-for-byte.
The vectors pin:

- JCS canonical bytes for each envelope and leaf input
- SHA-256 hashes of those canonical bytes
- Ed25519 signatures against a published fixed seed
- RFC 9162 Merkle roots and inclusion proofs at small / odd / large leaf counts

See [`artifact.md`](https://github.com/ar-io/ar-io-agent/blob/main/docs/artifact.md) §15 for the vector file format.

## Why Python

The Python `jcs` package and `pynacl` provide reference implementations
inherited from the `ar-io-mlflow` plugin. By generating vectors from Python
and validating the Go agent against them, we get cross-language conformance
from day 1.

## Run

```bash
# from this directory
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
python3 gen_vectors.py ../../test-vectors
```

Or from the repo root:

```bash
make vectors
```

## Conformance

The published vectors include:

- One envelope per event type (4 vectors)
- Merkle trees at 0, 1, 2, 3, 7, 16, 1024 leaves
- Inclusion proofs for first / middle / last leaf in each non-trivial tree

A verifier in any language is conformant iff `go test ./...` (or the
equivalent in that language) passes against the vector set without
modification. The Go reference verifier in [`pkg/proof/`](https://github.com/ar-io/ar-io-agent/tree/main/pkg/proof/)
and [`pkg/merkle/`](https://github.com/ar-io/ar-io-agent/tree/main/pkg/merkle/) defines the canonical
behavior; the Python here defines the canonical bytes.

## NOT for production use

The fixed Ed25519 seed (`0123...cdef × 4`) is published in `gen_vectors.py`.
Anyone with this file can sign envelopes that verify against the seed's
public key. The vectors are test fixtures, never operational signing material.
