#!/usr/bin/env python3
"""Generate cross-language conformance test vectors for ar-io-agent.

Each vector pins a known input → JCS-canonical bytes → SHA-256 → Ed25519
signature against a fixed test keypair. Go (and any other language)
implementations of the spec MUST reproduce these byte-for-byte to be
conformant.

See docs/artifact.md §15 for the file format.

Usage:
    python3 gen_vectors.py <output-dir>

Dependencies (install in a venv):
    pip install jcs pynacl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import jcs
from nacl.signing import SigningKey


# Fixed test seed — published in source so every implementer can reproduce.
# NEVER use this seed for real signing. The corresponding Arweave address
# is well-known too; treat the keypair as test fixture, not secret.
FIXED_SEED_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def sign_envelope_vector(
    *,
    vector_id: str,
    description: str,
    envelope_pre_signature: dict,
    seed_hex: str = FIXED_SEED_HEX,
) -> dict:
    """Compute all expected outputs for an envelope vector.

    Mirrors the producer steps in docs/artifact.md §6:
      1. JCS(payload)        -> payload_jcs_bytes
      2. SHA-256(payload_jcs)-> payload_hash
      3. envelope.payload_hash = payload_hash
         envelope.public_key  = hex(public)
         envelope (no signature) -> JCS -> envelope_for_sig_jcs_bytes
      4. Ed25519 sign(envelope_for_sig_jcs_bytes, seed) -> signature
    """
    seed = bytes.fromhex(seed_hex)
    sk = SigningKey(seed)
    pub_hex = sk.verify_key.encode().hex()

    payload = envelope_pre_signature["payload"]
    payload_jcs = jcs.canonicalize(payload)
    payload_hash = hashlib.sha256(payload_jcs).hexdigest()

    env = {k: v for k, v in envelope_pre_signature.items()}
    env["payload_hash"] = payload_hash
    env["public_key"] = pub_hex
    env.pop("signature", None)

    env_for_sig_jcs = jcs.canonicalize(env)
    signature = sk.sign(env_for_sig_jcs).signature.hex()

    return {
        "vector_id": vector_id,
        "description": description,
        "spec_version": "ario.agent/v1",
        "fixed_keypair": {
            "ed25519_seed_hex": seed_hex,
            "ed25519_public_hex": pub_hex,
        },
        "inputs": {
            "envelope_pre_signature": envelope_pre_signature,
        },
        "expected_outputs": {
            "payload_jcs_bytes_hex": payload_jcs.hex(),
            "payload_hash_hex": payload_hash,
            "envelope_for_sig_jcs_bytes_hex": env_for_sig_jcs.hex(),
            "signature_hex": signature,
        },
    }


def leaf_hash(leaf_obj: dict) -> bytes:
    """Compute the RFC 9162 leaf hash: SHA-256(0x00 || JCS(leaf_obj))."""
    return hashlib.sha256(b"\x00" + jcs.canonicalize(leaf_obj)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Compute the RFC 9162 internal node hash: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def largest_pow2_less_than(n: int) -> int:
    if n < 2:
        return 0
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaf_hashes: list[bytes]) -> bytes:
    """RFC 9162 Merkle Tree Hash."""
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hashes[0]
    k = largest_pow2_less_than(n)
    return node_hash(mth(leaf_hashes[:k]), mth(leaf_hashes[k:]))


def audit_path(m: int, leaf_hashes: list[bytes]) -> list[bytes]:
    """RFC 9162 inclusion proof for leaf at index m."""
    n = len(leaf_hashes)
    if n == 1:
        return []
    k = largest_pow2_less_than(n)
    if m < k:
        return audit_path(m, leaf_hashes[:k]) + [mth(leaf_hashes[k:])]
    return audit_path(m - k, leaf_hashes[k:]) + [mth(leaf_hashes[:k])]


def merkle_tree_vector(*, vector_id: str, description: str, leaf_objects: list[dict]) -> dict:
    """Build a Merkle tree vector with inclusion proofs for first/last/middle leaves."""
    hashes = [leaf_hash(lo) for lo in leaf_objects]
    root = mth(hashes)
    leaves_with_hashes = [
        {"leaf_object": lo, "leaf_hash_hex": h.hex()} for lo, h in zip(leaf_objects, hashes)
    ]
    n = len(leaf_objects)
    if n == 1:
        proof_indices = [0]
    elif n == 2:
        proof_indices = [0, 1]
    else:
        proof_indices = sorted({0, n // 2, n - 1})
    proofs = [
        {
            "leaf_index": i,
            "audit_path_hex": [h.hex() for h in audit_path(i, hashes)],
        }
        for i in proof_indices
    ]
    return {
        "vector_id": vector_id,
        "description": description,
        "leaf_count": n,
        "leaves": leaves_with_hashes,
        "expected_root_hex": root.hex(),
        "inclusion_proofs": proofs,
    }


# ---------------------------------------------------------------------------
# Vector definitions
# ---------------------------------------------------------------------------

ENVELOPE_VECTORS = [
    {
        "vector_id": "envelope-asset-registered-01",
        "description": "Minimal asset_registered envelope with a single filesystem asset",
        "envelope_pre_signature": {
            "spec_version": "ario.agent/v1",
            "event_id": "550e8400-e29b-41d4-a716-446655440000",
            "event_type": "asset_registered",
            "subject": {
                "type": "agent",
                "tenant_id": "acme-corp",
                "agent_id": "prod-ml-host-01",
            },
            "payload": {
                "asset": {
                    "asset_id": "production-models",
                    "policy_asset_index": 0,
                    "type": "filesystem",
                    "uri": "file:///models/prod/credit_scorer.pkl",
                },
                "hash": "7f4c0d2e1a8b6c3d9f5e4a2b1c0d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d",
                "size_bytes": 47832,
                "discovered_at": "2026-05-12T14:23:45.000Z",
                "policy_hash": "2a8e3f9d4c5b6a7e8f1d2c3b4a5e6f7d8c9b0a1e2f3d4c5b6a7e8f9d0c1b2a3e",
            },
            "previous_hash": "GENESIS",
            "signed_at": "2026-05-12T14:23:45.123Z",
        },
    },
    {
        "vector_id": "envelope-tamper-detected-01",
        "description": "tamper_detected envelope referencing a prior asset_registered baseline",
        "envelope_pre_signature": {
            "spec_version": "ario.agent/v1",
            "event_id": "660e8400-e29b-41d4-a716-446655440001",
            "event_type": "tamper_detected",
            "subject": {
                "type": "agent",
                "tenant_id": "acme-corp",
                "agent_id": "prod-ml-host-01",
            },
            "payload": {
                "asset": {
                    "asset_id": "production-models",
                    "policy_asset_index": 0,
                    "type": "filesystem",
                    "uri": "file:///models/prod/credit_scorer.pkl",
                },
                "baseline": {
                    "hash": "7f4c0d2e1a8b6c3d9f5e4a2b1c0d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d",
                    "tx_id": "BASELINE_TX_ID_PLACEHOLDER_PLACEHOLDER",
                    "registered_at": "2026-05-12T14:23:45.000Z",
                },
                "observed": {
                    "hash": "9a3b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
                    "size_bytes": 47833,
                    "detected_at": "2026-05-12T15:08:12.456Z",
                },
                "policy_hash": "2a8e3f9d4c5b6a7e8f1d2c3b4a5e6f7d8c9b0a1e2f3d4c5b6a7e8f9d0c1b2a3e",
            },
            "previous_hash": "GENESIS",
            "signed_at": "2026-05-12T15:08:12.500Z",
        },
    },
    {
        "vector_id": "envelope-policy-changed-01",
        "description": "policy_changed envelope: GENESIS → first policy",
        "envelope_pre_signature": {
            "spec_version": "ario.agent/v1",
            "event_id": "770e8400-e29b-41d4-a716-446655440002",
            "event_type": "policy_changed",
            "subject": {
                "type": "agent",
                "tenant_id": "acme-corp",
                "agent_id": "prod-ml-host-01",
            },
            "payload": {
                "previous_policy_hash": "GENESIS",
                "new_policy_hash": "2a8e3f9d4c5b6a7e8f1d2c3b4a5e6f7d8c9b0a1e2f3d4c5b6a7e8f9d0c1b2a3e",
                "policy_uri": "file:///etc/ario-agent/policy.yaml",
                "applied_at": "2026-05-10T08:00:00.000Z",
                "diff_summary": {
                    "added_assets": 3,
                    "removed_assets": 0,
                    "modified_assets": 0,
                },
            },
            "previous_hash": "GENESIS",
            "signed_at": "2026-05-10T08:00:00.123Z",
        },
    },
    {
        "vector_id": "envelope-key-retired-01",
        "description": "key_retired envelope: rotation handoff, signed by the OLD key",
        "envelope_pre_signature": {
            "spec_version": "ario.agent/v1",
            "event_id": "aa0e8400-e29b-41d4-a716-446655440005",
            "event_type": "key_retired",
            "subject": {
                "type": "agent",
                "tenant_id": "acme-corp",
                "agent_id": "prod-ml-host-01",
            },
            "payload": {
                # The FIXED_SEED_HEX keypair acts as the "old" key for
                # this vector. retired_public_key matches what the
                # vector signs with — that's the auditor's proof of
                # rotation authorship.
                "retired_key_id": "11111111-1111-4111-8111-111111111111",
                "retired_public_key": "4cb5fbb1f6cf83c54213b6692b88a4d4922eaa0987d76f1e2f5fd2f33b53d72e",
                "new_key_id": "22222222-2222-4222-8222-222222222222",
                "new_public_key": "9e3b4f1c8a6d2e5f7b0a9c1e3f5a7d2e4c6f8b0a1d3e5f7a9b1c2d4e6f8a0b3c",
                "retired_at": "2026-05-15T09:00:00.000Z",
                "reason": "rotation",
            },
            "previous_hash": "GENESIS",
            "signed_at": "2026-05-15T09:00:00.123Z",
        },
    },
    {
        "vector_id": "envelope-asset-missing-01",
        "description": "asset_missing envelope: asset unavailable for N consecutive cycles, crossing threshold",
        "envelope_pre_signature": {
            "spec_version": "ario.agent/v1",
            "event_id": "990e8400-e29b-41d4-a716-446655440004",
            "event_type": "asset_missing",
            "subject": {
                "type": "agent",
                "tenant_id": "acme-corp",
                "agent_id": "prod-ml-host-01",
            },
            "payload": {
                "asset": {
                    "asset_id": "production-models",
                    "policy_asset_index": 0,
                    "type": "filesystem",
                    "uri": "file:///models/prod/credit_scorer.pkl",
                },
                "baseline": {
                    "hash": "7f4c0d2e1a8b6c3d9f5e4a2b1c0d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d",
                    "tx_id": "BASELINE_TX_ID_PLACEHOLDER_PLACEHOLDER",
                    "registered_at": "2026-05-12T14:23:45.000Z",
                },
                "consecutive_unavailable": 3,
                "detected_at": "2026-05-12T21:08:12.000Z",
                "policy_hash": "2a8e3f9d4c5b6a7e8f1d2c3b4a5e6f7d8c9b0a1e2f3d4c5b6a7e8f9d0c1b2a3e",
            },
            "previous_hash": "GENESIS",
            "signed_at": "2026-05-12T21:08:12.123Z",
        },
    },
    {
        "vector_id": "envelope-verification-checkpoint-01",
        "description": "verification_checkpoint envelope summarizing a 3-leaf day",
        "envelope_pre_signature": {
            "spec_version": "ario.agent/v1",
            "event_id": "880e8400-e29b-41d4-a716-446655440003",
            "event_type": "verification_checkpoint",
            "subject": {
                "type": "agent",
                "tenant_id": "acme-corp",
                "agent_id": "prod-ml-host-01",
            },
            "payload": {
                "window": {
                    "start": "2026-05-12T00:00:00.000Z",
                    "end": "2026-05-13T00:00:00.000Z",
                },
                "merkle_root": "c5d9bbb3217b8fcb9fbb5be3b5b51b1b3b6cd5e5b2a3a6c5d1e1f1a0b9c8d7e6",
                "merkle_algorithm": "RFC9162-binary-sha256",
                "leaf_count": 3,
                "leaf_manifest": {
                    "hash": "f3a1e7b9c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8",
                    "size_bytes": 612,
                    "uri": "s3://acme-audit/ario-agent/prod-ml-host-01/2026-05-12.jsonl",
                },
                "previous_checkpoint_hash": "GENESIS",
                "outcome_summary": {
                    "verified": 3,
                    "tampered": 0,
                    "unavailable": 0,
                },
                "policy_hash": "2a8e3f9d4c5b6a7e8f1d2c3b4a5e6f7d8c9b0a1e2f3d4c5b6a7e8f9d0c1b2a3e",
            },
            "previous_hash": "GENESIS",
            "signed_at": "2026-05-13T00:00:01.000Z",
        },
    },
]


def make_leaves(n: int) -> list[dict]:
    """Build n synthetic leaf objects for tree vectors."""
    return [
        {
            "schema": "ario.agent.leaf/v1",
            "asset": {
                "asset_id": f"asset-{i:03d}",
                "type": "filesystem",
                "uri": f"file:///data/asset-{i:03d}.bin",
            },
            "outcome": "verified",
            "expected_hash": f"{i:064x}",
            "observed_hash": f"{i:064x}",
            "verified_at": f"2026-05-12T0{i % 10}:00:00.000Z",
            "agent_id": "prod-ml-host-01",
            "policy_hash": "2a8e3f9d4c5b6a7e8f1d2c3b4a5e6f7d8c9b0a1e2f3d4c5b6a7e8f9d0c1b2a3e",
        }
        for i in range(n)
    ]


MERKLE_VECTORS = [
    {"vector_id": "merkle-tree-01-leaves", "description": "Single-leaf RFC 9162 tree", "n": 1},
    {"vector_id": "merkle-tree-02-leaves", "description": "Two-leaf RFC 9162 tree", "n": 2},
    {"vector_id": "merkle-tree-03-leaves", "description": "Three-leaf RFC 9162 tree (smallest odd-leaf case)", "n": 3},
    {"vector_id": "merkle-tree-07-leaves", "description": "Seven-leaf RFC 9162 tree (asymmetric subtrees)", "n": 7},
    {"vector_id": "merkle-tree-16-leaves", "description": "Sixteen-leaf RFC 9162 tree (power-of-two)", "n": 16},
    {"vector_id": "merkle-tree-1024-leaves", "description": "1024-leaf RFC 9162 tree (large case)", "n": 1024},
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path, help="where to write vector JSON files")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    for spec in ENVELOPE_VECTORS:
        vec = sign_envelope_vector(**spec)
        out = args.output_dir / f"{spec['vector_id']}.json"
        out.write_text(json.dumps(vec, indent=2, sort_keys=True) + "\n")
        written += 1
        print(f"  wrote {out.name}")

    for spec in MERKLE_VECTORS:
        leaves = make_leaves(spec["n"])
        vec = merkle_tree_vector(
            vector_id=spec["vector_id"],
            description=spec["description"],
            leaf_objects=leaves,
        )
        out = args.output_dir / f"{spec['vector_id']}.json"
        out.write_text(json.dumps(vec, indent=2, sort_keys=True) + "\n")
        written += 1
        print(f"  wrote {out.name}")

    # Empty checkpoint vector — pinned literal root from artifact.md §8.
    empty_vec = {
        "vector_id": "merkle-tree-00-leaves",
        "description": "Empty RFC 9162 tree — root is SHA-256(\"\") per spec",
        "leaf_count": 0,
        "leaves": [],
        "expected_root_hex": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "inclusion_proofs": [],
    }
    (args.output_dir / "merkle-tree-00-leaves.json").write_text(
        json.dumps(empty_vec, indent=2, sort_keys=True) + "\n"
    )
    written += 1
    print(f"  wrote merkle-tree-00-leaves.json")

    print(f"\nGenerated {written} vector(s) into {args.output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
