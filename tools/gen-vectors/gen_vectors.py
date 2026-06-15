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


def merkle_tree_vector(
    *, vector_id: str, description: str, leaf_objects: list[dict]
) -> dict:
    """Build a Merkle tree vector with inclusion proofs for first/last/middle leaves."""
    hashes = [leaf_hash(lo) for lo in leaf_objects]
    root = mth(hashes)
    leaves_with_hashes = [
        {"leaf_object": lo, "leaf_hash_hex": h.hex()}
        for lo, h in zip(leaf_objects, hashes)
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
    {
        "vector_id": "merkle-tree-01-leaves",
        "description": "Single-leaf RFC 9162 tree",
        "n": 1,
    },
    {
        "vector_id": "merkle-tree-02-leaves",
        "description": "Two-leaf RFC 9162 tree",
        "n": 2,
    },
    {
        "vector_id": "merkle-tree-03-leaves",
        "description": "Three-leaf RFC 9162 tree (smallest odd-leaf case)",
        "n": 3,
    },
    {
        "vector_id": "merkle-tree-07-leaves",
        "description": "Seven-leaf RFC 9162 tree (asymmetric subtrees)",
        "n": 7,
    },
    {
        "vector_id": "merkle-tree-16-leaves",
        "description": "Sixteen-leaf RFC 9162 tree (power-of-two)",
        "n": 16,
    },
    {
        "vector_id": "merkle-tree-1024-leaves",
        "description": "1024-leaf RFC 9162 tree (large case)",
        "n": 1024,
    },
]


# ---------------------------------------------------------------------------
# ario.events/v1 vectors (corpus v1.1 candidates)
#
# The Anchoring SDK profile (sibling repo ar-io-anchor,
# docs/profile-ario.events-v1.md): EXTERNAL COMMITMENT + MINIMAL disclosure.
# The committed payload is a caller-retained "event record"; the on-chain
# envelope is the bare skeleton (no event_type / subject / previous_hash /
# payload) plus the REQUIRED `environment` field and optional `payload_ref`.
#
# Written into the ario.events-v1/ SUBDIRECTORY so the v1.0 top-level set —
# and every conformance gate pinned to it — is untouched until the
# test-vectors-v1.1 tag ceremony folds these in.
# ---------------------------------------------------------------------------

EVENTS_SPEC_VERSION = "ario.events/v1"


def sign_events_envelope_vector(
    *,
    vector_id: str,
    description: str,
    event_record: dict,
    envelope_pre_signature: dict,
    seed_hex: str = FIXED_SEED_HEX,
) -> dict:
    """Compute expected outputs for an external-commitment events vector.

    Mirrors the producer steps in ar-io-anchor docs/profile-ario.events-v1.md:
      1. JCS(event_record)          -> payload_jcs_bytes   (caller retains)
      2. SHA-256(payload_jcs)       -> payload_hash
      3. skeleton + payload_hash + public_key (NO payload, NO disclosure
         fields — Minimal mode) -> JCS -> envelope_for_sig_jcs_bytes
      4. Ed25519 sign               -> signature
      5. JCS(complete envelope)     -> envelope_jcs_bytes  (the upload bytes)
    """
    seed = bytes.fromhex(seed_hex)
    sk = SigningKey(seed)
    pub_hex = sk.verify_key.encode().hex()

    payload_jcs = jcs.canonicalize(event_record)
    payload_hash = hashlib.sha256(payload_jcs).hexdigest()

    env = {k: v for k, v in envelope_pre_signature.items()}
    env["payload_hash"] = payload_hash
    env["public_key"] = pub_hex
    env.pop("signature", None)

    env_for_sig_jcs = jcs.canonicalize(env)
    signature = sk.sign(env_for_sig_jcs).signature.hex()

    complete = {k: v for k, v in env.items()}
    complete["signature"] = signature
    envelope_jcs = jcs.canonicalize(complete)

    return {
        "vector_id": vector_id,
        "description": description,
        "spec_version": EVENTS_SPEC_VERSION,
        "profile": {"payload_mode": "external_commitment", "disclosure": "minimal"},
        "fixed_keypair": {
            "ed25519_seed_hex": seed_hex,
            "ed25519_public_hex": pub_hex,
        },
        "inputs": {
            "event_record": event_record,
            "envelope_pre_signature": envelope_pre_signature,
        },
        "expected_outputs": {
            "payload_jcs_bytes_hex": payload_jcs.hex(),
            "payload_hash_hex": payload_hash,
            "envelope_for_sig_jcs_bytes_hex": env_for_sig_jcs.hex(),
            "signature_hex": signature,
            "envelope_jcs_bytes_hex": envelope_jcs.hex(),
        },
    }


def events_vectors() -> list[dict]:
    """Build the ario.events/v1 vector set (deterministic, chained)."""
    subject = {"type": "producer", "producer_id": "acme-app"}

    # --- events-event-01: unchained single-shot, dev, payload_ref + metadata.
    content_1 = b"hello world"
    record_1 = {
        "payload_version": 1,
        "spec_version": EVENTS_SPEC_VERSION,
        "event_type": "event",
        "subject": subject,
        "previous_hash": "GENESIS",
        "event": {
            "content_hash": hashlib.sha256(content_1).hexdigest(),
            "content_length": len(content_1),
            "ref": "s3://demo-bucket/hello.txt",
        },
        "context": {},
        "metadata": {"approver": "alice", "note": "first anchor — ünïcode ✓"},
        "extras": {},
    }
    vec_1 = sign_events_envelope_vector(
        vector_id="events-event-01",
        description=(
            "Unchained ario.events/v1 event: Minimal-mode skeleton envelope, "
            "external-commitment record with caller metadata (JCS unicode "
            "exercise), payload_ref locator, environment=dev"
        ),
        event_record=record_1,
        envelope_pre_signature={
            "spec_version": EVENTS_SPEC_VERSION,
            "event_id": "1f0e9a4c-3b2d-4d5e-8f6a-7b8c9d0e1f2a",
            "signed_at": "2026-06-11T00:00:00.000Z",
            "environment": "dev",
            "payload_ref": "s3://demo-bucket/hello.txt.provenance.json",
        },
    )

    # --- events-event-02: chained to record 1, production, no optionals.
    content_2 = b"hello again"
    record_2 = {
        "payload_version": 1,
        "spec_version": EVENTS_SPEC_VERSION,
        "event_type": "s3.object_stored",
        "subject": subject,
        "previous_hash": vec_1["expected_outputs"]["payload_hash_hex"],
        "event": {
            "content_hash": hashlib.sha256(content_2).hexdigest(),
            "content_length": len(content_2),
        },
        "context": {"chain_key": "orders"},
        "metadata": {},
        "extras": {},
    }
    vec_2 = sign_events_envelope_vector(
        vector_id="events-event-02",
        description=(
            "Chained ario.events/v1 event (adapter-namespaced type): "
            "previous_hash links to events-event-01 record, chain_key in "
            "context, environment=production, no optional envelope fields"
        ),
        event_record=record_2,
        envelope_pre_signature={
            "spec_version": EVENTS_SPEC_VERSION,
            "event_id": "2a1b3c4d-5e6f-4a7b-9c8d-0e1f2a3b4c5d",
            "signed_at": "2026-06-11T00:01:00.000Z",
            "environment": "production",
        },
    )

    # --- events-checkpoint-01: three leaf envelopes -> RFC 9162 tree ->
    # checkpoint record + envelope. Leaf = leaf_hash over the COMPLETE signed
    # leaf envelope (JCS bytes), committing to the signature too.
    leaf_envelopes = []
    leaf_vectors = []
    for i in range(3):
        content = f"leaf-{i}".encode()
        record = {
            "payload_version": 1,
            "spec_version": EVENTS_SPEC_VERSION,
            "event_type": "event",
            "subject": subject,
            "previous_hash": "GENESIS",
            "event": {
                "content_hash": hashlib.sha256(content).hexdigest(),
                "content_length": len(content),
            },
            "context": {},
            "metadata": {},
            "extras": {},
        }
        vec = sign_events_envelope_vector(
            vector_id=f"events-checkpoint-01-leaf-{i}",
            description=f"checkpoint leaf {i} (not written standalone)",
            event_record=record,
            envelope_pre_signature={
                "spec_version": EVENTS_SPEC_VERSION,
                "event_id": f"3b2c4d5e-6f7a-4b8c-8d9e-{i:012d}",
                "signed_at": f"2026-06-11T00:02:0{i}.000Z",
                "environment": "dev",
            },
        )
        envelope = dict(vec["inputs"]["envelope_pre_signature"])
        envelope["payload_hash"] = vec["expected_outputs"]["payload_hash_hex"]
        envelope["public_key"] = vec["fixed_keypair"]["ed25519_public_hex"]
        envelope["signature"] = vec["expected_outputs"]["signature_hex"]
        leaf_envelopes.append(envelope)
        leaf_vectors.append(vec)

    hashes = [leaf_hash(env) for env in leaf_envelopes]
    root = mth(hashes)

    checkpoint_record = {
        "payload_version": 1,
        "spec_version": EVENTS_SPEC_VERSION,
        "event_type": "checkpoint",
        "subject": subject,
        "previous_hash": "GENESIS",
        "event": {
            "merkle_root": root.hex(),
            "leaf_count": len(leaf_envelopes),
            "window": {
                "start": "2026-06-11T00:02:00.000Z",
                "end": "2026-06-11T00:03:00.000Z",
            },
        },
        "context": {"chain_key": "batcher:demo"},
        "metadata": {},
        "extras": {},
    }
    checkpoint_vec = sign_events_envelope_vector(
        vector_id="events-checkpoint-01",
        description=(
            "ario.events/v1 Merkle checkpoint: three signed leaf envelopes, "
            "RFC 9162 leaf hashes over the complete leaf-envelope JCS bytes, "
            "root committed in the checkpoint record, inclusion proofs for "
            "every leaf"
        ),
        event_record=checkpoint_record,
        envelope_pre_signature={
            "spec_version": EVENTS_SPEC_VERSION,
            "event_id": "4c3d5e6f-7a8b-4c9d-a0e1-f2a3b4c5d6e7",
            "signed_at": "2026-06-11T00:03:00.500Z",
            "environment": "dev",
        },
    )
    checkpoint_vec["merkle"] = {
        "leaves": [
            {
                "event_record": leaf_vectors[i]["inputs"]["event_record"],
                "envelope": leaf_envelopes[i],
                "envelope_jcs_bytes_hex": leaf_vectors[i]["expected_outputs"][
                    "envelope_jcs_bytes_hex"
                ],
                "leaf_hash_hex": hashes[i].hex(),
            }
            for i in range(3)
        ],
        "expected_root_hex": root.hex(),
        "inclusion_proofs": [
            {
                "leaf_index": i,
                "audit_path_hex": [h.hex() for h in audit_path(i, hashes)],
            }
            for i in range(3)
        ],
    }

    return [vec_1, vec_2, checkpoint_vec]


# ---------------------------------------------------------------------------
# test-vectors-v1.2 additive candidates (kernel-ratification lane, Scope D)
#
# These do NOT alter any existing vector's bytes (the v1.1 set is pinned). Two
# new artifacts:
#   - events-checkpoint-chain-01: per-batcher checkpoint CONTINUITY across two
#     windows — window-2's checkpoint record previous_hash = SHA-256(JCS(
#     window-1 checkpoint record)). events-checkpoint-01 pins a single window;
#     this pins the chain link the batcher draws between windows.
#   - negatives/: inputs a conformant verifier MUST REJECT — malformed
#     spec_version minor (#13), lone UTF-16 surrogate (JCS reject-only), and a
#     missing payload_hash (envelope-spec §2). A new corpus category; each
#     carries the complete envelope BYTES + the expected rejection.
# ---------------------------------------------------------------------------


def _checkpoint_over(
    *,
    vector_id,
    leaf_contents,
    previous_hash,
    chain_key,
    base_event_id,
    signed_at,
    window,
):
    """Build a checkpoint vector over leaf_contents, chaining to previous_hash.

    Returns the sign_events vector with a ``merkle`` block (leaves, root,
    inclusion proofs) — identical construction to events-checkpoint-01, but
    parameterized by previous_hash + chain_key so two windows can chain.
    """
    subject = {"type": "producer", "producer_id": "acme-app"}
    leaf_envelopes, leaf_vectors = [], []
    for i, content in enumerate(leaf_contents):
        record = {
            "payload_version": 1,
            "spec_version": EVENTS_SPEC_VERSION,
            "event_type": "event",
            "subject": subject,
            "previous_hash": "GENESIS",
            "event": {
                "content_hash": hashlib.sha256(content).hexdigest(),
                "content_length": len(content),
            },
            "context": {},
            "metadata": {},
            "extras": {},
        }
        vec = sign_events_envelope_vector(
            vector_id=f"{vector_id}-leaf-{i}",
            description=f"{vector_id} leaf {i} (not written standalone)",
            event_record=record,
            envelope_pre_signature={
                "spec_version": EVENTS_SPEC_VERSION,
                "event_id": f"{base_event_id}{i:04d}",
                "signed_at": signed_at,
                "environment": "dev",
            },
        )
        env = dict(vec["inputs"]["envelope_pre_signature"])
        env["payload_hash"] = vec["expected_outputs"]["payload_hash_hex"]
        env["public_key"] = vec["fixed_keypair"]["ed25519_public_hex"]
        env["signature"] = vec["expected_outputs"]["signature_hex"]
        leaf_envelopes.append(env)
        leaf_vectors.append(vec)

    hashes = [leaf_hash(e) for e in leaf_envelopes]
    root = mth(hashes)
    checkpoint_record = {
        "payload_version": 1,
        "spec_version": EVENTS_SPEC_VERSION,
        "event_type": "checkpoint",
        "subject": subject,
        "previous_hash": previous_hash,
        "event": {
            "merkle_root": root.hex(),
            "leaf_count": len(leaf_envelopes),
            "window": window,
        },
        "context": {"chain_key": chain_key},
        "metadata": {},
        "extras": {},
    }
    cp = sign_events_envelope_vector(
        vector_id=vector_id,
        description=f"{vector_id} checkpoint over {len(leaf_contents)} leaves",
        event_record=checkpoint_record,
        envelope_pre_signature={
            "spec_version": EVENTS_SPEC_VERSION,
            "event_id": base_event_id + "ffff",
            "signed_at": signed_at,
            "environment": "dev",
        },
    )
    cp["merkle"] = {
        "leaves": [
            {
                "envelope_jcs_bytes_hex": leaf_vectors[i]["expected_outputs"][
                    "envelope_jcs_bytes_hex"
                ],
                "leaf_hash_hex": hashes[i].hex(),
            }
            for i in range(len(leaf_contents))
        ],
        "expected_root_hex": root.hex(),
        "inclusion_proofs": [
            {
                "leaf_index": i,
                "audit_path_hex": [h.hex() for h in audit_path(i, hashes)],
            }
            for i in range(len(leaf_contents))
        ],
    }
    return cp


def events_checkpoint_chain_vector() -> dict:
    """Two chained checkpoints: window-2.previous_hash = window-1 record hash."""
    chain_key = "batcher:chain-demo"
    w1 = _checkpoint_over(
        vector_id="events-checkpoint-chain-01-w1",
        leaf_contents=[b"w1-leaf-0", b"w1-leaf-1"],
        previous_hash="GENESIS",
        chain_key=chain_key,
        base_event_id="5c6d7e8f-0a1b-4c2d-8e3f-",
        signed_at="2026-06-15T00:00:00.000Z",
        window={"start": "2026-06-15T00:00:00.000Z", "end": "2026-06-15T00:01:00.000Z"},
    )
    w1_record_hash = w1["expected_outputs"]["payload_hash_hex"]
    w2 = _checkpoint_over(
        vector_id="events-checkpoint-chain-01-w2",
        leaf_contents=[b"w2-leaf-0", b"w2-leaf-1", b"w2-leaf-2"],
        previous_hash=w1_record_hash,  # the chain link being pinned
        chain_key=chain_key,
        base_event_id="6d7e8f90-1b2c-4d3e-9f4a-",
        signed_at="2026-06-15T00:01:30.000Z",
        window={"start": "2026-06-15T00:01:00.000Z", "end": "2026-06-15T00:02:00.000Z"},
    )
    return {
        "vector_id": "events-checkpoint-chain-01",
        "description": (
            "ario.events/v1 per-batcher checkpoint continuity: two windows on "
            "one chain_key; window-2's checkpoint record previous_hash equals "
            "SHA-256(JCS(window-1 checkpoint record)). Each checkpoint is a "
            "complete signed envelope verifiable through verifyEnvelope."
        ),
        "spec_version": EVENTS_SPEC_VERSION,
        "profile": {"payload_mode": "external_commitment", "disclosure": "minimal"},
        "fixed_keypair": w1["fixed_keypair"],
        "chain_key": chain_key,
        "windows": [w1, w2],
        "chain_link": {
            "window1_record_hash": w1_record_hash,
            "window2_previous_hash": w2["inputs"]["event_record"]["previous_hash"],
        },
    }


def negative_vectors() -> list[dict]:
    """Inputs a conformant verifier MUST reject. Each carries the complete
    envelope BYTES (hex) + the expected rejection; the conformance gate parses
    and verifies the bytes and asserts the envelope does NOT verify."""
    seed = bytes.fromhex(FIXED_SEED_HEX)
    sk = SigningKey(seed)
    pub_hex = sk.verify_key.encode().hex()
    record = {"k": "v"}
    record_hash = hashlib.sha256(jcs.canonicalize(record)).hexdigest()

    def signed_bytes(env_no_sig: dict) -> bytes:
        env = dict(env_no_sig)
        env["payload_hash"] = record_hash
        env["public_key"] = pub_hex
        sig = sk.sign(jcs.canonicalize(env)).signature.hex()
        env["signature"] = sig
        return jcs.canonicalize(env)

    negatives = []

    # 1. malformed spec_version minor (#13) — otherwise a valid signature.
    for i, bad in enumerate(
        ["ario.agent/v1.x", "ario.agent/v1.3abc", "ario.agent/v1."]
    ):
        b = signed_bytes(
            {
                "spec_version": bad,
                "event_id": "1f0e9a4c-3b2d-4d5e-8f6a-7b8c9d0e1f2a",
                "signed_at": "2026-06-15T00:00:00Z",
            }
        )
        negatives.append(
            {
                "vector_id": f"negative-malformed-minor-{i:02d}",
                "description": f"spec_version {bad!r}: non-numeric/empty minor token is malformed (#13)",
                "category": "spec_version",
                "envelope_bytes_hex": b.hex(),
                "expect": {"accepts": False, "reason": "unsupported_spec_version"},
            }
        )

    # 2. lone UTF-16 surrogate in a string field (JCS reject-only). Built as
    #    raw bytes: a JSON document whose signed_at carries a \uD800 escape.
    #    (Signature validity is moot — a conformant verifier rejects at the
    #    JCS/parse layer before trusting any field.)
    base = {
        "spec_version": "ario.agent/v1",
        "event_id": "1f0e9a4c-3b2d-4d5e-8f6a-7b8c9d0e1f2a",
        "payload_hash": record_hash,
        "public_key": pub_hex,
        "signature": "00" * 64,
    }
    # canonicalize the non-surrogate skeleton, then splice a lone-surrogate
    # field in as raw JSON text so the byte stream contains \uD800.
    body = jcs.canonicalize(base).decode("ascii")
    assert body.endswith("}")
    lone = body[:-1] + ',"signed_at":"2026-06-15T00:00:00Z \\uD800"}'
    negatives.append(
        {
            "vector_id": "negative-lone-surrogate-00",
            "description": "lone high surrogate \\uD800 in a string field: not representable as UTF-8; reject at JCS/parse",
            "category": "encoding",
            "envelope_bytes_hex": lone.encode("ascii").hex(),
            "expect": {"accepts": False, "reason": "lone_surrogate"},
        }
    )

    # 3. missing payload_hash (envelope-spec §2) — valid signature over the
    #    payload_hash-less scope.
    env = {
        "spec_version": "ario.agent/v1",
        "event_id": "1f0e9a4c-3b2d-4d5e-8f6a-7b8c9d0e1f2a",
        "signed_at": "2026-06-15T00:00:00Z",
        "public_key": pub_hex,
    }
    sig = sk.sign(jcs.canonicalize(env)).signature.hex()
    env["signature"] = sig
    negatives.append(
        {
            "vector_id": "negative-missing-payload-hash-00",
            "description": "no payload_hash field: §2 requires it; hard reject in every mode",
            "category": "payload_hash",
            "envelope_bytes_hex": jcs.canonicalize(env).hex(),
            "expect": {"accepts": False, "reason": "missing_payload_hash"},
        }
    )
    return negatives


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output_dir", type=Path, help="where to write vector JSON files"
    )
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    for spec in ENVELOPE_VECTORS:
        vec = sign_envelope_vector(**spec)
        out = args.output_dir / f"{spec['vector_id']}.json"
        out.write_text(json.dumps(vec, indent=2, sort_keys=True) + "\n")
        written += 1
        print(f"  wrote {out.name}")

    events_dir = args.output_dir / "ario.events-v1"
    events_dir.mkdir(parents=True, exist_ok=True)
    for vec in events_vectors():
        out = events_dir / f"{vec['vector_id']}.json"
        out.write_text(json.dumps(vec, indent=2, sort_keys=True) + "\n")
        written += 1
        print(f"  wrote ario.events-v1/{out.name}")

    # test-vectors-v1.2 additive: chained two-checkpoint vector.
    chain_vec = events_checkpoint_chain_vector()
    chain_out = events_dir / f"{chain_vec['vector_id']}.json"
    chain_out.write_text(json.dumps(chain_vec, indent=2, sort_keys=True) + "\n")
    written += 1
    print(f"  wrote ario.events-v1/{chain_out.name}")

    # test-vectors-v1.2 additive: negative vectors (must-reject inputs).
    negatives_dir = args.output_dir / "negatives"
    negatives_dir.mkdir(parents=True, exist_ok=True)
    for vec in negative_vectors():
        out = negatives_dir / f"{vec['vector_id']}.json"
        out.write_text(json.dumps(vec, indent=2, sort_keys=True) + "\n")
        written += 1
        print(f"  wrote negatives/{out.name}")

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
        "description": 'Empty RFC 9162 tree — root is SHA-256("") per spec',
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
