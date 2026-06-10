"""Inclusion-proof bundle verification tests.

The checkpoint envelope vector's ``merkle_root`` is synthetic (not derived
from the Merkle vectors), so bundles here are assembled from the real corpus
trees — every leaf, pinned audit path, and root comes from
``merkle-tree-*.json`` — wrapped in a checkpoint envelope signed with the
corpus's fixed keypair.
"""

import json
from pathlib import Path

import pytest

from ario_proof.bundle import BUNDLE_SPEC_VERSION, verify_proof_bundle
from ario_proof.envelope import sign_envelope
from ario_proof.sign import signing_key_from_seed_hex

VECTORS_DIR = Path(__file__).resolve().parent.parent / "test-vectors"
SEED_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
KEY = signing_key_from_seed_hex(SEED_HEX)

MERKLE_VECTORS = [
    json.loads(p.read_text(encoding="utf-8"))
    for p in sorted(VECTORS_DIR.glob("merkle-tree-*.json"))
    if json.loads(p.read_text(encoding="utf-8"))["leaf_count"] > 0
]


def checkpoint_envelope(merkle_root_hex: str, leaf_count: int) -> dict:
    return sign_envelope(
        {
            "spec_version": "ario.agent/v1",
            "event_id": "550e8400-e29b-41d4-a716-446655440777",
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
                "merkle_root": merkle_root_hex,
                "merkle_algorithm": "RFC9162-binary-sha256",
                "leaf_count": leaf_count,
                "outcome_summary": {
                    "verified": leaf_count,
                    "tampered": 0,
                    "unavailable": 0,
                },
                "previous_checkpoint_hash": "GENESIS",
            },
            "previous_hash": "GENESIS",
            "signed_at": "2026-05-13T00:00:01.000Z",
        },
        KEY,
    )


def bundles_for(vector: dict) -> list[dict]:
    env = checkpoint_envelope(vector["expected_root_hex"], vector["leaf_count"])
    return [
        {
            "spec_version": BUNDLE_SPEC_VERSION,
            "checkpoint_tx_id": "B" * 43,
            "checkpoint_envelope": env,
            "leaf": vector["leaves"][proof["leaf_index"]]["leaf_object"],
            "leaf_index": proof["leaf_index"],
            "audit_path": proof["audit_path_hex"],
        }
        for proof in vector["inclusion_proofs"]
    ]


@pytest.mark.parametrize("vector", MERKLE_VECTORS, ids=lambda v: v["vector_id"])
def test_corpus_derived_bundles_verify(vector: dict) -> None:
    for bundle in bundles_for(vector):
        result = verify_proof_bundle(bundle)
        assert result.ok, result.errors
        assert result.spec_version_ok
        assert result.envelope is not None and result.envelope.ok
        assert result.inclusion_ok
        assert result.errors == []


def test_wrong_leaf_fails_inclusion() -> None:
    vector = next(v for v in MERKLE_VECTORS if v["leaf_count"] == 7)
    bundle = bundles_for(vector)[0]
    bundle["leaf"] = dict(bundle["leaf"], outcome="tampered")
    result = verify_proof_bundle(bundle)
    assert not result.ok
    assert not result.inclusion_ok
    assert result.envelope is not None and result.envelope.ok  # envelope untouched


def test_wrong_leaf_index_fails_inclusion() -> None:
    vector = next(v for v in MERKLE_VECTORS if v["leaf_count"] == 16)
    bundle = bundles_for(vector)[0]
    bundle["leaf_index"] += 1
    assert not verify_proof_bundle(bundle).ok


def test_tampered_checkpoint_envelope_fails() -> None:
    vector = MERKLE_VECTORS[0]
    bundle = bundles_for(vector)[0]
    env = dict(bundle["checkpoint_envelope"])
    env["payload"] = dict(env["payload"], leaf_count=env["payload"]["leaf_count"] + 1)
    bundle["checkpoint_envelope"] = env
    result = verify_proof_bundle(bundle)
    assert not result.ok
    assert result.envelope is not None and not result.envelope.ok


def test_root_swap_fails_inclusion() -> None:
    vector = next(v for v in MERKLE_VECTORS if v["leaf_count"] == 3)
    other = next(v for v in MERKLE_VECTORS if v["leaf_count"] == 2)
    bundle = bundles_for(vector)[0]
    # Re-sign the checkpoint with a different tree's root: the envelope
    # verifies, but the audit path no longer reconstructs it.
    bundle["checkpoint_envelope"] = checkpoint_envelope(
        other["expected_root_hex"], vector["leaf_count"]
    )
    result = verify_proof_bundle(bundle)
    assert not result.ok
    assert result.envelope is not None and result.envelope.ok
    assert not result.inclusion_ok


def test_unknown_bundle_spec_version_fails_closed() -> None:
    bundle = bundles_for(MERKLE_VECTORS[0])[0]
    bundle["spec_version"] = "ario.agent.proof/v2"
    result = verify_proof_bundle(bundle)
    assert not result.ok
    assert not result.spec_version_ok


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b.pop("checkpoint_envelope"),
        lambda b: b.pop("leaf"),
        lambda b: b.pop("checkpoint_tx_id"),
        lambda b: b.update(checkpoint_tx_id=""),
        lambda b: b.update(audit_path="not-a-list"),
        lambda b: b.update(audit_path=["zz"]),
        lambda b: b.update(leaf_index="0"),
        lambda b: b.update(leaf_index=True),
    ],
)
def test_malformed_bundles_never_raise(mutate) -> None:
    bundle = bundles_for(MERKLE_VECTORS[0])[0]
    mutate(bundle)
    result = verify_proof_bundle(bundle)
    assert not result.ok
    assert result.errors


@pytest.mark.parametrize("bad", [None, 42, "bundle", [], True])
def test_non_object_bundle_never_raises(bad) -> None:
    result = verify_proof_bundle(bad)
    assert not result.ok
    assert result.errors


def test_malformed_envelope_leaf_count_rejected() -> None:
    bundle = bundles_for(MERKLE_VECTORS[0])[0]
    env = dict(bundle["checkpoint_envelope"])
    env["payload"] = dict(env["payload"])
    env["payload"]["leaf_count"] = "3"
    bundle["checkpoint_envelope"] = env
    result = verify_proof_bundle(bundle)
    assert not result.ok
