"""Unit tests for envelope verification — both profiles, negatives, edges.

The agent-profile positive path is exercised exhaustively by
``test_conformance.py``; this file covers the behaviors the v1.0 corpus
cannot: the mlflow (external-commitment) profile, the reserved
``co_signatures`` signed-scope exclusion, underscore-key stripping, legacy
envelopes, and adversarial input.
"""

import pytest

from ario_proof.canonicalize import canonical_json
from ario_proof.envelope import (
    content_hashes,
    envelope_for_signature,
    sign_envelope,
    spec_version_supported,
    verify_envelope,
)
from ario_proof.hash import sha256_hex
from ario_proof.sign import signing_key_from_seed_hex

KEY = signing_key_from_seed_hex("11" * 32)


def agent_envelope() -> dict:
    return sign_envelope(
        {
            "spec_version": "ario.agent/v1",
            "event_id": "550e8400-e29b-41d4-a716-446655440000",
            "event_type": "asset_registered",
            "subject": {"type": "agent", "tenant_id": "t", "agent_id": "a"},
            "payload": {"asset": {"asset_id": "x"}, "hash": "ab" * 32},
            "previous_hash": "GENESIS",
            "signed_at": "2026-06-10T00:00:00.000Z",
        },
        KEY,
    )


def mlflow_envelope(payload_bytes: bytes) -> dict:
    return sign_envelope(
        {
            "spec_version": "ario.mlflow/v1",
            "event_id": "550e8400-e29b-41d4-a716-446655440001",
            "event_type": "training_complete",
            "subject": {"type": "mlflow_run", "run_id": "r1"},
            "payload_hash": sha256_hex(payload_bytes),
            "previous_hash": "GENESIS",
            "signed_at": "2026-06-10T00:00:00.000Z",
        },
        KEY,
    )


# ---------------------------------------------------------------- profiles


def test_agent_profile_inline_binding_verifies() -> None:
    result = verify_envelope(agent_envelope())
    assert result.ok
    assert result.spec_version_ok and result.signature_ok
    assert result.payload_hash_ok is True
    assert result.legacy_envelope is False
    assert result.errors == []


def test_mlflow_profile_external_binding_verifies() -> None:
    committed = canonical_json({"metrics": {"acc": 0.91}})
    env = mlflow_envelope(committed)
    result = verify_envelope(env, payload_bytes=committed)
    assert result.ok
    assert result.payload_hash_ok is True


def test_mlflow_profile_wrong_bytes_fail_binding() -> None:
    committed = canonical_json({"metrics": {"acc": 0.91}})
    env = mlflow_envelope(committed)
    result = verify_envelope(env, payload_bytes=b"tampered")
    assert not result.ok
    assert result.payload_hash_ok is False
    assert result.signature_ok  # signature itself is intact


def test_commitment_only_verification_leaves_binding_unchecked() -> None:
    env = mlflow_envelope(canonical_json({"metrics": {"acc": 0.91}}))
    result = verify_envelope(env)
    assert result.ok
    assert result.payload_hash_ok is None


def test_inline_and_external_must_both_match_when_both_given() -> None:
    env = agent_envelope()
    good = canonical_json(env["payload"])
    assert verify_envelope(env, payload_bytes=good).payload_hash_ok is True
    assert verify_envelope(env, payload_bytes=b"x").payload_hash_ok is False


# ------------------------------------------------------------ signed scope


def test_co_signatures_is_outside_the_signed_scope() -> None:
    # envelope-spec.md v1.0 §7.1: co_signatures is reserved and excluded
    # from the signed scope from day one. The v1.0 corpus has no co-signed
    # vectors, so this unit test is the only guard — do not remove it.
    env = agent_envelope()
    env["co_signatures"] = [{"public_key": "00" * 32, "signature": "00" * 64}]
    assert "co_signatures" not in envelope_for_signature(env)
    assert verify_envelope(env).ok


def test_mlflow_underscore_annotations_are_outside_the_signed_scope() -> None:
    # mlflow convention: _* keys are unsigned routing metadata, attachable
    # after signing without breaking verification.
    env = mlflow_envelope(b"bytes")
    env["_tx_id"] = "some-arweave-tx"
    assert "_tx_id" not in envelope_for_signature(env)
    assert verify_envelope(env).ok


def test_agent_underscore_keys_are_inside_the_signed_scope() -> None:
    # The agent profile has no annotation convention — its signed scope is
    # minus signature/co_signatures ONLY, matching the Go reference. An
    # injected _* key is unsigned-field injection and must fail. The corpus
    # cannot catch this (no vector carries _* keys) — same class as the
    # co_signatures gotcha above; do not remove this test.
    env = agent_envelope()
    env["_injected"] = "x"
    assert "_injected" in envelope_for_signature(env)
    result = verify_envelope(env)
    assert not result.ok
    assert not result.signature_ok


def test_legacy_underscore_annotations_are_outside_the_signed_scope() -> None:
    pre = {
        "event_id": "550e8400-e29b-41d4-a716-446655440002",
        "payload_hash": sha256_hex(b"bytes"),
        "previous_hash": "GENESIS",
    }
    env = sign_envelope(pre, KEY)
    env["_tx_id"] = "some-arweave-tx"
    assert verify_envelope(env, allow_legacy=True).ok


def test_sign_side_agent_underscore_key_is_signed() -> None:
    # Signing an agent envelope that contains a _* key signs it like any
    # other field: it verifies as-signed, and removing it afterwards breaks
    # the signature (Go would behave identically).
    pre = {
        "spec_version": "ario.agent/v1",
        "event_id": "550e8400-e29b-41d4-a716-446655440003",
        "event_type": "asset_registered",
        "subject": {"type": "agent", "tenant_id": "t", "agent_id": "a"},
        "payload": {"asset": {"asset_id": "x"}, "hash": "ab" * 32},
        "previous_hash": "GENESIS",
        "signed_at": "2026-06-10T00:00:00.000Z",
        "_note": "inside the signed scope",
    }
    env = sign_envelope(pre, KEY)
    assert verify_envelope(env).ok
    del env["_note"]
    assert not verify_envelope(env).signature_ok


def test_sign_side_mlflow_underscore_key_is_not_signed() -> None:
    pre = {
        "spec_version": "ario.mlflow/v1",
        "event_id": "550e8400-e29b-41d4-a716-446655440004",
        "payload_hash": sha256_hex(b"bytes"),
        "previous_hash": "GENESIS",
        "_note": "outside the signed scope",
    }
    env = sign_envelope(pre, KEY)
    assert verify_envelope(env).ok
    del env["_note"]  # annotations can be dropped or rewritten freely
    assert verify_envelope(env).ok


def test_any_signed_field_mutation_breaks_the_signature() -> None:
    env = agent_envelope()
    env["event_id"] = "550e8400-e29b-41d4-a716-446655449999"
    result = verify_envelope(env)
    assert not result.ok
    assert not result.signature_ok


def test_payload_mutation_breaks_binding_and_signature() -> None:
    env = agent_envelope()
    env["payload"] = dict(env["payload"], hash="cd" * 32)
    result = verify_envelope(env)
    assert not result.ok
    assert result.payload_hash_ok is False
    assert not result.signature_ok


# ------------------------------------------------------- spec_version gate


def test_spec_version_registry() -> None:
    assert spec_version_supported("ario.agent/v1")
    assert spec_version_supported("ario.mlflow/v1")
    assert not spec_version_supported("ario.agent/v2")
    assert not spec_version_supported("ario.governance/v1")
    assert not spec_version_supported(None)


def test_spec_version_accepts_additive_minor_within_major() -> None:
    # envelope-spec v1.1 §2: matching is on the v<major> token boundary, so
    # a v1 verifier accepts additive minors (issue #1; mirrors Go pkg/proof
    # and TS @ar-io/proof).
    assert spec_version_supported("ario.agent/v1.3")
    assert spec_version_supported("ario.mlflow/v1.12")


def test_spec_version_rejects_different_major_sharing_digit_prefix() -> None:
    # "ario.agent/v10" starts with "ario.agent/v1" as a string but is major
    # 10 — the token boundary (the dot) is what separates these.
    assert not spec_version_supported("ario.agent/v10")
    assert not spec_version_supported("ario.mlflow/v11.2")


def test_spec_version_rejects_malformed_minor() -> None:
    # Grammar is <namespace>/v<major>[.<minor>] with numeric minor —
    # anything else is malformed and fails closed.
    assert not spec_version_supported("ario.agent/v1.x")
    assert not spec_version_supported("ario.agent/v1.")
    assert not spec_version_supported("ario.agent/v1.3.2")
    assert not spec_version_supported("ario.agent/v1.3x")


def test_minor_suffixed_envelope_verifies_end_to_end() -> None:
    pre = {
        "spec_version": "ario.agent/v1.3",
        "event_id": "550e8400-e29b-41d4-a716-446655440005",
        "event_type": "asset_registered",
        "subject": {"type": "agent", "tenant_id": "t", "agent_id": "a"},
        "payload": {"asset": {"asset_id": "x"}, "hash": "ab" * 32},
        "previous_hash": "GENESIS",
        "signed_at": "2026-06-11T00:00:00.000Z",
    }
    result = verify_envelope(sign_envelope(pre, KEY))
    assert result.ok
    assert result.spec_version_ok


def test_minor_suffixed_mlflow_keeps_annotation_strip() -> None:
    # The profile-conditional _* strip is also major-token-based: an
    # ario.mlflow/v1.2 envelope is still the mlflow profile.
    pre = {
        "spec_version": "ario.mlflow/v1.2",
        "event_id": "550e8400-e29b-41d4-a716-446655440006",
        "payload_hash": sha256_hex(b"bytes"),
        "previous_hash": "GENESIS",
    }
    env = sign_envelope(pre, KEY)
    env["_tx_id"] = "annotation"
    assert "_tx_id" not in envelope_for_signature(env)
    assert verify_envelope(env).ok


def test_unknown_spec_version_fails_closed() -> None:
    env = agent_envelope()
    env["spec_version"] = "ario.agent/v2"
    result = verify_envelope(env)
    assert not result.ok
    assert not result.spec_version_ok
    assert not result.signature_ok  # spec_version is inside the signed scope


def test_legacy_envelope_fails_closed_by_default() -> None:
    env = dict(mlflow_envelope(b"bytes"))
    del env["spec_version"]
    env = sign_envelope({k: v for k, v in env.items() if k != "signature"}, KEY)
    result = verify_envelope(env)
    assert not result.ok and result.legacy_envelope

    accepted = verify_envelope(env, allow_legacy=True)
    assert accepted.ok and accepted.legacy_envelope


# ------------------------------------------------------------ content bind


def test_content_bind_matches_registered_asset_hash() -> None:
    env = agent_envelope()
    result = verify_envelope(env, expected_content_hash=("AB" * 32))
    assert result.ok
    assert result.content_hash_ok is True
    assert result.content_role == "asset"


def test_content_bind_mismatch_reports_false_but_keeps_crypto_verdict() -> None:
    env = agent_envelope()
    result = verify_envelope(env, expected_content_hash="ff" * 32)
    assert result.ok  # crypto is valid; the bind failed
    assert result.content_hash_ok is False
    assert result.content_role is None


def test_content_hashes_tamper_detected_yields_observed_and_baseline() -> None:
    env = {
        "event_type": "tamper_detected",
        "payload": {"observed": {"hash": "aa" * 32}, "baseline": {"hash": "bb" * 32}},
    }
    assert content_hashes(env) == [("observed", "aa" * 32), ("baseline", "bb" * 32)]


# ------------------------------------------------------- adversarial input


@pytest.mark.parametrize("bad", [None, 42, "envelope", [], [{}], True])
def test_non_object_input_never_raises(bad) -> None:
    result = verify_envelope(bad)
    assert not result.ok
    assert result.errors


def test_missing_fields_never_raise() -> None:
    result = verify_envelope({})
    assert not result.ok
    assert not result.spec_version_ok
    assert not result.signature_ok
    # envelope-spec §2: a missing payload_hash is a hard reject, not undetermined.
    assert result.payload_hash_ok is False


def test_missing_payload_hash_is_rejected() -> None:
    # A signed external-commitment-shaped envelope that omits payload_hash
    # must fail the binding (§2), independent of the signature.
    env = agent_envelope()
    env.pop("payload", None)
    env.pop("payload_hash", None)
    result = verify_envelope(env)
    assert result.payload_hash_ok is False
    assert not result.ok
    assert any("payload_hash" in e for e in result.errors)


def test_unserializable_payload_never_raises() -> None:
    env = agent_envelope()
    env["payload"] = {"f": float("inf")}
    result = verify_envelope(env)
    assert not result.ok
    assert result.payload_hash_ok is False


# ---------------------------------------------------------------- sign side


def test_sign_envelope_rejects_double_signing() -> None:
    with pytest.raises(ValueError):
        sign_envelope(agent_envelope(), KEY)


def test_sign_envelope_rejects_stale_payload_hash() -> None:
    with pytest.raises(ValueError):
        sign_envelope(
            {
                "spec_version": "ario.agent/v1",
                "payload": {"a": 1},
                "payload_hash": "00" * 32,
            },
            KEY,
        )


def test_sign_envelope_rejects_foreign_public_key() -> None:
    with pytest.raises(ValueError):
        sign_envelope(
            {
                "spec_version": "ario.mlflow/v1",
                "payload_hash": "00" * 32,
                "public_key": "11" * 32,
            },
            KEY,
        )


def test_sign_envelope_requires_some_binding() -> None:
    with pytest.raises(ValueError):
        sign_envelope({"spec_version": "ario.mlflow/v1"}, KEY)


def test_sign_envelope_does_not_mutate_input() -> None:
    pre = {
        "spec_version": "ario.mlflow/v1",
        "payload_hash": sha256_hex(b"bytes"),
        "previous_hash": "GENESIS",
    }
    snapshot = dict(pre)
    sign_envelope(pre, KEY)
    assert pre == snapshot
