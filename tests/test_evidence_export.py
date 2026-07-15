"""Attested-evidence-export verification tests (evidence-export.md §5).

Mirrors the TS kernel's ``evidence-export.test.ts`` against the SAME frozen
shared golden export. The positive pins the whole §5 algorithm end to end
(wrapper sig + body_hash, source linkage, source-verdict recompute, verdict
agreement, embedded RSA-PSS attestations + operator/data_hash binding). The
per-class negatives pin exactly which exit each failure earns. The step-5 nuance
— an on-chain-dimension-only difference in the cached verdict is INFORMATIONAL
and must NOT trigger a tamper verdict — gets its own case.

The tampered-per-class inputs come from the committed v1.3 corpus vectors
(``test-vectors/evidence-export/*.json``), generated — never hand-edited — by
``tools/gen-vectors/gen_export_vectors.py``; this test drives each through the
kernel and asserts the recorded ``expected`` block reproduces exactly.
"""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from ario_proof.canonicalize import canonical_json
from ario_proof.evidence import verify_evidence_bundle

VECTORS = Path(__file__).resolve().parent.parent / "test-vectors" / "evidence-export"
GOLDEN = json.loads((VECTORS / "evidence-export-bundle.golden.json").read_text("utf-8"))
EXPORT = GOLDEN["export"]
OPERATOR_ADDRESSES = GOLDEN["operator_addresses"]


def checkpoint_bytes() -> bytes:
    cp = EXPORT["body"]["source_bundle"]["body"]["checkpoints"][0]["envelope"]
    return canonical_json(cp)


# --------------------------------------------------------------------------- #
# The positive vector
# --------------------------------------------------------------------------- #


class TestExportPositive:
    def test_fixture_signed_with_well_known_stack_seed(self) -> None:
        assert GOLDEN["seed_hex"] == (
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )

    def test_verifies_green_offline_exit_0_verdict_agrees(self) -> None:
        r = verify_evidence_bundle(EXPORT)
        assert r.status == "verified"
        assert r.body_type == "ario.evidence.export/v1"
        assert r.signature_ok and r.body_hash_ok and r.spec_version_ok
        assert r.exit_code() == 0

        e = r.export
        assert e.source_linkage_ok is True
        assert e.source_status == "verified"
        # recompute-don't-trust: the fresh verdict AGREES with the cached one over
        # the deterministic (offline-recomputable) dimensions.
        assert e.verdict_agreement_ok is True
        assert e.status == "verified"

        assert len(e.attestations) == 2
        for a in e.attestations:
            assert a.signature_ok and a.operator_address_bound and a.data_hash_bound
            assert a.checkpoint_resolved and a.ok
        assert e.attestations[0].operator == OPERATOR_ADDRESSES["op1"]
        assert e.attestations[1].operator == OPERATOR_ADDRESSES["op2"]
        # subject_ref present on att0 (well-formed, no side input) → undetermined.
        assert e.attestations[0].subject_ref_ok is None

    def test_recomputes_section4_verdict_object(self) -> None:
        r = verify_evidence_bundle(EXPORT)
        v = r.export.verdict
        assert v["schema_version"] == "ario.evidence.verdict/v1"
        # Event 0 disclosed → content_ok true; 1 & 2 undisclosed → null.
        assert [ev["content_ok"] for ev in v["events"]] == [True, None, None]
        assert all(ev["signature_ok"] and ev["inclusion_ok"] for ev in v["events"])
        # Recomputed per-attestation bindings equal the cached kernel_verdict's.
        cached = EXPORT["body"]["kernel_verdict"]["checkpoints"][0]["attestations"]
        assert v["checkpoints"][0]["attestations"] == cached
        # Offline: no gateway re-fetch → the on_chain dimension is null.
        assert v["checkpoints"][0]["on_chain"] is None

    def test_recomputed_verdict_is_byte_identical_to_the_corpus_anchor(self) -> None:
        # The v1.3 byte-agreement anchor: SHA-256(JCS(§4 verdict)). The TS kernel
        # reproduces the same hash (cross-kernel/run_export.sh).
        r = verify_evidence_bundle(EXPORT)
        digest = hashlib.sha256(canonical_json(r.export.verdict)).hexdigest()
        positive = json.loads(
            (VECTORS / "evidence-export-positive-01.json").read_text("utf-8")
        )
        assert digest == positive["expected"]["verdict_jcs_sha256"]
        assert (
            digest == "738663f32ccec765743ed7d53f79b09254af2f11656e7d9955e521c4edeab8cb"
        )


# --------------------------------------------------------------------------- #
# Per-class negatives, corpus-driven (each earns its exit)
# --------------------------------------------------------------------------- #

_CORPUS_VECTORS = sorted(
    p
    for p in VECTORS.glob("evidence-export-*.json")
    if p.name != "evidence-export-bundle.golden.json"
)


@pytest.mark.parametrize("vector_path", _CORPUS_VECTORS, ids=lambda p: p.stem)
def test_corpus_vector_reproduces_expected(vector_path: Path) -> None:
    """Every committed v1.3 export vector: the kernel reproduces its recorded
    ``expected`` block exactly (status, exit, wrapper flags, per-attestation
    bindings, and the recomputed §4 verdict hash)."""
    vec = json.loads(vector_path.read_text("utf-8"))
    exp = vec["expected"]
    r = verify_evidence_bundle(vec["bundle"])

    assert r.status == exp["status"]
    assert r.exit_code() == exp["exit_code"]
    assert r.signature_ok == exp["signature_ok"]
    assert r.body_hash_ok == exp["body_hash_ok"]

    if "attestations" in exp:
        assert r.export is not None
        assert r.export.source_linkage_ok == exp["source_linkage_ok"]
        assert r.export.verdict_agreement_ok == exp["verdict_agreement_ok"]
        assert r.export.source_status == exp["source_status"]
        got = [
            {
                "signature_ok": a.signature_ok,
                "operator_address_bound": a.operator_address_bound,
                "data_hash_bound": a.data_hash_bound,
                "checkpoint_resolved": a.checkpoint_resolved,
                "subject_ref_ok": a.subject_ref_ok,
                "ok": a.ok,
            }
            for a in r.export.attestations
        ]
        assert got == exp["attestations"]
        digest = hashlib.sha256(canonical_json(r.export.verdict)).hexdigest()
        assert digest == exp["verdict_jcs_sha256"]
    else:
        # malformed / undetermined-offline classes carry no export block.
        assert r.export is None


# --------------------------------------------------------------------------- #
# Targeted assertions mirroring the TS negatives (the load-bearing dimensions)
# --------------------------------------------------------------------------- #


def _load_tamper(name: str) -> dict:
    return json.loads((VECTORS / name).read_text("utf-8"))["bundle"]


class TestExportNegativeDimensions:
    def test_wrapper_signature_break_no_export_block(self) -> None:
        r = verify_evidence_bundle(
            _load_tamper("evidence-export-tamper-wrapper-signature.json")
        )
        assert r.status == "failed" and r.signature_ok is False
        assert r.export is None
        assert r.exit_code() == 1

    def test_source_linkage_break_wrapper_authentic(self) -> None:
        r = verify_evidence_bundle(
            _load_tamper("evidence-export-tamper-source-linkage.json")
        )
        assert r.status == "failed"
        assert r.signature_ok is True  # wrapper authentic; the LINKAGE is broken
        assert r.export.source_linkage_ok is False
        assert r.exit_code() == 1

    def test_verdict_disagreement(self) -> None:
        r = verify_evidence_bundle(
            _load_tamper("evidence-export-tamper-verdict-disagreement.json")
        )
        assert r.status == "failed"
        assert r.signature_ok is True
        assert r.export.verdict_agreement_ok is False
        assert r.exit_code() == 1

    def test_forged_attestation_signature(self) -> None:
        r = verify_evidence_bundle(
            _load_tamper("evidence-export-tamper-attestation-signature.json")
        )
        assert r.status == "failed"
        assert r.signature_ok is True
        assert r.export.attestations[0].signature_ok is False
        assert r.export.attestations[0].ok is False
        assert r.exit_code() == 1

    def test_mis_salt_rejected_by_salt32_pin(self) -> None:
        r = verify_evidence_bundle(_load_tamper("evidence-export-tamper-mis-salt.json"))
        assert r.status == "failed"
        # salt=32 verify cannot auto-detect the max-salt signature over the SAME
        # payload+key → the salt pin rejects it.
        assert r.export.attestations[0].signature_ok is False
        assert r.exit_code() == 1

    def test_operator_address_binding_break(self) -> None:
        r = verify_evidence_bundle(
            _load_tamper("evidence-export-tamper-operator-binding.json")
        )
        assert r.status == "failed"
        a = r.export.attestations[0]
        assert a.signature_ok is True  # op2 really signed it
        assert a.operator_address_bound is False  # base64url(SHA-256(op2.n)) != op1
        assert a.ok is False
        assert r.exit_code() == 1

    def test_data_hash_binding_break(self) -> None:
        r = verify_evidence_bundle(
            _load_tamper("evidence-export-tamper-data-hash-binding.json")
        )
        assert r.status == "failed"
        a = r.export.attestations[0]
        assert a.signature_ok is True
        assert a.operator_address_bound is True
        assert a.data_hash_bound is False
        assert a.ok is False
        assert r.exit_code() == 1

    def test_malformed_rsa_key_is_malformed_exit_2(self) -> None:
        r = verify_evidence_bundle(
            _load_tamper("evidence-export-malformed-rsa-key.json")
        )
        assert r.status == "malformed"
        assert r.exit_code() == 2

    def test_unsupported_signature_alg_is_malformed_exit_2(self) -> None:
        r = verify_evidence_bundle(
            _load_tamper("evidence-export-malformed-signature-alg.json")
        )
        assert r.status == "malformed"
        assert r.exit_code() == 2

    def test_source_bundle_ref_offline_is_undetermined_exit_3(self) -> None:
        r = verify_evidence_bundle(
            _load_tamper("evidence-export-source-bundle-ref.json")
        )
        assert r.status == "partial"  # bytes unavailable offline — NOT a failure
        assert r.exit_code() == 3


# --------------------------------------------------------------------------- #
# On-chain fold-in + undetermined-not-failed (§5 step-5 nuance + exit 3)
# --------------------------------------------------------------------------- #


class TestExportOnChainAndUndetermined:
    def test_on_chain_mismatch_on_refetch_exit_1(self) -> None:
        r = verify_evidence_bundle(
            EXPORT,
            gateways=["https://g.example"],
            fetch_impl=lambda _url: b'{"tampered":true}',
        )
        assert r.status == "failed"
        assert r.export.status == "failed"
        assert r.exit_code() == 1

    def test_all_unreachable_export_still_verifies_offline_exit_0(self) -> None:
        # The cached verdict carries the issuer's on-chain observation, but an
        # offline verifier does no re-fetch — the inline proofs still verify.
        r = verify_evidence_bundle(EXPORT)
        assert r.status == "verified"
        assert r.exit_code() == 0

    def test_on_chain_only_cache_difference_does_not_trigger_exit_1(self) -> None:
        # Mutate ONLY the cached on_chain block (a dimension the offline verifier
        # legitimately sees as null). Agreement compares only the deterministic
        # dimensions, so this stays verified — informational, never tamper.
        from nacl.signing import SigningKey

        sk = SigningKey(bytes.fromhex(GOLDEN["seed_hex"]))
        from ario_proof.hash import sha256_hex

        e = copy.deepcopy(EXPORT)
        cp = e["body"]["kernel_verdict"]["checkpoints"][0]
        cp["on_chain"]["on_chain_ok"] = False
        cp["on_chain"]["rollup"] = "unreachable"
        cp["on_chain"]["per_gateway"] = [
            {"gateway": "https://elsewhere.example", "outcome": "unreachable"}
        ]
        e["body_hash"] = sha256_hex(canonical_json(e["body"]))
        pre = {k: v for k, v in e.items() if k != "signature"}
        e["public_key"] = sk.verify_key.encode().hex()
        e["signature"] = sk.sign(canonical_json(pre)).signature.hex()

        r = verify_evidence_bundle(e)
        assert r.export.verdict_agreement_ok is True  # on_chain excluded from agreement
        assert r.status == "verified"
        assert r.exit_code() == 0

    def test_refetch_against_down_gateway_exit_3(self) -> None:
        def down(_url: str) -> bytes:
            raise ConnectionError("ECONNREFUSED")

        r = verify_evidence_bundle(
            EXPORT, gateways=["https://down.example"], fetch_impl=down
        )
        assert r.status == "partial"
        assert r.exit_code() == 3  # undetermined, not failed
