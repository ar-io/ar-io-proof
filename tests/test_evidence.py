"""ario.evidence/v1 + ario.anchor.trace/v1 verification tests.

Exercises the evidence-bundle verifier over a REAL anchor-trace bundle — the
inline source bundle of the frozen shared golden export (3 events, one disclosing
its raw log → content_ok:true, a 1-checkpoint RFC 9162 merkle window), plus the
on-chain re-fetch (§4.2) via an injected fetch seam, and the tamper discipline:
a tampered copy of the SAME bytes fails. Mirrors the TS ``evidence-golden.test.ts``.
"""

import copy
import json
from pathlib import Path

from nacl.signing import SigningKey

from ario_proof.canonicalize import canonical_json
from ario_proof.evidence import verify_evidence_bundle
from ario_proof.hash import sha256_hex

GOLDEN = (
    Path(__file__).resolve().parent.parent
    / "test-vectors"
    / "evidence-export"
    / "evidence-export-bundle.golden.json"
)
FIXTURE = json.loads(GOLDEN.read_text(encoding="utf-8"))
SEED_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
SK = SigningKey(bytes.fromhex(SEED_HEX))


def anchor_trace_bundle() -> dict:
    """The export's inline source bundle is a complete standalone
    ario.anchor.trace/v1 bundle."""
    return copy.deepcopy(FIXTURE["export"]["body"]["source_bundle"])


def re_sign_wrapper(bundle: dict) -> None:
    bundle["body_hash"] = sha256_hex(canonical_json(bundle["body"]))
    pre = {k: v for k, v in bundle.items() if k != "signature"}
    bundle["public_key"] = SK.verify_key.encode().hex()
    bundle["signature"] = SK.sign(canonical_json(pre)).signature.hex()


def flip(hex_str: str) -> str:
    return hex_str[:-1] + ("1" if hex_str.endswith("0") else "0")


class TestAnchorTraceGreen:
    def test_committed_bundle_verifies_fully_green(self) -> None:
        r = verify_evidence_bundle(anchor_trace_bundle())
        assert r.status == "verified"
        assert r.spec_version_ok and r.signature_ok and r.body_hash_ok
        assert r.body_type == "ario.anchor.trace/v1"
        assert len(r.checkpoints) > 0 and all(c.ok for c in r.checkpoints)
        assert len(r.events) > 0 and all(e.ok for e in r.events)
        # The real producer disclosed every record → every binding is determined.
        assert all(e.payload_binding_ok is True for e in r.events)
        assert r.exit_code() == 0

    def test_asserted_verdict_surfaced_and_matches_recompute(self) -> None:
        r = verify_evidence_bundle(anchor_trace_bundle())
        assert r.asserted_status == "verified"
        assert r.status == "verified"

    def test_disclosed_event_binds_content_ok_true_others_null(self) -> None:
        r = verify_evidence_bundle(anchor_trace_bundle())
        assert r.events[0].content_ok is True  # disclosed in-body
        assert r.events[1].content_ok is None  # undisclosed → undetermined
        assert r.events[2].content_ok is None
        assert r.status == "verified"


class TestAnchorTraceTamper:
    def test_flipping_record_bytes_fails_event_and_rollup(self) -> None:
        b = anchor_trace_bundle()
        b["body"]["events"][0]["record_bytes"] = flip(
            b["body"]["events"][0]["record_bytes"]
        )
        # No wrapper re-sign: verbatim-bytes tamper an auditor would see.
        r = verify_evidence_bundle(b)
        assert r.status == "failed"
        assert r.body_hash_ok is False
        assert r.signature_ok is False

    def test_forging_wrapper_signature_is_hard_failure(self) -> None:
        b = anchor_trace_bundle()
        b["signature"] = flip(b["signature"])
        r = verify_evidence_bundle(b)
        assert r.status == "failed"
        assert r.signature_ok is False
        assert len(r.checkpoints) == 0  # do not verify a body under a broken wrapper

    def test_tampering_body_hash_alone_is_caught(self) -> None:
        b = anchor_trace_bundle()
        b["body_hash"] = flip(b["body_hash"])
        r = verify_evidence_bundle(b)
        assert r.status == "failed"
        assert r.body_hash_ok is False

    def test_flipping_audit_path_breaks_inclusion(self) -> None:
        b = anchor_trace_bundle()
        incl = b["body"]["events"][1]["inclusion"]
        assert len(incl["audit_path"]) > 0
        incl["audit_path"][0] = flip(incl["audit_path"][0])
        re_sign_wrapper(b)  # isolate the inner-proof break from the wrapper sig
        r = verify_evidence_bundle(b)
        assert r.status == "failed"
        assert r.signature_ok is True  # wrapper authentic; the BODY's proof is broken
        assert r.events[1].inclusion_ok is False
        assert r.events[1].ok is False

    def test_wrong_leaf_index_breaks_inclusion(self) -> None:
        b = anchor_trace_bundle()
        incl = b["body"]["events"][2]["inclusion"]
        incl["leaf_index"] = 1 if incl["leaf_index"] == 0 else 0
        re_sign_wrapper(b)
        r = verify_evidence_bundle(b)
        assert r.status == "failed"
        assert r.signature_ok is True
        assert r.events[2].inclusion_ok is False

    def test_tampered_disclosed_content_fails_event(self) -> None:
        b = anchor_trace_bundle()
        ev = b["body"]["events"][0]
        assert isinstance(ev["content"], str)
        ev["content"] = flip(ev["content"])
        re_sign_wrapper(b)  # isolate the disclosed-bytes lie from the wrapper sig
        r = verify_evidence_bundle(b)
        assert r.status == "failed"
        assert r.signature_ok is True
        assert r.events[0].content_ok is False
        assert r.events[0].ok is False


class TestAnchorTraceOnChain:
    """Per-gateway on-chain outcomes (§4.2) via an injected fetch seam."""

    def _checkpoint_bytes(self) -> bytes:
        b = anchor_trace_bundle()
        return canonical_json(b["body"]["checkpoints"][0]["envelope"])

    def test_confirm_collapses_to_on_chain_ok_true(self) -> None:
        exact = self._checkpoint_bytes()
        r = verify_evidence_bundle(
            anchor_trace_bundle(),
            gateways=["https://g.example"],
            fetch_impl=lambda _url: exact,
        )
        assert r.checkpoints[0].on_chain.rollup == "confirm"
        assert r.checkpoints[0].on_chain_ok is True
        assert r.status == "verified"

    def test_mismatch_fails_the_checkpoint(self) -> None:
        r = verify_evidence_bundle(
            anchor_trace_bundle(),
            gateways=["https://g.example"],
            fetch_impl=lambda _url: b'{"other":"bytes"}',
        )
        assert r.checkpoints[0].on_chain.rollup == "mismatch"
        assert r.checkpoints[0].on_chain_ok is False
        assert r.status == "failed"
        assert r.exit_code() == 1

    def test_unreachable_is_undetermined_not_failed(self) -> None:
        def down(_url: str) -> bytes:
            raise ConnectionError("ECONNREFUSED")

        r = verify_evidence_bundle(
            anchor_trace_bundle(),
            gateways=["https://g.example"],
            fetch_impl=down,
        )
        assert r.checkpoints[0].on_chain.rollup == "unreachable"
        assert r.checkpoints[0].on_chain_ok is None
        assert r.status == "partial"
        assert r.exit_code() == 3  # undetermined, NOT failed

    def test_confirm_unreachable_mix_preserves_per_gateway(self) -> None:
        exact = self._checkpoint_bytes()

        def mix(url: str) -> bytes:
            if "g1" in url:
                return exact
            raise ConnectionError("ECONNREFUSED")

        r = verify_evidence_bundle(
            anchor_trace_bundle(),
            gateways=["https://g1.example", "https://g2.example"],
            fetch_impl=mix,
        )
        oc = r.checkpoints[0].on_chain
        assert [(g.gateway, g.outcome) for g in oc.per_gateway] == [
            ("https://g1.example", "confirm"),
            ("https://g2.example", "unreachable"),
        ]
        assert oc.rollup == "confirm"  # best-evidence after no mismatch
        assert oc.on_chain_ok is True
        assert r.status == "verified"
