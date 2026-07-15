"""RSA-PSS-SHA-256 operator-attestation primitive tests (evidence-export.md §3.3).

Mirrors the TS kernel's ``rsa-pss-attestation.test.ts`` against the SAME frozen
golden vector (``test-vectors/evidence-export/rsa-pss-attestation.golden.json``,
byte-identical to ``ts/test/fixtures/``): a real RSA-2048 key, a snake_case
attestation payload, the salt=32 signature, AND a second signature over max/auto
salt — so the salt-length pin is proven to round-trip and the un-verifiable
AUTO-salt trap is proven to fail. The kernels reproduce the same verdicts on
these bytes.
"""

import json
from pathlib import Path

import pytest

from ario_proof.canonicalize import canonical_json
from ario_proof.rsa_pss import (
    MalformedRsaError,
    derive_operator_address,
    verify_rsa_pss_sha256,
)

FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "test-vectors"
    / "evidence-export"
    / "rsa-pss-attestation.golden.json"
)
F = json.loads(FIXTURE.read_text(encoding="utf-8"))


def payload_bytes() -> bytes:
    # The signed bytes are the raw JCS of the payload — recompute them here so the
    # round-trip also pins jcs↔signature agreement.
    return canonical_json(F["payload"])


def flip_last_nibble(hex_str: str) -> str:
    return hex_str[:-1] + ("1" if hex_str.endswith("0") else "0")


class TestVerifyRsaPssSalt32Pin:
    def test_a_committed_salt32_signature_verifies_true(self) -> None:
        assert F["salt_length"] == 32  # documents the pin the fixture was signed under
        assert (
            verify_rsa_pss_sha256(payload_bytes(), F["signature_hex"], F["public_key"])
            is True
        )

    def test_b_tampered_signature_verifies_false(self) -> None:
        tampered = flip_last_nibble(F["signature_hex"])
        assert tampered != F["signature_hex"]
        assert (
            verify_rsa_pss_sha256(payload_bytes(), tampered, F["public_key"]) is False
        )

    def test_c_tampered_payload_verifies_false(self) -> None:
        mutated = {**F["payload"], "data_size": F["payload"]["data_size"] + 1}
        assert (
            verify_rsa_pss_sha256(
                canonical_json(mutated), F["signature_hex"], F["public_key"]
            )
            is False
        )

    def test_d_wrong_salt_length_signature_verifies_false(self) -> None:
        # Same key, same JCS bytes, only the salt differs (AUTO → max on signing).
        # The salt=32 pin cannot verify it — the interop trap.
        assert (
            verify_rsa_pss_sha256(
                payload_bytes(), F["signature_wrong_salt_hex"], F["public_key"]
            )
            is False
        )

    def test_malformed_signature_hex_raises(self) -> None:
        with pytest.raises(MalformedRsaError, match="malformed signature hex"):
            verify_rsa_pss_sha256(payload_bytes(), "not-hex!!", F["public_key"])

    def test_odd_length_signature_hex_raises(self) -> None:
        with pytest.raises(MalformedRsaError, match="malformed signature hex"):
            verify_rsa_pss_sha256(payload_bytes(), "abc", F["public_key"])

    def test_malformed_rsa_public_key_raises(self) -> None:
        # A structurally-invalid JWK (wrong kty) is the malformed-key throw path.
        bad_key = {"kty": "oct", "n": F["public_key"]["n"], "e": F["public_key"]["e"]}
        with pytest.raises(MalformedRsaError, match="malformed RSA public key"):
            verify_rsa_pss_sha256(payload_bytes(), F["signature_hex"], bad_key)


class TestDeriveOperatorAddress:
    def test_e_reproduces_fixture_address_from_modulus(self) -> None:
        addr = derive_operator_address(F["public_key"]["n"])
        assert addr == F["operator_address"]
        # §3.3 self-consistency: the signed payload's `operator` == the derived addr.
        assert addr == F["payload"]["operator"]

    def test_wrong_modulus_derives_different_address(self) -> None:
        n = F["public_key"]["n"]
        wrong_n = ("y" if n[0] == "x" else "x") + n[1:]
        assert wrong_n != n
        assert derive_operator_address(wrong_n) != F["operator_address"]

    def test_produces_unpadded_base64url(self) -> None:
        addr = derive_operator_address(F["public_key"]["n"])
        assert "=" not in addr and "+" not in addr and "/" not in addr
        assert all(c.isalnum() or c in "_-" for c in addr)

    def test_non_base64url_modulus_raises(self) -> None:
        with pytest.raises(MalformedRsaError, match="base64url"):
            derive_operator_address("has spaces and +/=")
