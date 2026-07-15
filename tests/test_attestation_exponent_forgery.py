"""Regression: the RSA e=1 "identity" attestation forgery (red-team RT1).

An attacker takes a real operator's PUBLIC modulus, sets e=1 (making RSA verify
the identity, s**1 mod n = s), and forges a PSS "signature" = the encoded
message -- no private key. The operator-address binding commits to n alone and
never covered e, so before the exponent guard the forgery verified. Both kernels
now enforce e == 65537. The forged artifact MUST verify as ``failed``.
"""

import json
import pathlib

from ario_proof.evidence import verify_evidence_bundle
from ario_proof.rsa_pss import verify_rsa_pss_sha256

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_FORGERY = (
    _ROOT / "test-vectors/evidence-export/negatives/attestation-exponent-forgery.json"
)


def _status(result: object) -> object:
    return getattr(result, "status", None) or (
        result.get("status") if isinstance(result, dict) else result
    )


def test_exponent_guard_rejects_e1() -> None:
    # A structurally valid RSA JWK with e=1: verify_rsa_pss_sha256 must return
    # False regardless of the signature, because e != 65537 is not a legitimate
    # operator key. (Guard short-circuits before key construction.)
    key = {"kty": "RSA", "n": "AQAB", "e": "AQ"}  # e = 1
    assert verify_rsa_pss_sha256(b"any bytes", "00", key) is False


def test_full_forged_export_fails() -> None:
    forged = json.loads(_FORGERY.read_text())
    assert _status(verify_evidence_bundle(forged)) == "failed"


def test_exponent_guard_rejects_even_e() -> None:
    # An EVEN exponent is the cross-kernel divergence case: pyca rejects even e
    # at key construction ("e must be >= 3 and < n") -> would be `malformed`,
    # while WebCrypto imports it -> would be a `failed` verify. The exponent
    # guard short-circuits BOTH kernels to False (clean FAILED) BEFORE key
    # import, so e=2 agrees cross-kernel. It must return False, NOT raise --
    # raising is the malformed signal this guard keeps the kernels from
    # diverging on. Mirrors the e=2 case in attestation-exponent-forgery.test.ts.
    key = {"kty": "RSA", "n": "sQ", "e": "Ag"}  # e = 2 (even)
    assert verify_rsa_pss_sha256(b"any bytes", "00", key) is False
