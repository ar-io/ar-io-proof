#!/usr/bin/env python3
"""Shared builder for the ``ario.evidence.export/v1`` conformance case set.

Single source of truth for the export vector mutations, imported by BOTH:

- ``gen_export_vectors.py`` — writes the committed ``test-vectors/v1.3`` corpus
  files (positive + one tampered vector per failure class), and
- ``cross-kernel/generate_export_cases.py`` — drives the Python⇄TS byte-agreement
  gate over the same bytes.

CORP1 (``specs/governance.md`` §4): vectors are **generated, never hand-edited**.
The positive vector is the frozen shared golden export
(``test-vectors/evidence-export/evidence-export-bundle.golden.json``, byte-identical
to the TS kernel's ``ts/test/fixtures/`` copy). Each tampered vector is a
**programmatic** mutation of it — a single byte-flip, a swap-in of a pre-signed
``_tamper`` piece (the attestation-class negatives that need an RSA private key
the fixture does not carry), or a field delete — re-signed with the published
Ed25519 stack seed where the wrapper must stay valid so the verifier reaches the
inner check. Nothing here is typed by hand.

The RSA-PSS attestation signatures cannot be re-generated offline (the fixture
carries only the operator public keys), so the three RSA failure classes reuse
the fixture's ``_tamper`` block: ``att0_mis_salt_sig`` (a max-salt signature over
att0's SAME payload+key — the salt=32 pin must reject it),
``wrong_operator_attestation`` (op2-signed but claims op1's address), and
``wrong_data_hash_attestation`` (op1-signed but a data_hash that does not bind
the checkpoint).
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import jcs
from nacl.signing import SigningKey

# The published stack test seed — the issuer key the fixture wrapper and its
# inline source bundle are signed with, so a tampered wrapper can be re-signed
# and ISOLATE an inner check from the wrapper signature. NEVER a real key.
SEED_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
_SK = SigningKey(bytes.fromhex(SEED_HEX))
_PUB_HEX = _SK.verify_key.encode().hex()

# Failure-class → expected CLI exit, for the corpus manifest + human review.
# (The kernels compute the actual verdict; this is the declared intent.)
EXPECTED_EXIT = {
    "positive": 0,
    "wrapper-signature-break": 1,
    "body-hash-mismatch": 1,
    "source-bundle-hash-mismatch": 1,
    "verdict-disagreement": 1,
    "forged-attestation-signature": 1,
    "mis-salted-attestation": 1,
    "operator-address-binding-break": 1,
    "data-hash-binding-break": 1,
    "disclosed-content-mismatch": 1,
    "subject-ref-tamper": 1,
    "malformed-rsa-key": 2,
    "malformed-signature-alg": 2,
    "source-bundle-ref-offline": 3,
}


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _flip(hex_str: str) -> str:
    """Flip the last nibble of a hex string (mirrors the TS tests' ``flip``)."""
    return hex_str[:-1] + ("1" if hex_str[-1] == "0" else "0")


def _re_sign_wrapper(bundle: dict[str, Any]) -> None:
    """Recompute ``body_hash`` and re-sign the wrapper with the stack seed, so a
    body tamper is isolated from the wrapper signature (mirrors the TS
    ``reSignWrapper``)."""
    bundle["body_hash"] = _sha256_hex(jcs.canonicalize(bundle["body"]))
    pre = {k: v for k, v in bundle.items() if k != "signature"}
    bundle["public_key"] = _PUB_HEX
    bundle["signature"] = _SK.sign(jcs.canonicalize(pre)).signature.hex()


def _re_sign_source_and_export(export: dict[str, Any]) -> None:
    """Re-sign the inline source bundle wrapper, re-link ``source_bundle_hash``,
    then re-sign the export wrapper — used when a mutation lives inside the
    source bundle body and must stay wrapper-valid so the inner check is
    reached."""
    sb = export["body"]["source_bundle"]
    sb["body_hash"] = _sha256_hex(jcs.canonicalize(sb["body"]))
    sb_pre = {k: v for k, v in sb.items() if k != "signature"}
    sb["public_key"] = _PUB_HEX
    sb["signature"] = _SK.sign(jcs.canonicalize(sb_pre)).signature.hex()
    export["body"]["source_bundle_hash"] = _sha256_hex(jcs.canonicalize(sb))
    _re_sign_wrapper(export)


def load_fixture(repo_root: Path) -> dict[str, Any]:
    path = (
        repo_root
        / "test-vectors"
        / "evidence-export"
        / "evidence-export-bundle.golden.json"
    )
    return json.loads(path.read_text(encoding="utf-8"))


def build_cases(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the ordered case set: ``[{id, klass, expected_exit, bundle}, ...]``.

    ``bundle`` is the complete ``ario.evidence.export/v1`` wrapper a verifier
    consumes (already re-signed where noted). ``klass`` names the failure class;
    ``expected_exit`` is the declared intent (the kernels compute the verdict)."""
    export = fixture["export"]
    tamper = fixture["_tamper"]
    cases: list[dict[str, Any]] = []

    def add(vid: str, klass: str, bundle: dict[str, Any]) -> None:
        cases.append(
            {
                "id": vid,
                "klass": klass,
                "expected_exit": EXPECTED_EXIT[klass],
                "bundle": bundle,
            }
        )

    # -- positive -----------------------------------------------------------
    add("evidence-export-positive-01", "positive", copy.deepcopy(export))

    # -- 1. wrapper-signature break (verbatim-bytes tamper; no re-sign) ------
    e = copy.deepcopy(export)
    e["signature"] = _flip(e["signature"])
    add("evidence-export-tamper-wrapper-signature", "wrapper-signature-break", e)

    # -- 2. body_hash mismatch (verbatim-bytes tamper; no re-sign) ----------
    e = copy.deepcopy(export)
    e["body_hash"] = _flip(e["body_hash"])
    add("evidence-export-tamper-body-hash", "body-hash-mismatch", e)

    # -- 3. source_bundle_hash mismatch (re-sign wrapper) -------------------
    e = copy.deepcopy(export)
    e["body"]["source_bundle_hash"] = _flip(e["body"]["source_bundle_hash"])
    _re_sign_wrapper(e)
    add("evidence-export-tamper-source-linkage", "source-bundle-hash-mismatch", e)

    # -- 4. verdict disagreement (flip a cached deterministic finding) ------
    e = copy.deepcopy(export)
    e["body"]["kernel_verdict"]["events"][0]["signature_ok"] = False
    _re_sign_wrapper(e)
    add("evidence-export-tamper-verdict-disagreement", "verdict-disagreement", e)

    # -- 5. forged attestation signature (one flipped byte; re-sign) --------
    e = copy.deepcopy(export)
    e["body"]["attestations"][0]["signature"] = _flip(
        e["body"]["attestations"][0]["signature"]
    )
    _re_sign_wrapper(e)
    add(
        "evidence-export-tamper-attestation-signature",
        "forged-attestation-signature",
        e,
    )

    # -- 6. mis-salted attestation (max/auto salt; the salt=32 pin) ---------
    e = copy.deepcopy(export)
    e["body"]["attestations"][0]["signature"] = tamper["att0_mis_salt_sig"]
    _re_sign_wrapper(e)
    add("evidence-export-tamper-mis-salt", "mis-salted-attestation", e)

    # -- 7. operator-address-binding break (op2 signs, claims op1) ----------
    e = copy.deepcopy(export)
    e["body"]["attestations"][0] = copy.deepcopy(tamper["wrong_operator_attestation"])
    _re_sign_wrapper(e)
    add("evidence-export-tamper-operator-binding", "operator-address-binding-break", e)

    # -- 8. data_hash-binding break (op1 signs; wrong data_hash) ------------
    e = copy.deepcopy(export)
    e["body"]["attestations"][0] = copy.deepcopy(tamper["wrong_data_hash_attestation"])
    _re_sign_wrapper(e)
    add("evidence-export-tamper-data-hash-binding", "data-hash-binding-break", e)

    # -- 9. disclosed-content mismatch (flip event 0's in-body content) -----
    e = copy.deepcopy(export)
    ev0 = e["body"]["source_bundle"]["body"]["events"][0]
    ev0["content"] = _flip(ev0["content"])
    _re_sign_source_and_export(e)
    add("evidence-export-tamper-disclosed-content", "disclosed-content-mismatch", e)

    # -- 10. subject_ref tamper (mutate the RSA-signed payload) -------------
    # subject_ref lives INSIDE the signed attestation payload, so altering it
    # breaks the RSA-PSS signature — proving it cannot be added/altered post-sign.
    e = copy.deepcopy(export)
    sr = e["body"]["attestations"][0]["payload"]["subject_ref"]
    sr["hash"] = _flip(sr["hash"])
    _re_sign_wrapper(e)
    add("evidence-export-tamper-subject-ref", "subject-ref-tamper", e)

    # -- 11. malformed embedded RSA key (kty=oct won't import → exit 2) -----
    e = copy.deepcopy(export)
    e["body"]["attestations"][0]["public_key"]["kty"] = "oct"
    _re_sign_wrapper(e)
    add("evidence-export-malformed-rsa-key", "malformed-rsa-key", e)

    # -- 12. unsupported attestation signature_alg (→ exit 2) ---------------
    e = copy.deepcopy(export)
    e["body"]["attestations"][0]["signature_alg"] = "ed25519"
    _re_sign_wrapper(e)
    add("evidence-export-malformed-signature-alg", "malformed-signature-alg", e)

    # -- 13. source_bundle_ref (no inline source) → undetermined (exit 3) ---
    e = copy.deepcopy(export)
    del e["body"]["source_bundle"]
    e["body"]["source_bundle_ref"] = "ar://some-large-source-bundle-txid"
    _re_sign_wrapper(e)
    add("evidence-export-source-bundle-ref", "source-bundle-ref-offline", e)

    return cases
