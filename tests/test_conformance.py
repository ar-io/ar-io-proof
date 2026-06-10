"""Corpus conformance gate.

The vendored ``test-vectors/`` corpus (tag ``test-vectors-v1.0`` from
ar-io-agent) is the contract: a kernel is conformant iff it reproduces every
vector byte-for-byte. This file grows with each landed primitive; the corpus
integrity and structural checks below establish the gate itself.

If anything in this file disagrees with a vector, the kernel is wrong — never
the vector.
"""

import hashlib
import json
from pathlib import Path

import pytest

from ario_proof.canonicalize import canonical_json
from ario_proof.envelope import content_hashes, sign_envelope, verify_envelope
from ario_proof.hash import sha256_hex
from ario_proof.sign import public_key_hex, sign, signing_key_from_seed_hex
from ario_proof.verify import verify_signature

VECTORS_DIR = Path(__file__).resolve().parent.parent / "test-vectors"

# Pinned from test-vectors/CORPUS-v1.md (corpus tag test-vectors-v1.0).
# A drifted vendored copy fails here before any crypto runs.
CORPUS_SHA256 = {
    "envelope-asset-missing-01.json": "fecb29289df2b6ea210b51737e6cdf10438ec996add050b053247cc567fe2e27",
    "envelope-asset-registered-01.json": "3b99fc850edba7775a4df970e406fcb2d787fc10594cd7f969936938b881b9a9",
    "envelope-key-retired-01.json": "2e89bc2b1986e3545d0aae94f850d675f9f16fc384b311cc75090a5e275eaf33",
    "envelope-policy-changed-01.json": "62a460fb4e0e49c2ef28acc73ddea1163f801ccef6c0e247679e65e6c655509c",
    "envelope-tamper-detected-01.json": "5f4b8b1dab9c50ca97ff0349e39481ee33f9a19991632d13fb71fd940a88fcd0",
    "envelope-verification-checkpoint-01.json": "393c04e411807481587c591ccb1e637cb072f40940cbc9d25e53dd29253bb56d",
    "merkle-tree-00-leaves.json": "705adf82ce9cc46d0e45fce216cb205d5755e2d41975b66444f1765a982faa95",
    "merkle-tree-01-leaves.json": "bdbb57ad29272054c5dcc655c2279c4debec9c4c67ea85f17490760a19b52923",
    "merkle-tree-02-leaves.json": "9c33d0fcb57655729a0e657b8b4313de806e397949465d310338db5dd56a573b",
    "merkle-tree-03-leaves.json": "f4cc12cd11cb3a49225edff2c18ab9f516992f8d6c13e7baadb627f1c7efe8eb",
    "merkle-tree-07-leaves.json": "8372c63f3d5a61c8dfc0939fb5776b8041960313df4f9334e620d398326bdd1c",
    "merkle-tree-1024-leaves.json": "e732c755539b84e20b80d15e5a7989e2d6736153d9d78c944ed6e7ee98627254",
    "merkle-tree-16-leaves.json": "b58b31340bef317fd32734be7e3ff58b0d4a4d0cb03a7b16f08056161c7ae72c",
    "README.md": "7d21d23fcbf9996e9e7a710099bb59b4cb501720ded57aac65edde43de10ef44",
}

ENVELOPE_VECTOR_FILES = sorted(VECTORS_DIR.glob("envelope-*.json"))
MERKLE_VECTOR_FILES = sorted(VECTORS_DIR.glob("merkle-tree-*.json"))


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def is_hex(s: str, nibbles: int | None = None) -> bool:
    if nibbles is not None and len(s) != nibbles:
        return False
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False


@pytest.mark.parametrize("name", sorted(CORPUS_SHA256))
def test_corpus_integrity(name: str) -> None:
    digest = hashlib.sha256((VECTORS_DIR / name).read_bytes()).hexdigest()
    assert (
        digest == CORPUS_SHA256[name]
    ), f"vendored {name} drifted from test-vectors-v1.0"


def test_corpus_complete() -> None:
    vector_files = {p.name for p in VECTORS_DIR.glob("*.json")}
    expected = {n for n in CORPUS_SHA256 if n.endswith(".json")}
    assert vector_files == expected
    assert len(ENVELOPE_VECTOR_FILES) == 6
    assert len(MERKLE_VECTOR_FILES) == 7


@pytest.mark.parametrize("path", ENVELOPE_VECTOR_FILES, ids=lambda p: p.stem)
def test_envelope_vector_structure(path: Path) -> None:
    v = load(path)
    assert v["spec_version"] == "ario.agent/v1"
    assert v["vector_id"] == path.stem

    kp = v["fixed_keypair"]
    assert is_hex(kp["ed25519_seed_hex"], 64)
    assert is_hex(kp["ed25519_public_hex"], 64)

    pre = v["inputs"]["envelope_pre_signature"]
    for field in ("spec_version", "event_id", "event_type", "subject", "payload"):
        assert field in pre, f"envelope_pre_signature missing {field}"
    # The signer injects these before canonicalizing; vectors must not pre-bake them.
    assert "payload_hash" not in pre
    assert "public_key" not in pre
    assert "signature" not in pre

    out = v["expected_outputs"]
    assert is_hex(out["payload_jcs_bytes_hex"])
    assert is_hex(out["payload_hash_hex"], 64)
    assert is_hex(out["envelope_for_sig_jcs_bytes_hex"])
    assert is_hex(out["signature_hex"], 128)


@pytest.mark.parametrize("path", ENVELOPE_VECTOR_FILES, ids=lambda p: p.stem)
def test_payload_jcs_bytes(path: Path) -> None:
    v = load(path)
    payload = v["inputs"]["envelope_pre_signature"]["payload"]
    assert (
        canonical_json(payload).hex() == v["expected_outputs"]["payload_jcs_bytes_hex"]
    )


@pytest.mark.parametrize("path", ENVELOPE_VECTOR_FILES, ids=lambda p: p.stem)
def test_payload_hash(path: Path) -> None:
    v = load(path)
    payload = v["inputs"]["envelope_pre_signature"]["payload"]
    assert (
        sha256_hex(canonical_json(payload)) == v["expected_outputs"]["payload_hash_hex"]
    )


@pytest.mark.parametrize("path", ENVELOPE_VECTOR_FILES, ids=lambda p: p.stem)
def test_envelope_for_sig_jcs_bytes(path: Path) -> None:
    v = load(path)
    env = dict(v["inputs"]["envelope_pre_signature"])
    env["payload_hash"] = v["expected_outputs"]["payload_hash_hex"]
    env["public_key"] = v["fixed_keypair"]["ed25519_public_hex"]
    assert (
        canonical_json(env).hex()
        == v["expected_outputs"]["envelope_for_sig_jcs_bytes_hex"]
    )


@pytest.mark.parametrize("path", ENVELOPE_VECTOR_FILES, ids=lambda p: p.stem)
def test_signature_reproduces_deterministically(path: Path) -> None:
    v = load(path)
    key = signing_key_from_seed_hex(v["fixed_keypair"]["ed25519_seed_hex"])
    assert public_key_hex(key) == v["fixed_keypair"]["ed25519_public_hex"]
    message = bytes.fromhex(v["expected_outputs"]["envelope_for_sig_jcs_bytes_hex"])
    assert sign(message, key).hex() == v["expected_outputs"]["signature_hex"]


@pytest.mark.parametrize("path", ENVELOPE_VECTOR_FILES, ids=lambda p: p.stem)
def test_signature_verifies(path: Path) -> None:
    v = load(path)
    message = bytes.fromhex(v["expected_outputs"]["envelope_for_sig_jcs_bytes_hex"])
    sig_hex = v["expected_outputs"]["signature_hex"]
    pub_hex = v["fixed_keypair"]["ed25519_public_hex"]
    assert verify_signature(message, sig_hex, pub_hex)
    # Tampered message and forged signature must both fail.
    assert not verify_signature(message + b" ", sig_hex, pub_hex)
    forged = bytearray(bytes.fromhex(sig_hex))
    forged[0] ^= 0xFF
    assert not verify_signature(message, bytes(forged).hex(), pub_hex)


def signed_envelope(v: dict) -> dict:
    """The full signed envelope a vector describes."""
    env = dict(v["inputs"]["envelope_pre_signature"])
    env["payload_hash"] = v["expected_outputs"]["payload_hash_hex"]
    env["public_key"] = v["fixed_keypair"]["ed25519_public_hex"]
    env["signature"] = v["expected_outputs"]["signature_hex"]
    return env


@pytest.mark.parametrize("path", ENVELOPE_VECTOR_FILES, ids=lambda p: p.stem)
def test_sign_envelope_reproduces_vector(path: Path) -> None:
    v = load(path)
    key = signing_key_from_seed_hex(v["fixed_keypair"]["ed25519_seed_hex"])
    env = sign_envelope(dict(v["inputs"]["envelope_pre_signature"]), key)
    assert env == signed_envelope(v)


@pytest.mark.parametrize("path", ENVELOPE_VECTOR_FILES, ids=lambda p: p.stem)
def test_verify_envelope_accepts_vector(path: Path) -> None:
    result = verify_envelope(signed_envelope(load(path)))
    assert result.ok
    assert result.spec_version_ok
    assert result.payload_hash_ok is True
    assert result.signature_ok
    assert result.errors == []


@pytest.mark.parametrize("path", ENVELOPE_VECTOR_FILES, ids=lambda p: p.stem)
def test_verify_envelope_rejects_tamper_and_forgery(path: Path) -> None:
    v = load(path)

    tampered = signed_envelope(v)
    tampered["payload"] = dict(tampered["payload"], _injected="x")
    assert not verify_envelope(tampered).ok

    forged = signed_envelope(v)
    sig = bytearray(bytes.fromhex(forged["signature"]))
    sig[0] ^= 0xFF
    forged["signature"] = bytes(sig).hex()
    assert not verify_envelope(forged).ok

    swapped = signed_envelope(v)
    swapped["public_key"] = "00" * 32
    assert not verify_envelope(swapped).ok

    unknown = signed_envelope(v)
    unknown["spec_version"] = "ario.agent/v99"
    assert not verify_envelope(unknown).ok


@pytest.mark.parametrize("path", ENVELOPE_VECTOR_FILES, ids=lambda p: p.stem)
def test_content_bind_against_vector(path: Path) -> None:
    env = signed_envelope(load(path))
    for role, content_hash in content_hashes(env):
        result = verify_envelope(env, expected_content_hash=content_hash)
        assert result.content_hash_ok is True
        assert result.content_role == role
    result = verify_envelope(env, expected_content_hash="f" * 64)
    assert result.content_hash_ok is False


@pytest.mark.parametrize("path", MERKLE_VECTOR_FILES, ids=lambda p: p.stem)
def test_merkle_vector_structure(path: Path) -> None:
    v = load(path)
    assert v["vector_id"] == path.stem
    assert is_hex(v["expected_root_hex"], 64)
    assert v["leaf_count"] == len(v["leaves"])
    assert len(v["inclusion_proofs"]) == (
        0 if v["leaf_count"] == 0 else min(v["leaf_count"], 3)
    )
    for leaf in v["leaves"]:
        assert is_hex(leaf["leaf_hash_hex"], 64)
        assert isinstance(leaf["leaf_object"], dict)
    for proof in v["inclusion_proofs"]:
        assert 0 <= proof["leaf_index"] < v["leaf_count"]
        for sibling in proof["audit_path_hex"]:
            assert is_hex(sibling, 64)
