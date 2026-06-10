"""Unit tests for Ed25519 sign/verify primitives."""

import pytest

from ario_proof.sign import public_key_hex, sign, signing_key_from_seed_hex
from ario_proof.verify import verify_signature

SEED_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def test_round_trip() -> None:
    key = signing_key_from_seed_hex(SEED_HEX)
    sig = sign(b"hello", key)
    assert len(sig) == 64
    assert verify_signature(b"hello", sig.hex(), public_key_hex(key))


def test_signing_is_deterministic() -> None:
    key = signing_key_from_seed_hex(SEED_HEX)
    assert sign(b"hello", key) == sign(b"hello", key)


def test_rejects_bad_seed_length() -> None:
    with pytest.raises(ValueError):
        signing_key_from_seed_hex("abcd")


def test_verify_rejects_tampered_message() -> None:
    key = signing_key_from_seed_hex(SEED_HEX)
    sig = sign(b"hello", key)
    assert not verify_signature(b"hellO", sig.hex(), public_key_hex(key))


def test_verify_rejects_forged_signature() -> None:
    key = signing_key_from_seed_hex(SEED_HEX)
    sig = bytearray(sign(b"hello", key))
    sig[0] ^= 0xFF
    assert not verify_signature(b"hello", bytes(sig).hex(), public_key_hex(key))


def test_verify_rejects_wrong_key() -> None:
    key = signing_key_from_seed_hex(SEED_HEX)
    other = signing_key_from_seed_hex("ff" * 32)
    sig = sign(b"hello", key)
    assert not verify_signature(b"hello", sig.hex(), public_key_hex(other))


@pytest.mark.parametrize(
    ("sig_hex", "pub_hex"),
    [
        ("not-hex", "00" * 32),
        ("00" * 64, "not-hex"),
        ("00" * 63, "00" * 32),  # wrong signature length
        ("00" * 64, "00" * 31),  # wrong key length
        ("", ""),
        ("zz" * 64, "00" * 32),
    ],
)
def test_verify_never_raises_on_malformed_input(sig_hex: str, pub_hex: str) -> None:
    assert verify_signature(b"hello", sig_hex, pub_hex) is False
