"""Ed25519 signing primitives.

Pure functions over keys and bytes — no key files, no environment lookups, no
key lifecycle. Producers own key storage and rotation; the kernel only signs.

Ed25519 here is strict RFC 8032 (libsodium via PyNaCl), matching the Go
reference (``crypto/ed25519``) and the JS sibling verifier (``@noble/ed25519``
with ``zip215: false``).
"""

from nacl.signing import SigningKey

__all__ = ["signing_key_from_seed_hex", "public_key_hex", "sign"]


def signing_key_from_seed_hex(seed_hex: str) -> SigningKey:
    """Construct an Ed25519 signing key from a 32-byte hex seed."""
    seed = bytes.fromhex(seed_hex)
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    return SigningKey(seed)


def public_key_hex(key: SigningKey) -> str:
    """The 32-byte Ed25519 verify key for ``key``, as lowercase hex."""
    return bytes(key.verify_key).hex()


def sign(message: bytes, key: SigningKey) -> bytes:
    """Sign ``message`` with ``key``; returns the detached 64-byte signature.

    Ed25519 is deterministic: the same key and message always produce the
    same signature, which is what makes signatures conformance-testable
    against the corpus.
    """
    return key.sign(message).signature
