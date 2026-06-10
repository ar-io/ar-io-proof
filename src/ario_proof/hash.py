"""SHA-256 hashing.

Every hash in the envelope family is SHA-256 rendered as lowercase hex with
no prefix — ``payload_hash``, asset content hashes, policy hashes, Merkle
roots.
"""

import hashlib

__all__ = ["sha256_hex"]


def sha256_hex(data: bytes) -> str:
    """SHA-256 of ``data`` as lowercase hex."""
    return hashlib.sha256(data).hexdigest()
