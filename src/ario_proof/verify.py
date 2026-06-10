"""Ed25519 signature verification.

The verifier never raises on adversarial input: malformed hex, wrong-length
keys or signatures, and signature mismatches all return ``False``.
"""

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

__all__ = ["verify_signature"]


def verify_signature(message: bytes, signature_hex: str, public_key_hex: str) -> bool:
    """True iff ``signature_hex`` is a valid Ed25519 signature of ``message``
    under the 32-byte verify key ``public_key_hex``."""
    try:
        signature = bytes.fromhex(signature_hex)
        public_key = bytes.fromhex(public_key_hex)
        if len(signature) != 64 or len(public_key) != 32:
            return False
        VerifyKey(public_key).verify(message, signature)
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False
