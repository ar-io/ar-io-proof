"""RSA-PSS-SHA-256 operator-attestation crypto (``ario.evidence.export/v1``).

The attested-evidence-export body (``specs/evidence-export.md`` §3) embeds
operator attestations signed with RSA-PSS-SHA-256 over the JCS-canonical
attestation payload; the operator key is the operator's Arweave RSA wallet.
These two pure functions are the only new primitive that body needs and the
only RSA in the kernel: verify one attestation signature, and derive the
operator's Arweave address from the embedded modulus (the self-describing
key→wallet binding).

The parameters are **pinned for cross-kernel byte-agreement** between the
issuer, the TypeScript kernel, and this Python kernel (evidence-export.md
§3.3): hash = SHA-256; MGF1 with SHA-256; **salt length = 32** (the SHA-256
digest length, i.e. OpenSSL's ``RSA_PSS_SALTLEN_DIGEST``); padding = PSS.
``salt_length = 32`` is load-bearing — the shipped issuer's former
``RSA_PSS_SALTLEN_AUTO`` (which resolves to the maximum, key-size-dependent
salt on signing) is NOT verifiable when the verifier pins the salt length,
which is exactly what makes these round-trip. This mirrors the TS kernel's
WebCrypto ``saltLength: 32`` byte-for-byte.

Malformed-vs-failed follows the kernel's split (same contract as
:func:`ario_proof.verify.verify_signature` and the TS ``verifyRsaPssSha256``):
a malformed key (JWK that will not import) or malformed signature hex is a
caller/input error and **raises** :class:`MalformedRsaError` — the "malformed"
signal the CLI buckets as exit 2. A well-formed key + signature that simply
does not verify (wrong signer, tampered payload, wrong salt length) returns
``False`` and never raises, so a hostile attestation cannot crash the checker.
"""

import base64
import hashlib
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

__all__ = [
    "RSA_PSS_SALT_LENGTH",
    "MalformedRsaError",
    "verify_rsa_pss_sha256",
    "derive_operator_address",
]

# The pinned PSS salt length: 32 bytes = the SHA-256 digest length
# (RSA_PSS_SALTLEN_DIGEST). Identical to the TS kernel's saltLength and the
# migrated issuer's RSA_PSS_SALTLEN_DIGEST. See the module docstring.
RSA_PSS_SALT_LENGTH = 32

_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


class MalformedRsaError(ValueError):
    """A malformed RSA input (unparseable signature hex or public key JWK).

    Distinct from a well-formed-but-failing verification, which returns
    ``False``. The kernel maps this to the "malformed" bucket (CLI exit 2).
    """


def _strict_hex_to_bytes(hex_str: str) -> bytes:
    """Strict hex → bytes, mirroring the TS ``hexToBytes``: reject odd length
    and any non-hex character (``bytes.fromhex`` tolerates internal
    whitespace, which the TS kernel rejects — so validate first)."""
    if not isinstance(hex_str, str):
        raise MalformedRsaError("signature is not a string")
    if len(hex_str) % 2 != 0:
        raise MalformedRsaError("odd-length hex string")
    if not _HEX_RE.match(hex_str):
        raise MalformedRsaError("non-hex characters")
    return bytes.fromhex(hex_str)


def _base64url_to_bytes(b64url: str) -> bytes:
    """Decode unpadded base64url (RFC 4648 §5), mirroring the TS
    ``base64UrlToBytes``: reject non-base64url characters and the impossible
    ``len % 4 == 1`` remainder, then re-pad and decode."""
    if not isinstance(b64url, str) or not _B64URL_RE.match(b64url):
        raise MalformedRsaError("non-base64url characters")
    rem = len(b64url) % 4
    if rem == 1:
        raise MalformedRsaError("invalid base64url length")
    padded = b64url + ("=" * (0 if rem == 0 else 4 - rem))
    return base64.urlsafe_b64decode(padded)


def _bytes_to_base64url(data: bytes) -> str:
    """Encode bytes as unpadded base64url (the Arweave address form)."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _rsa_public_key_from_jwk(public_key: dict) -> rsa.RSAPublicKey:
    """Build an RSA public key from a ``{kty:"RSA", n, e}`` JWK (``n``/``e``
    base64url). Raises :class:`MalformedRsaError` on any structural problem —
    the same "will not import" throw path as the TS ``crypto.subtle.importKey``.
    """
    if (
        not isinstance(public_key, dict)
        or public_key.get("kty") != "RSA"
        or not isinstance(public_key.get("n"), str)
        or not isinstance(public_key.get("e"), str)
    ):
        raise MalformedRsaError("malformed RSA public key: not a {kty:RSA,n,e} JWK")
    try:
        n = int.from_bytes(_base64url_to_bytes(public_key["n"]), "big")
        e = int.from_bytes(_base64url_to_bytes(public_key["e"]), "big")
        if n <= 0 or e <= 0:
            raise ValueError("non-positive RSA parameter")
        return rsa.RSAPublicNumbers(e, n).public_key()
    except MalformedRsaError:
        raise
    except Exception as exc:  # noqa: BLE001 — any import failure is malformed
        raise MalformedRsaError(f"malformed RSA public key: {exc}") from exc


def verify_rsa_pss_sha256(
    payload_bytes: bytes, signature_hex: str, public_key: dict
) -> bool:
    """Verify an RSA-PSS-SHA-256 signature over ``payload_bytes`` (the raw JCS
    bytes of the attestation payload) with the JWK RSA public key
    ``{kty:"RSA", n, e}`` and a lowercase-hex ``signature_hex``.

    Returns ``True``/``False`` for a well-formed key + signature; **raises**
    :class:`MalformedRsaError` for malformed signature hex or an unimportable
    key (the malformed-input path). The PSS parameters are the pinned
    salt-32 / MGF1-SHA-256 (module docstring).
    """
    try:
        signature = _strict_hex_to_bytes(signature_hex)
    except MalformedRsaError as exc:
        raise MalformedRsaError(f"malformed signature hex: {exc}") from exc

    key = _rsa_public_key_from_jwk(public_key)

    try:
        key.verify(
            signature,
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=RSA_PSS_SALT_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
    except Exception:  # noqa: BLE001
        # Some backends raise (rather than return) on a wrong-length RSA
        # signature. That is still just "not verified" — the signature parsed
        # as hex fine; it is the wrong signature (same tolerance as the TS
        # kernel's catch-return-false).
        return False


def derive_operator_address(n_base64url: str) -> str:
    """Derive an operator's Arweave wallet address from the base64url JWK
    modulus ``n``: ``address = base64url(SHA-256(raw_modulus_bytes))``, where
    ``raw_modulus_bytes`` is the decoded base64url ``n``.

    This is the same owner→address derivation arweave-js uses (SHA-256 over
    the modulus octets, unpadded base64url), so it binds an embedded RSA key
    to a specific wallet with no roster lookup. Raises
    :class:`MalformedRsaError` on a non-base64url modulus.
    """
    modulus = _base64url_to_bytes(n_base64url)
    digest = hashlib.sha256(modulus).digest()
    return _bytes_to_base64url(digest)
