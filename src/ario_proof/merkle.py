"""RFC 9162 binary Merkle tree — build, audit paths, inclusion verification.

A faithful port of the Go reference (``ar-io-agent/internal/merkle``). All
hashing is SHA-256 with RFC 9162 §2.1 domain separation: leaves prefixed
``0x00``, interior nodes ``0x01``. A tree of n leaves splits into a left
subtree of k leaves (the largest power of two < n) and a right subtree of
n−k — NOT the Bitcoin duplicate-last-leaf variant, which produces different
roots for non-power-of-two leaf counts.

The empty tree (zero leaves) hashes to ``SHA-256("")``:
``e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855``.
"""

import hashlib

__all__ = [
    "EMPTY_TREE_ROOT_HEX",
    "leaf_hash",
    "node_hash",
    "merkle_root",
    "audit_path",
    "verify_inclusion",
]

EMPTY_TREE_ROOT_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def leaf_hash(leaf_bytes: bytes) -> bytes:
    """``SHA-256(0x00 || leaf_bytes)`` per RFC 9162 §2.1."""
    return hashlib.sha256(b"\x00" + leaf_bytes).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """``SHA-256(0x01 || left || right)`` per RFC 9162 §2.1."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaf_hashes: list[bytes]) -> bytes:
    """The RFC 9162 Merkle Tree Hash of already-hashed leaves.

    Callers pass leaf hashes — the output of :func:`leaf_hash` on each
    leaf's canonical bytes. Zero leaves yields ``SHA-256("")``.
    """
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hashes[0]
    k = _largest_pow2_less_than(n)
    return node_hash(merkle_root(leaf_hashes[:k]), merkle_root(leaf_hashes[k:]))


def audit_path(m: int, leaf_hashes: list[bytes]) -> list[bytes]:
    """The inclusion proof for the leaf at index ``m``, per RFC 9162 §2.1.3.

    Sibling hashes bottom-up; empty for a single-leaf tree (the leaf hash
    itself is the root). Raises ``IndexError`` when ``m`` is out of range.
    """
    n = len(leaf_hashes)
    if m < 0 or m >= n:
        raise IndexError("merkle: leaf index out of range")
    return _audit_path(m, leaf_hashes)


def _audit_path(m: int, leaf_hashes: list[bytes]) -> list[bytes]:
    n = len(leaf_hashes)
    if n == 1:
        return []
    k = _largest_pow2_less_than(n)
    if m < k:
        return _audit_path(m, leaf_hashes[:k]) + [merkle_root(leaf_hashes[k:])]
    return _audit_path(m - k, leaf_hashes[k:]) + [merkle_root(leaf_hashes[:k])]


def verify_inclusion(
    leaf: bytes,
    leaf_index: int,
    total_leaves: int,
    path: list[bytes],
    expected_root: bytes,
) -> bool:
    """Verify an RFC 9162 §2.1.3 inclusion proof.

    ``leaf`` is the leaf hash (:func:`leaf_hash` of the canonical leaf
    bytes); ``path`` is the audit path bottom-up; ``expected_root`` is the
    ``merkle_root`` committed by the checkpoint envelope. True iff the path
    reconstructs the expected root. Never raises on adversarial proof
    *content* (wrong index, truncated/padded path, mismatched root); passing
    non-``bytes`` arguments is API misuse and raises ``TypeError`` —
    :func:`ario_proof.bundle.verify_proof_bundle` performs that hex/type
    validation before calling here.
    """
    if leaf_index < 0 or leaf_index >= total_leaves or total_leaves == 0:
        return False
    if total_leaves == 1:
        return len(path) == 0 and leaf == expected_root

    fn = leaf_index
    sn = total_leaves - 1
    r = leaf

    for p in path:
        if sn == 0:
            # Audit path is longer than the tree depth — malformed proof.
            return False
        if fn & 1 == 1 or fn == sn:
            r = node_hash(p, r)
            if fn & 1 == 0:
                while fn & 1 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1

    return sn == 0 and r == expected_root


def _largest_pow2_less_than(n: int) -> int:
    """The largest k = 2**a with k < n (0 for n < 2)."""
    if n < 2:
        return 0
    k = 1
    while k * 2 < n:
        k *= 2
    return k
