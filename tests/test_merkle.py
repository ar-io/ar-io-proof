"""Unit tests for the RFC 9162 Merkle tree (corpus coverage lives in
test_conformance.py)."""

import hashlib

import pytest

from ario_proof.merkle import (
    EMPTY_TREE_ROOT_HEX,
    audit_path,
    leaf_hash,
    merkle_root,
    node_hash,
    verify_inclusion,
)


def hashes(n: int) -> list[bytes]:
    return [leaf_hash(f"leaf-{i}".encode()) for i in range(n)]


def test_empty_tree_root_is_sha256_of_nothing() -> None:
    assert merkle_root([]).hex() == EMPTY_TREE_ROOT_HEX
    assert merkle_root([]) == hashlib.sha256(b"").digest()


def test_single_leaf_root_is_the_leaf_hash() -> None:
    (h,) = hashes(1)
    assert merkle_root([h]) == h
    assert audit_path(0, [h]) == []
    assert verify_inclusion(h, 0, 1, [], h)


def test_domain_separation_prefixes() -> None:
    assert leaf_hash(b"x") == hashlib.sha256(b"\x00x").digest()
    assert (
        node_hash(b"L" * 32, b"R" * 32)
        == hashlib.sha256(b"\x01" + b"L" * 32 + b"R" * 32).digest()
    )


def test_two_leaves() -> None:
    h = hashes(2)
    assert merkle_root(h) == node_hash(h[0], h[1])
    assert audit_path(0, h) == [h[1]]
    assert audit_path(1, h) == [h[0]]


def test_rfc9162_split_is_not_bitcoin_duplicate_last_leaf() -> None:
    # n=3 splits 2|1: root = node(node(h0,h1), h2). The Bitcoin variant
    # would duplicate h2 and produce node(node(h0,h1), node(h2,h2)).
    h = hashes(3)
    assert merkle_root(h) == node_hash(node_hash(h[0], h[1]), h[2])
    assert merkle_root(h) != node_hash(node_hash(h[0], h[1]), node_hash(h[2], h[2]))


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 6, 7, 8, 13, 16, 31, 64])
def test_every_leaf_proves_inclusion_at_every_size(n: int) -> None:
    h = hashes(n)
    root = merkle_root(h)
    for i in range(n):
        path = audit_path(i, h)
        assert verify_inclusion(h[i], i, n, path, root), f"leaf {i} of {n}"


def test_audit_path_out_of_range_raises() -> None:
    h = hashes(3)
    with pytest.raises(IndexError):
        audit_path(3, h)
    with pytest.raises(IndexError):
        audit_path(-1, h)


def test_verify_inclusion_negatives_never_raise() -> None:
    h = hashes(7)
    root = merkle_root(h)
    path = audit_path(2, h)
    assert not verify_inclusion(h[2], 3, 7, path, root)  # wrong index
    assert not verify_inclusion(h[3], 2, 7, path, root)  # wrong leaf
    # Note: not every wrong size is detectable — for some (index, size)
    # pairs the RFC 9162 walk makes identical decisions (e.g. 2-of-7 vs
    # 2-of-8). Sizes whose depth diverges from the path length must fail:
    assert not verify_inclusion(h[2], 2, 9, path, root)  # path too short
    assert not verify_inclusion(h[2], 2, 4, path, root)  # path too long
    assert not verify_inclusion(h[2], 2, 7, path[:-1], root)  # truncated path
    assert not verify_inclusion(h[2], 2, 7, path + [h[0]], root)  # padded path
    assert not verify_inclusion(h[2], 2, 7, path, merkle_root(hashes(8)))  # wrong root
    assert not verify_inclusion(h[0], 0, 0, [], root)  # empty tree
    assert not verify_inclusion(h[0], -1, 7, path, root)  # negative index
