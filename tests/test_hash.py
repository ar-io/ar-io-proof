"""Unit tests for the SHA-256 wrapper."""

from ario_proof.hash import sha256_hex


def test_empty_input_is_the_pinned_empty_tree_root() -> None:
    # Also the RFC 9162 empty-tree root pinned in merkle-tree-00-leaves.json.
    assert (
        sha256_hex(b"")
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_known_digest_lowercase_hex() -> None:
    assert (
        sha256_hex(b"abc")
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
