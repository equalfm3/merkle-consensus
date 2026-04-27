"""Hashing utilities and serialization helpers.

Provides SHA-256 wrappers and data serialization for use across
the hash chain, Merkle tree, and consensus modules.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Union


def sha256_hash(data: bytes) -> str:
    """Compute the SHA-256 hex digest of raw bytes.

    Args:
        data: Raw bytes to hash.

    Returns:
        Hex-encoded SHA-256 digest (64 characters).
    """
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    """Compute the SHA-256 digest as raw bytes.

    Args:
        data: Raw bytes to hash.

    Returns:
        32-byte SHA-256 digest.
    """
    return hashlib.sha256(data).digest()


def hash_concat(left: str, right: str) -> str:
    """Hash the concatenation of two hex-encoded hashes.

    This is the core operation for building Merkle trees: the parent
    node hash is H(left || right) where || is byte concatenation.

    Args:
        left: Hex-encoded left child hash.
        right: Hex-encoded right child hash.

    Returns:
        Hex-encoded hash of the concatenation.
    """
    combined = bytes.fromhex(left) + bytes.fromhex(right)
    return sha256_hash(combined)


def serialize_data(data: Any) -> bytes:
    """Deterministically serialize data to bytes.

    Uses JSON with sorted keys for deterministic output. Non-JSON-serializable
    types are converted to their string representation.

    Args:
        data: Any Python object to serialize.

    Returns:
        UTF-8 encoded bytes of the JSON representation.
    """
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("utf-8")
    try:
        return json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    except (TypeError, ValueError):
        return str(data).encode("utf-8")


def hash_data(data: Any) -> str:
    """Hash arbitrary data by serializing then hashing.

    Args:
        data: Any Python object.

    Returns:
        Hex-encoded SHA-256 digest.
    """
    return sha256_hash(serialize_data(data))


def verify_hash(data: Any, expected_hash: str) -> bool:
    """Verify that data hashes to the expected value.

    Args:
        data: The data to verify.
        expected_hash: Expected hex-encoded SHA-256 digest.

    Returns:
        True if the hash matches.
    """
    return hash_data(data) == expected_hash


def hex_to_bits(hex_str: str) -> list[int]:
    """Convert a hex string to a list of bits (MSB first).

    Args:
        hex_str: Hex-encoded string.

    Returns:
        List of 0s and 1s representing the binary form.
    """
    value = int(hex_str, 16)
    bit_length = len(hex_str) * 4
    return [(value >> (bit_length - 1 - i)) & 1 for i in range(bit_length)]


if __name__ == "__main__":
    print("=== Hashing Utilities Demo ===\n")

    msg = b"hello, merkle world"
    h = sha256_hash(msg)
    print(f"SHA-256('{msg.decode()}'): {h}")
    print(f"Digest length: {len(h)} hex chars = {len(h)*4} bits\n")

    h1 = hash_data("alice:100")
    h2 = hash_data("bob:50")
    parent = hash_concat(h1, h2)
    print(f"H('alice:100'): {h1[:16]}...")
    print(f"H('bob:50'):    {h2[:16]}...")
    print(f"H(H1 || H2):   {parent[:16]}...\n")

    data = {"sender": "alice", "amount": 100}
    serialized = serialize_data(data)
    print(f"Serialized: {serialized}")
    print(f"Hash:       {hash_data(data)[:16]}...")
    print(f"Verified:   {verify_hash(data, hash_data(data))}")
