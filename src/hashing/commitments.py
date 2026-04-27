"""Hash-based commitment schemes.

A commitment scheme lets a party commit to a value without revealing it,
then later reveal the value and prove it matches the commitment. This is
used in consensus protocols to prevent equivocation — a node commits to
its vote before seeing others' votes.

Scheme: commit(value, nonce) = H(nonce || value)
Reveal: provide (value, nonce), verifier checks H(nonce || value) == commitment
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from src.hashing.utils import serialize_data, sha256_hash


@dataclass(frozen=True)
class Commitment:
    """An opaque commitment to a hidden value.

    Attributes:
        digest: The commitment hash H(nonce || value).
        nonce_hex: Hex-encoded random nonce (kept secret until reveal).
    """

    digest: str
    nonce_hex: str

    def verify(self, value: Any) -> bool:
        """Verify that a revealed value matches this commitment.

        Args:
            value: The claimed original value.

        Returns:
            True if H(nonce || value) equals the stored digest.
        """
        raw = bytes.fromhex(self.nonce_hex) + serialize_data(value)
        return sha256_hash(raw) == self.digest


class CommitmentScheme:
    """Factory for creating and verifying hash-based commitments.

    Uses a random 32-byte nonce for hiding. The commitment is
    computationally binding (can't find two values with the same
    commitment) and hiding (commitment reveals nothing about the value).
    """

    def __init__(self, nonce_bytes: int = 32) -> None:
        """Initialize the commitment scheme.

        Args:
            nonce_bytes: Number of random bytes for the nonce.
        """
        self.nonce_bytes = nonce_bytes

    def commit(self, value: Any, nonce: bytes | None = None) -> Commitment:
        """Create a commitment to a value.

        Args:
            value: The value to commit to.
            nonce: Optional explicit nonce (random if not provided).

        Returns:
            A Commitment containing the digest and nonce.
        """
        if nonce is None:
            nonce = os.urandom(self.nonce_bytes)
        raw = nonce + serialize_data(value)
        digest = sha256_hash(raw)
        return Commitment(digest=digest, nonce_hex=nonce.hex())

    @staticmethod
    def verify(commitment: Commitment, value: Any) -> bool:
        """Verify a commitment against a revealed value.

        Args:
            commitment: The original commitment.
            value: The revealed value.

        Returns:
            True if the value matches the commitment.
        """
        return commitment.verify(value)

    def batch_commit(self, values: list[Any]) -> list[Commitment]:
        """Create commitments for multiple values.

        Args:
            values: List of values to commit to.

        Returns:
            List of commitments, one per value.
        """
        return [self.commit(v) for v in values]

    @staticmethod
    def batch_verify(
        commitments: list[Commitment], values: list[Any]
    ) -> list[bool]:
        """Verify multiple commitment-value pairs.

        Args:
            commitments: List of commitments.
            values: List of revealed values.

        Returns:
            List of booleans indicating which commitments verified.
        """
        return [c.verify(v) for c, v in zip(commitments, values)]


if __name__ == "__main__":
    print("=== Commitment Scheme Demo ===\n")

    scheme = CommitmentScheme()

    vote = "approve"
    commitment = scheme.commit(vote)
    print(f"Vote:       '{vote}'")
    print(f"Commitment: {commitment.digest[:32]}...")
    print(f"Nonce:      {commitment.nonce_hex[:16]}...\n")

    print(f"Verify 'approve': {scheme.verify(commitment, 'approve')}")
    print(f"Verify 'reject':  {scheme.verify(commitment, 'reject')}\n")

    print("--- Batch commit/verify ---")
    votes = ["approve", "reject", "approve", "abstain"]
    commitments = scheme.batch_commit(votes)
    results = CommitmentScheme.batch_verify(commitments, votes)
    for v, c, r in zip(votes, commitments, results):
        print(f"  '{v}' -> {c.digest[:16]}... verified={r}")

    tampered = ["approve", "approve", "approve", "abstain"]
    results2 = CommitmentScheme.batch_verify(commitments, tampered)
    print(f"\nTampered verification: {results2}")
