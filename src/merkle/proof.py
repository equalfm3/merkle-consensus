"""Merkle inclusion proof generation and verification.

An inclusion proof demonstrates that a specific leaf is part of a Merkle
tree without revealing the entire tree. The proof consists of O(log n)
sibling hashes along the path from the leaf to the root. The verifier
recomputes the root from the leaf and siblings, checking it matches.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

from src.hashing.utils import hash_concat, hash_data


@dataclass(frozen=True)
class ProofStep:
    """A single step in a Merkle inclusion proof.

    Attributes:
        hash: The sibling hash at this level.
        side: Whether the sibling is on the 'left' or 'right'.
    """

    hash: str
    side: str


@dataclass
class MerkleProof:
    """A complete Merkle inclusion proof.

    Attributes:
        leaf_data: The original leaf data.
        leaf_hash: Hash of the leaf data.
        leaf_index: Position of the leaf in the tree.
        steps: Ordered list of proof steps from leaf to root.
        root_hash: The expected Merkle root.
    """

    leaf_data: str
    leaf_hash: str
    leaf_index: int
    steps: list[ProofStep]
    root_hash: str

    def verify(self) -> bool:
        """Verify this proof by recomputing the root.

        Returns:
            True if the recomputed root matches the expected root.
        """
        return verify_proof(
            leaf_data=self.leaf_data,
            proof_steps=self.steps,
            expected_root=self.root_hash,
        )

    @property
    def proof_size(self) -> int:
        """Number of hashes in the proof (tree depth)."""
        return len(self.steps)

    def to_dict(self) -> dict:
        """Serialize the proof to a dictionary.

        Returns:
            Dictionary representation of the proof.
        """
        return {
            "leaf_data": self.leaf_data,
            "leaf_hash": self.leaf_hash,
            "leaf_index": self.leaf_index,
            "steps": [{"hash": s.hash, "side": s.side} for s in self.steps],
            "root_hash": self.root_hash,
        }

    @classmethod
    def from_dict(cls, data: dict) -> MerkleProof:
        """Deserialize a proof from a dictionary.

        Args:
            data: Dictionary with proof fields.

        Returns:
            Reconstructed MerkleProof.
        """
        steps = [ProofStep(hash=s["hash"], side=s["side"]) for s in data["steps"]]
        return cls(
            leaf_data=data["leaf_data"],
            leaf_hash=data["leaf_hash"],
            leaf_index=data["leaf_index"],
            steps=steps,
            root_hash=data["root_hash"],
        )


def verify_proof(
    leaf_data: str,
    proof_steps: list[ProofStep],
    expected_root: str,
) -> bool:
    """Verify a Merkle inclusion proof.

    Recomputes the root hash by walking from the leaf to the root,
    combining with sibling hashes at each level.

    Args:
        leaf_data: The original leaf data string.
        proof_steps: Ordered sibling hashes with side indicators.
        expected_root: The known Merkle root to verify against.

    Returns:
        True if the recomputed root matches expected_root.
    """
    current = hash_data(leaf_data)

    for step in proof_steps:
        if step.side == "left":
            current = hash_concat(step.hash, current)
        else:
            current = hash_concat(current, step.hash)

    return current == expected_root


def generate_proof(
    tree: "MerkleTree", leaf_index: int  # noqa: F821
) -> MerkleProof:
    """Generate an inclusion proof for a leaf in a Merkle tree.

    Args:
        tree: The Merkle tree instance.
        leaf_index: Index of the leaf to prove.

    Returns:
        A complete MerkleProof.

    Raises:
        IndexError: If leaf_index is out of range.
    """
    raw_steps = tree.get_proof_hashes(leaf_index)
    steps = [ProofStep(hash=h, side=s) for h, s in raw_steps]
    return MerkleProof(
        leaf_data=tree.data_items[leaf_index],
        leaf_hash=tree.get_leaf_hash(leaf_index),
        leaf_index=leaf_index,
        steps=steps,
        root_hash=tree.root_hash,
    )


if __name__ == "__main__":
    from src.merkle.tree import MerkleTree

    parser = argparse.ArgumentParser(description="Merkle proof generation and verification")
    parser.add_argument("--leaf", type=str, default="bob:50", help="Leaf value to prove")
    parser.add_argument("--root", type=str, default=None, help="Expected root hash")
    parser.add_argument("--proof", type=str, default=None, help="Comma-separated proof hashes")
    args = parser.parse_args()

    print("=== Merkle Proof Demo ===\n")

    items = ["alice:100", "bob:50", "carol:75", "dave:200"]
    tree = MerkleTree(items)

    for i, item in enumerate(items):
        proof = generate_proof(tree, i)
        valid = proof.verify()
        print(f"Leaf {i} ('{item}'): proof_size={proof.proof_size}, valid={valid}")

    print(f"\nRoot: {tree.root_hash}")

    print("\n--- Tamper detection ---")
    proof = generate_proof(tree, 1)
    proof_dict = proof.to_dict()
    proof_dict["leaf_data"] = "bob:999"
    tampered = MerkleProof.from_dict(proof_dict)
    print(f"Original 'bob:50' proof valid:  {proof.verify()}")
    print(f"Tampered 'bob:999' proof valid: {tampered.verify()}")
