"""Merkle tree construction (binary).

Builds a binary Merkle tree bottom-up from leaf values. Each leaf is
hashed, then pairs of hashes are combined: parent = H(left || right).
If the number of leaves is odd, the last leaf is duplicated.

The root hash commits to all leaves — changing any leaf changes the root.
Proof generation and verification are in proof.py.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from typing import Optional

from src.hashing.utils import hash_data, hash_concat


@dataclass
class MerkleNode:
    """A node in the Merkle tree.

    Attributes:
        hash: The node's hash value.
        left: Left child node (None for leaves).
        right: Right child node (None for leaves).
        parent: Parent node (None for root).
        index: Leaf index if this is a leaf node, else -1.
    """

    hash: str
    left: Optional[MerkleNode] = None
    right: Optional[MerkleNode] = None
    parent: Optional[MerkleNode] = None
    index: int = -1

    @property
    def is_leaf(self) -> bool:
        """Check if this node is a leaf."""
        return self.left is None and self.right is None


class MerkleTree:
    """Binary Merkle tree with O(log n) inclusion proofs.

    Builds the tree bottom-up from a list of data items. Supports
    proof generation for any leaf and root recomputation.

    Attributes:
        root: The root node of the tree.
        leaves: List of leaf nodes in order.
        levels: All tree levels, from leaves (index 0) to root.
    """

    def __init__(self, data_items: list[str]) -> None:
        """Build a Merkle tree from data items.

        Args:
            data_items: List of string values to use as leaves.

        Raises:
            ValueError: If data_items is empty.
        """
        if not data_items:
            raise ValueError("Cannot build Merkle tree from empty data")
        self.data_items = list(data_items)
        self.leaves: list[MerkleNode] = []
        self.levels: list[list[MerkleNode]] = []
        self.root: MerkleNode = self._build()

    def _build(self) -> MerkleNode:
        """Build the tree bottom-up.

        Returns:
            The root node.
        """
        self.leaves = [
            MerkleNode(hash=hash_data(item), index=i)
            for i, item in enumerate(self.data_items)
        ]
        current_level = list(self.leaves)
        self.levels = [current_level]

        while len(current_level) > 1:
            next_level: list[MerkleNode] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent_hash = hash_concat(left.hash, right.hash)
                parent = MerkleNode(hash=parent_hash, left=left, right=right)
                left.parent = parent
                if right is not left:
                    right.parent = parent
                next_level.append(parent)
            current_level = next_level
            self.levels.append(current_level)

        return current_level[0]

    @property
    def root_hash(self) -> str:
        """Return the Merkle root hash."""
        return self.root.hash

    @property
    def depth(self) -> int:
        """Return the depth of the tree (number of levels - 1)."""
        return len(self.levels) - 1

    @property
    def num_leaves(self) -> int:
        """Return the number of leaves."""
        return len(self.leaves)

    def get_proof_hashes(self, leaf_index: int) -> list[tuple[str, str]]:
        """Get the sibling hashes needed for an inclusion proof.

        Args:
            leaf_index: Index of the leaf to prove.

        Returns:
            List of (hash, side) tuples where side is 'left' or 'right',
            indicating the sibling's position relative to the path node.

        Raises:
            IndexError: If leaf_index is out of range.
        """
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise IndexError(f"Leaf index {leaf_index} out of range [0, {len(self.leaves)})")

        proof: list[tuple[str, str]] = []
        idx = leaf_index

        for level in self.levels[:-1]:
            sibling_idx = idx ^ 1
            if sibling_idx < len(level):
                side = "left" if sibling_idx < idx else "right"
                proof.append((level[sibling_idx].hash, side))
            else:
                proof.append((level[idx].hash, "right"))
            idx //= 2

        return proof

    def get_leaf_hash(self, leaf_index: int) -> str:
        """Get the hash of a specific leaf.

        Args:
            leaf_index: Index of the leaf.

        Returns:
            The leaf's hash value.
        """
        return self.leaves[leaf_index].hash

    def __repr__(self) -> str:
        """Return a string representation."""
        return f"MerkleTree(leaves={self.num_leaves}, root={self.root_hash[:16]}...)"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build a Merkle tree")
    parser.add_argument(
        "--leaves",
        type=str,
        default="alice:100,bob:50,carol:75,dave:200",
        help="Comma-separated leaf values",
    )
    args = parser.parse_args()

    items = args.leaves.split(",")
    tree = MerkleTree(items)

    print("=== Merkle Tree Demo ===\n")
    print(f"Leaves: {items}")
    print(f"Tree depth: {tree.depth}")
    print(f"Root hash:  {tree.root_hash}\n")

    for i, item in enumerate(items):
        proof = tree.get_proof_hashes(i)
        print(f"Leaf {i} ('{item}'):")
        print(f"  Hash: {tree.get_leaf_hash(i)[:32]}...")
        print(f"  Proof ({len(proof)} siblings):")
        for h, side in proof:
            print(f"    {side}: {h[:32]}...")
