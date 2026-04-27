"""Sparse Merkle tree for key-value commitments.

A sparse Merkle tree (SMT) is a Merkle tree over a fixed 2^depth address
space where most leaves are empty (default hash). It supports:
- Inclusion proofs: prove a key has a specific value
- Exclusion proofs: prove a key is NOT in the tree (has default value)

Only non-empty subtrees are materialized, keeping storage proportional
to the number of entries rather than the address space size.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from src.hashing.utils import hash_concat, hash_data, sha256_hash


def _default_hash(depth: int, cache: dict[int, str] | None = None) -> str:
    """Compute the default hash for an empty subtree at a given depth.

    The default hash at depth 0 (leaf) is H(""). At depth d, it is
    H(default(d-1) || default(d-1)).

    Args:
        depth: Depth of the subtree (0 = leaf level).
        cache: Optional memoization cache.

    Returns:
        Hex-encoded default hash.
    """
    if cache is None:
        cache = {}
    if depth in cache:
        return cache[depth]
    if depth == 0:
        result = sha256_hash(b"")
    else:
        child = _default_hash(depth - 1, cache)
        result = hash_concat(child, child)
    cache[depth] = result
    return result


@dataclass
class SparseMerkleProof:
    """Proof of inclusion or exclusion in a sparse Merkle tree.

    Attributes:
        key: The key being proved.
        value: The value at the key (empty string if absent).
        siblings: Sibling hashes from leaf to root.
        root: The expected root hash.
        included: Whether the key is present in the tree.
    """

    key: str
    value: str
    siblings: list[str]
    root: str
    included: bool

    def verify(self, tree_depth: int) -> bool:
        """Verify this sparse Merkle proof.

        Args:
            tree_depth: Depth of the sparse Merkle tree.

        Returns:
            True if the proof is valid.
        """
        if self.included:
            current = hash_data(f"{self.key}:{self.value}")
        else:
            current = _default_hash(0)

        key_hash = hash_data(self.key)
        key_bits = int(key_hash, 16)

        for i, sibling in enumerate(self.siblings):
            bit = (key_bits >> i) & 1
            if bit == 0:
                current = hash_concat(current, sibling)
            else:
                current = hash_concat(sibling, current)

        return current == self.root


class SparseMerkleTree:
    """Sparse Merkle tree with inclusion and exclusion proofs.

    Uses a virtual tree of depth `tree_depth` but only stores non-empty
    nodes. Keys are mapped to leaf positions by hashing.

    Attributes:
        depth: Tree depth (address space is 2^depth).
        store: Mapping from key to value for non-empty leaves.
    """

    def __init__(self, tree_depth: int = 16) -> None:
        """Initialize an empty sparse Merkle tree.

        Args:
            tree_depth: Depth of the tree. Larger = more address space.
        """
        self.depth = tree_depth
        self.store: dict[str, str] = {}
        self._default_cache: dict[int, str] = {}
        self._nodes: dict[tuple[int, int], str] = {}
        self._rebuild()

    def _leaf_position(self, key: str) -> int:
        """Map a key to a leaf position using its hash.

        Args:
            key: The key string.

        Returns:
            Integer leaf position in [0, 2^depth).
        """
        key_hash = hash_data(key)
        return int(key_hash, 16) % (1 << self.depth)

    def _default(self, depth: int) -> str:
        """Get the default hash for an empty subtree."""
        return _default_hash(depth, self._default_cache)

    def _rebuild(self) -> None:
        """Rebuild the tree from the current store."""
        self._nodes.clear()
        num_leaves = 1 << self.depth

        for key, value in self.store.items():
            pos = self._leaf_position(key)
            self._nodes[(0, pos)] = hash_data(f"{key}:{value}")

        for d in range(self.depth):
            level_size = 1 << (self.depth - d)
            for i in range(0, level_size, 2):
                left = self._nodes.get((d, i), self._default(d))
                right = self._nodes.get((d, i + 1), self._default(d))
                parent_hash = hash_concat(left, right)
                if parent_hash != self._default(d + 1):
                    self._nodes[(d + 1, i // 2)] = parent_hash

    @property
    def root_hash(self) -> str:
        """Return the current root hash."""
        return self._nodes.get(
            (self.depth, 0), self._default(self.depth)
        )

    def insert(self, key: str, value: str) -> str:
        """Insert or update a key-value pair.

        Args:
            key: The key to insert.
            value: The value to associate.

        Returns:
            The new root hash.
        """
        self.store[key] = value
        self._rebuild()
        return self.root_hash

    def get(self, key: str) -> Optional[str]:
        """Retrieve the value for a key.

        Args:
            key: The key to look up.

        Returns:
            The value, or None if the key is not in the tree.
        """
        return self.store.get(key)

    def delete(self, key: str) -> str:
        """Remove a key from the tree.

        Args:
            key: The key to remove.

        Returns:
            The new root hash.
        """
        self.store.pop(key, None)
        self._rebuild()
        return self.root_hash

    def generate_proof(self, key: str) -> SparseMerkleProof:
        """Generate an inclusion or exclusion proof for a key.

        Args:
            key: The key to prove.

        Returns:
            A SparseMerkleProof (inclusion if key exists, exclusion otherwise).
        """
        pos = self._leaf_position(key)
        siblings: list[str] = []

        for d in range(self.depth):
            sibling_pos = pos ^ 1
            sibling_hash = self._nodes.get((d, sibling_pos), self._default(d))
            siblings.append(sibling_hash)
            pos //= 2

        included = key in self.store
        value = self.store.get(key, "")

        return SparseMerkleProof(
            key=key,
            value=value,
            siblings=siblings,
            root=self.root_hash,
            included=included,
        )

    def __len__(self) -> int:
        """Return the number of entries in the tree."""
        return len(self.store)

    def __repr__(self) -> str:
        """Return a string representation."""
        return f"SparseMerkleTree(depth={self.depth}, entries={len(self)}, root={self.root_hash[:16]}...)"


if __name__ == "__main__":
    print("=== Sparse Merkle Tree Demo ===\n")

    smt = SparseMerkleTree(tree_depth=8)

    entries = {"alice": "100", "bob": "50", "carol": "75"}
    for k, v in entries.items():
        root = smt.insert(k, v)
        print(f"Insert '{k}': {v} -> root={root[:24]}...")

    print(f"\nTree: {smt}")
    print(f"Get 'alice': {smt.get('alice')}")
    print(f"Get 'eve':   {smt.get('eve')}\n")

    print("--- Inclusion proof ---")
    proof = smt.generate_proof("alice")
    print(f"Key: {proof.key}, included: {proof.included}")
    print(f"Siblings: {len(proof.siblings)}")
    print(f"Valid: {proof.verify(smt.depth)}\n")

    print("--- Exclusion proof ---")
    proof_exc = smt.generate_proof("eve")
    print(f"Key: {proof_exc.key}, included: {proof_exc.included}")
    print(f"Valid: {proof_exc.verify(smt.depth)}")
