"""Block structure with Merkle state root.

A block bundles a set of transactions with a Merkle root committing
to the state after execution. Blocks are hash-chained: each block
includes the hash of the previous block header, forming an immutable
ledger once consensus is reached.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from src.hashing.utils import hash_data, sha256_hash, serialize_data
from src.merkle.tree import MerkleTree


@dataclass
class BlockHeader:
    """Header of a consensus block.

    Attributes:
        block_number: Sequential block number.
        prev_hash: Hash of the previous block header.
        merkle_root: Merkle root of the transactions in this block.
        timestamp: Unix timestamp of block creation.
        proposer: Node ID of the block proposer (leader).
        view: Consensus view number when this block was proposed.
    """

    block_number: int
    prev_hash: str
    merkle_root: str
    timestamp: float
    proposer: int
    view: int

    def compute_hash(self) -> str:
        """Compute the hash of this block header.

        Returns:
            Hex-encoded SHA-256 hash of the header fields.
        """
        content = (
            f"{self.block_number}:{self.prev_hash}:{self.merkle_root}:"
            f"{self.timestamp}:{self.proposer}:{self.view}"
        )
        return sha256_hash(content.encode("utf-8"))


@dataclass
class Block:
    """A complete block with header and transactions.

    Attributes:
        header: The block header with metadata and Merkle root.
        transactions: List of transactions included in this block.
        hash: The block's hash (computed from header).
    """

    header: BlockHeader
    transactions: list[str]
    hash: str = ""

    def __post_init__(self) -> None:
        """Compute the block hash after initialization."""
        if not self.hash:
            self.hash = self.header.compute_hash()

    def verify_merkle_root(self) -> bool:
        """Verify that the Merkle root matches the transactions.

        Returns:
            True if the Merkle root in the header matches a tree
            built from the transactions.
        """
        if not self.transactions:
            return self.header.merkle_root == hash_data("")
        tree = MerkleTree(self.transactions)
        return tree.root_hash == self.header.merkle_root

    @property
    def num_transactions(self) -> int:
        """Number of transactions in this block."""
        return len(self.transactions)


class BlockBuilder:
    """Builds blocks with proper chaining and Merkle roots.

    Maintains the chain state (previous hash, block number) and
    constructs new blocks from transaction batches.
    """

    def __init__(self, proposer: int = 0, view: int = 0) -> None:
        """Initialize the block builder.

        Args:
            proposer: Default proposer node ID.
            view: Initial consensus view number.
        """
        self.proposer = proposer
        self.view = view
        self._next_number = 0
        self._prev_hash = "0" * 64

    def build(
        self,
        transactions: list[str],
        proposer: Optional[int] = None,
        view: Optional[int] = None,
    ) -> Block:
        """Build a new block from transactions.

        Args:
            transactions: List of transaction strings.
            proposer: Override proposer ID.
            view: Override view number.

        Returns:
            A new Block with computed Merkle root and chain link.
        """
        if transactions:
            tree = MerkleTree(transactions)
            merkle_root = tree.root_hash
        else:
            merkle_root = hash_data("")

        header = BlockHeader(
            block_number=self._next_number,
            prev_hash=self._prev_hash,
            merkle_root=merkle_root,
            timestamp=time.time(),
            proposer=proposer if proposer is not None else self.proposer,
            view=view if view is not None else self.view,
        )

        block = Block(header=header, transactions=list(transactions))
        self._prev_hash = block.hash
        self._next_number += 1
        return block

    @property
    def chain_height(self) -> int:
        """Number of blocks built so far."""
        return self._next_number


def verify_chain(blocks: list[Block]) -> tuple[bool, Optional[int]]:
    """Verify a sequence of blocks forms a valid chain.

    Checks that each block's prev_hash matches the previous block's
    hash, and that Merkle roots are correct.

    Args:
        blocks: Ordered list of blocks.

    Returns:
        Tuple of (is_valid, first_invalid_index).
    """
    for i, block in enumerate(blocks):
        if block.hash != block.header.compute_hash():
            return False, i
        if not block.verify_merkle_root():
            return False, i
        if i > 0 and block.header.prev_hash != blocks[i - 1].hash:
            return False, i
    return True, None


if __name__ == "__main__":
    print("=== Block Structure Demo ===\n")

    builder = BlockBuilder(proposer=0, view=0)

    blocks: list[Block] = []
    tx_batches = [
        ["alice->bob:100", "carol->dave:50"],
        ["bob->carol:25", "dave->alice:10", "alice->carol:30"],
        ["eve->bob:75"],
    ]

    for txs in tx_batches:
        block = builder.build(txs)
        blocks.append(block)
        print(f"Block {block.header.block_number}:")
        print(f"  Hash:        {block.hash[:32]}...")
        print(f"  Prev hash:   {block.header.prev_hash[:32]}...")
        print(f"  Merkle root: {block.header.merkle_root[:32]}...")
        print(f"  Transactions: {block.num_transactions}")
        print(f"  Merkle valid: {block.verify_merkle_root()}\n")

    valid, bad = verify_chain(blocks)
    print(f"Chain valid: {valid}")
    print(f"Chain height: {builder.chain_height}")
