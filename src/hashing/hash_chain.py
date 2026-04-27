"""Hash chain construction and verification.

A hash chain links records by including the hash of the previous record
in each new one: h_i = H(h_{i-1} || d_i). Modifying any past record
invalidates every subsequent hash, making tampering detectable.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from src.hashing.utils import hash_concat, hash_data, serialize_data, sha256_hash


@dataclass
class ChainBlock:
    """A single block in the hash chain.

    Attributes:
        index: Position in the chain (0-indexed).
        data: The payload stored in this block.
        timestamp: Unix timestamp of creation.
        prev_hash: Hash of the previous block (empty string for genesis).
        hash: This block's hash = H(prev_hash || serialized_data).
    """

    index: int
    data: Any
    timestamp: float
    prev_hash: str
    hash: str

    @staticmethod
    def compute_hash(prev_hash: str, data: Any, timestamp: float) -> str:
        """Compute the block hash from its components.

        Args:
            prev_hash: Hash of the previous block.
            data: Block payload.
            timestamp: Block creation timestamp.

        Returns:
            Hex-encoded SHA-256 hash.
        """
        content = f"{prev_hash}:{serialize_data(data).hex()}:{timestamp}"
        return sha256_hash(content.encode("utf-8"))


class HashChain:
    """Append-only hash chain with tamper detection.

    Each block's hash depends on the previous block's hash, creating
    a chain where modifying any block invalidates all subsequent hashes.

    Attributes:
        blocks: Ordered list of chain blocks.
    """

    def __init__(self) -> None:
        """Initialize an empty hash chain with a genesis block."""
        self.blocks: list[ChainBlock] = []
        self._create_genesis()

    def _create_genesis(self) -> None:
        """Create the genesis (first) block with empty previous hash."""
        ts = time.time()
        genesis_hash = ChainBlock.compute_hash("", "genesis", ts)
        genesis = ChainBlock(
            index=0, data="genesis", timestamp=ts, prev_hash="", hash=genesis_hash
        )
        self.blocks.append(genesis)

    @property
    def head(self) -> str:
        """Return the hash of the latest block (chain head)."""
        return self.blocks[-1].hash

    @property
    def length(self) -> int:
        """Return the number of blocks in the chain."""
        return len(self.blocks)

    def append(self, data: Any) -> ChainBlock:
        """Append a new block to the chain.

        Args:
            data: Payload for the new block.

        Returns:
            The newly created block.
        """
        prev = self.blocks[-1]
        ts = time.time()
        block_hash = ChainBlock.compute_hash(prev.hash, data, ts)
        block = ChainBlock(
            index=prev.index + 1,
            data=data,
            timestamp=ts,
            prev_hash=prev.hash,
            hash=block_hash,
        )
        self.blocks.append(block)
        return block

    def verify(self) -> tuple[bool, Optional[int]]:
        """Verify the integrity of the entire chain.

        Recomputes each block's hash and checks it matches the stored
        hash and the next block's prev_hash pointer.

        Returns:
            Tuple of (is_valid, first_invalid_index). If valid,
            first_invalid_index is None.
        """
        for i, block in enumerate(self.blocks):
            expected = ChainBlock.compute_hash(
                block.prev_hash, block.data, block.timestamp
            )
            if block.hash != expected:
                return False, i
            if i > 0 and block.prev_hash != self.blocks[i - 1].hash:
                return False, i
        return True, None

    def verify_from(self, start_index: int) -> tuple[bool, Optional[int]]:
        """Verify chain integrity from a checkpoint.

        Args:
            start_index: Index to start verification from.

        Returns:
            Tuple of (is_valid, first_invalid_index).
        """
        if start_index < 0 or start_index >= len(self.blocks):
            return False, start_index
        for i in range(start_index, len(self.blocks)):
            block = self.blocks[i]
            expected = ChainBlock.compute_hash(
                block.prev_hash, block.data, block.timestamp
            )
            if block.hash != expected:
                return False, i
            if i > 0 and block.prev_hash != self.blocks[i - 1].hash:
                return False, i
        return True, None

    def get_block(self, index: int) -> Optional[ChainBlock]:
        """Retrieve a block by index.

        Args:
            index: Block index.

        Returns:
            The block, or None if index is out of range.
        """
        if 0 <= index < len(self.blocks):
            return self.blocks[index]
        return None


if __name__ == "__main__":
    print("=== Hash Chain Demo ===\n")

    chain = HashChain()
    transactions = [
        {"sender": "alice", "receiver": "bob", "amount": 100},
        {"sender": "bob", "receiver": "carol", "amount": 50},
        {"sender": "carol", "receiver": "dave", "amount": 25},
        {"sender": "dave", "receiver": "alice", "amount": 10},
    ]

    for tx in transactions:
        block = chain.append(tx)
        print(f"Block {block.index}: {block.hash[:16]}... | {tx}")

    print(f"\nChain length: {chain.length}")
    print(f"Chain head:   {chain.head[:16]}...")

    valid, bad_idx = chain.verify()
    print(f"Chain valid:  {valid}\n")

    print("--- Tampering with block 2 ---")
    chain.blocks[2].data = {"sender": "bob", "receiver": "eve", "amount": 999}
    valid, bad_idx = chain.verify()
    print(f"Chain valid:  {valid}")
    print(f"First invalid block: {bad_idx}")
