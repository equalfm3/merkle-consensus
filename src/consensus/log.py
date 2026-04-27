"""Consensus message log and quorum tracking.

Tracks pre-prepare, prepare, and commit messages for each consensus
sequence number. A quorum is reached when 2f+1 matching messages are
collected, where f is the maximum number of Byzantine faults tolerated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class MessageType(Enum):
    """Types of PBFT consensus messages."""

    PRE_PREPARE = auto()
    PREPARE = auto()
    COMMIT = auto()
    VIEW_CHANGE = auto()
    NEW_VIEW = auto()


@dataclass(frozen=True)
class LogEntry:
    """A single consensus message in the log.

    Attributes:
        msg_type: Type of consensus message.
        view: The view number (leader epoch).
        sequence: Sequence number for ordering.
        digest: Hash digest of the proposed value.
        sender: Node ID of the message sender.
    """

    msg_type: MessageType
    view: int
    sequence: int
    digest: str
    sender: int


class ConsensusLog:
    """Message log with quorum tracking for PBFT consensus.

    Collects messages and determines when quorum thresholds are met
    for prepare and commit phases.

    Attributes:
        num_nodes: Total number of nodes in the network.
        max_faults: Maximum Byzantine faults tolerated (f).
        quorum_size: Number of matching messages needed (2f + 1).
    """

    def __init__(self, num_nodes: int) -> None:
        """Initialize the consensus log.

        Args:
            num_nodes: Total number of nodes (must be >= 4 for f >= 1).
        """
        self.num_nodes = num_nodes
        self.max_faults = (num_nodes - 1) // 3
        self.quorum_size = 2 * self.max_faults + 1
        self._entries: list[LogEntry] = []
        self._by_sequence: dict[int, list[LogEntry]] = {}

    def add(self, entry: LogEntry) -> None:
        """Add a message to the log.

        Args:
            entry: The consensus message to record.
        """
        self._entries.append(entry)
        self._by_sequence.setdefault(entry.sequence, []).append(entry)

    def get_messages(
        self,
        sequence: int,
        msg_type: MessageType,
        view: Optional[int] = None,
        digest: Optional[str] = None,
    ) -> list[LogEntry]:
        """Retrieve messages matching the given criteria.

        Args:
            sequence: Sequence number to filter by.
            msg_type: Message type to filter by.
            view: Optional view number filter.
            digest: Optional digest filter.

        Returns:
            List of matching log entries.
        """
        entries = self._by_sequence.get(sequence, [])
        result = [e for e in entries if e.msg_type == msg_type]
        if view is not None:
            result = [e for e in result if e.view == view]
        if digest is not None:
            result = [e for e in result if e.digest == digest]
        return result

    def has_pre_prepare(self, sequence: int, view: int) -> bool:
        """Check if a pre-prepare exists for this sequence and view.

        Args:
            sequence: Sequence number.
            view: View number.

        Returns:
            True if a pre-prepare message exists.
        """
        msgs = self.get_messages(sequence, MessageType.PRE_PREPARE, view=view)
        return len(msgs) > 0

    def is_prepared(
        self, sequence: int, view: int, digest: str
    ) -> bool:
        """Check if the prepare quorum is met.

        Prepared means: has pre-prepare AND 2f+1 matching prepares.

        Args:
            sequence: Sequence number.
            view: View number.
            digest: Expected digest.

        Returns:
            True if the node is prepared for this sequence.
        """
        if not self.has_pre_prepare(sequence, view):
            return False
        prepares = self.get_messages(
            sequence, MessageType.PREPARE, view=view, digest=digest
        )
        unique_senders = {e.sender for e in prepares}
        return len(unique_senders) >= self.quorum_size

    def is_committed(
        self, sequence: int, view: int, digest: str
    ) -> bool:
        """Check if the commit quorum is met.

        Committed means: is_prepared AND 2f+1 matching commits.

        Args:
            sequence: Sequence number.
            view: View number.
            digest: Expected digest.

        Returns:
            True if the value is committed for this sequence.
        """
        if not self.is_prepared(sequence, view, digest):
            return False
        commits = self.get_messages(
            sequence, MessageType.COMMIT, view=view, digest=digest
        )
        unique_senders = {e.sender for e in commits}
        return len(unique_senders) >= self.quorum_size

    def count_unique_senders(
        self, sequence: int, msg_type: MessageType, view: int
    ) -> int:
        """Count unique senders for a message type at a sequence.

        Args:
            sequence: Sequence number.
            msg_type: Message type.
            view: View number.

        Returns:
            Number of unique senders.
        """
        msgs = self.get_messages(sequence, msg_type, view=view)
        return len({e.sender for e in msgs})

    @property
    def total_entries(self) -> int:
        """Total number of log entries."""
        return len(self._entries)

    def clear_sequence(self, sequence: int) -> None:
        """Remove all entries for a sequence (after execution).

        Args:
            sequence: Sequence number to clear.
        """
        self._by_sequence.pop(sequence, None)
        self._entries = [e for e in self._entries if e.sequence != sequence]


if __name__ == "__main__":
    print("=== Consensus Log Demo ===\n")

    log = ConsensusLog(num_nodes=4)
    print(f"Nodes: {log.num_nodes}, max faults: {log.max_faults}, quorum: {log.quorum_size}\n")

    digest = "abc123"
    log.add(LogEntry(MessageType.PRE_PREPARE, view=0, sequence=1, digest=digest, sender=0))

    for sender in [0, 1, 2]:
        log.add(LogEntry(MessageType.PREPARE, view=0, sequence=1, digest=digest, sender=sender))

    print(f"Has pre-prepare(seq=1, view=0): {log.has_pre_prepare(1, 0)}")
    print(f"Prepared(seq=1): {log.is_prepared(1, 0, digest)}")
    print(f"Committed(seq=1): {log.is_committed(1, 0, digest)}\n")

    for sender in [0, 1, 2]:
        log.add(LogEntry(MessageType.COMMIT, view=0, sequence=1, digest=digest, sender=sender))

    print(f"Committed(seq=1): {log.is_committed(1, 0, digest)}")
    print(f"Total entries: {log.total_entries}")
