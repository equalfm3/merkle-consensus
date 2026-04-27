"""PBFT protocol — pre-prepare, prepare, commit phases.

Three-phase consensus: leader proposes, replicas exchange prepare/commit
messages, value committed when 2f+1 matching commits collected.
Simplified from full PBFT: no checkpointing, view changes in view_change.py.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional

from src.hashing.utils import hash_data
from src.consensus.log import ConsensusLog, LogEntry, MessageType


class PBFTPhase(Enum):
    """Current phase of a PBFT consensus round."""
    IDLE = auto()
    PRE_PREPARE = auto()
    PREPARE = auto()
    COMMIT = auto()
    COMMITTED = auto()


@dataclass
class PBFTMessage:
    """A PBFT protocol message.

    Attributes:
        msg_type: Type of consensus message.
        view: Current view number.
        sequence: Sequence number.
        digest: Hash of the proposed value.
        sender: Sender node ID.
        value: The actual proposed value (only in pre-prepare).
    """

    msg_type: MessageType
    view: int
    sequence: int
    digest: str
    sender: int
    value: Optional[str] = None


@dataclass
class PBFTState:
    """State of a single PBFT consensus round.

    Attributes:
        sequence: The sequence number for this round.
        view: The view number.
        phase: Current phase.
        proposed_value: The value being agreed upon.
        digest: Hash of the proposed value.
        committed: Whether the value has been committed.
    """

    sequence: int
    view: int
    phase: PBFTPhase = PBFTPhase.IDLE
    proposed_value: Optional[str] = None
    digest: str = ""
    committed: bool = False


class PBFTProtocol:
    """Simplified PBFT consensus protocol for a single node.

    Manages the three-phase protocol: pre-prepare, prepare, commit.
    Each node maintains a consensus log and tracks its current phase.

    Attributes:
        node_id: This node's identifier.
        num_nodes: Total nodes in the network.
        view: Current view number (determines leader).
        log: Consensus message log.
    """

    def __init__(self, node_id: int, num_nodes: int) -> None:
        """Initialize the PBFT protocol for a node.

        Args:
            node_id: This node's ID.
            num_nodes: Total number of nodes (must be >= 3f+1).
        """
        self.node_id = node_id
        self.num_nodes = num_nodes
        self.view = 0
        self.log = ConsensusLog(num_nodes)
        self._sequence = 0
        self._rounds: dict[int, PBFTState] = {}
        self._committed_values: list[tuple[int, str]] = []

    @property
    def max_faults(self) -> int:
        """Maximum Byzantine faults tolerated."""
        return (self.num_nodes - 1) // 3

    @property
    def leader(self) -> int:
        """Current leader node ID (view mod num_nodes)."""
        return self.view % self.num_nodes

    @property
    def is_leader(self) -> bool:
        """Check if this node is the current leader."""
        return self.node_id == self.leader
    def propose(self, value: str) -> list[PBFTMessage]:
        """Propose a value as leader (Phase 1: Pre-prepare).

        Args:
            value: The value to propose.

        Returns:
            List of pre-prepare messages to broadcast.

        Raises:
            RuntimeError: If this node is not the leader.
        """
        if not self.is_leader:
            raise RuntimeError(f"Node {self.node_id} is not the leader (leader={self.leader})")

        self._sequence += 1
        digest = hash_data(value)
        state = PBFTState(
            sequence=self._sequence,
            view=self.view,
            phase=PBFTPhase.PRE_PREPARE,
            proposed_value=value,
            digest=digest,
        )
        self._rounds[self._sequence] = state

        entry = LogEntry(MessageType.PRE_PREPARE, self.view, self._sequence, digest, self.node_id)
        self.log.add(entry)

        return [
            PBFTMessage(
                msg_type=MessageType.PRE_PREPARE,
                view=self.view,
                sequence=self._sequence,
                digest=digest,
                sender=self.node_id,
                value=value,
            )
        ]

    def handle_pre_prepare(self, msg: PBFTMessage) -> list[PBFTMessage]:
        """Handle a pre-prepare message (transition to Prepare phase).

        Args:
            msg: The pre-prepare message from the leader.

        Returns:
            List of prepare messages to broadcast.
        """
        if msg.view != self.view:
            return []
        if msg.sender != self.leader:
            return []
        if msg.value is None:
            return []

        expected_digest = hash_data(msg.value)
        if expected_digest != msg.digest:
            return []

        self.log.add(LogEntry(
            MessageType.PRE_PREPARE, msg.view, msg.sequence, msg.digest, msg.sender
        ))

        state = PBFTState(
            sequence=msg.sequence,
            view=msg.view,
            phase=PBFTPhase.PREPARE,
            proposed_value=msg.value,
            digest=msg.digest,
        )
        self._rounds[msg.sequence] = state

        prepare = PBFTMessage(
            msg_type=MessageType.PREPARE,
            view=self.view,
            sequence=msg.sequence,
            digest=msg.digest,
            sender=self.node_id,
        )
        self.log.add(LogEntry(
            MessageType.PREPARE, self.view, msg.sequence, msg.digest, self.node_id
        ))
        return [prepare]

    def handle_prepare(self, msg: PBFTMessage) -> list[PBFTMessage]:
        """Handle a prepare message. If quorum reached, send commit.

        Args:
            msg: A prepare message from another node.

        Returns:
            List of commit messages if prepare quorum is reached.
        """
        self.log.add(LogEntry(
            msg.msg_type, msg.view, msg.sequence, msg.digest, msg.sender
        ))

        state = self._rounds.get(msg.sequence)
        if state is None or state.phase == PBFTPhase.COMMITTED:
            return []

        if self.log.is_prepared(msg.sequence, msg.view, msg.digest):
            if state.phase in (PBFTPhase.PREPARE, PBFTPhase.PRE_PREPARE):
                state.phase = PBFTPhase.COMMIT
                commit = PBFTMessage(
                    msg_type=MessageType.COMMIT,
                    view=self.view,
                    sequence=msg.sequence,
                    digest=msg.digest,
                    sender=self.node_id,
                )
                self.log.add(LogEntry(
                    MessageType.COMMIT, self.view, msg.sequence, msg.digest, self.node_id
                ))
                return [commit]
        return []

    def handle_commit(self, msg: PBFTMessage) -> Optional[str]:
        """Handle a commit message. If quorum reached, commit the value.

        Args:
            msg: A commit message from another node.

        Returns:
            The committed value if commit quorum is reached, else None.
        """
        self.log.add(LogEntry(
            msg.msg_type, msg.view, msg.sequence, msg.digest, msg.sender
        ))

        state = self._rounds.get(msg.sequence)
        if state is None or state.committed:
            return None

        if self.log.is_committed(msg.sequence, msg.view, msg.digest):
            state.phase = PBFTPhase.COMMITTED
            state.committed = True
            self._committed_values.append((msg.sequence, state.proposed_value or ""))
            return state.proposed_value
        return None

    @property
    def committed_values(self) -> list[tuple[int, str]]:
        """Return all committed (sequence, value) pairs."""
        return list(self._committed_values)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PBFT consensus simulation")
    parser.add_argument("--nodes", type=int, default=4, help="Number of nodes")
    parser.add_argument("--byzantine", type=int, default=1, help="Byzantine nodes")
    parser.add_argument("--rounds", type=int, default=3, help="Consensus rounds")
    args = parser.parse_args()

    n = args.nodes
    print(f"=== PBFT Consensus Demo ({n} nodes, f={args.byzantine}) ===\n")

    nodes = [PBFTProtocol(i, n) for i in range(n)]
    honest = list(range(n - args.byzantine))

    for r in range(1, args.rounds + 1):
        value = f"tx_batch_{r}"
        leader = nodes[0]
        pre_prep = leader.propose(value)
        print(f"Round {r}: Leader proposes '{value}'")
        # Replicas handle pre-prepare -> produce prepares
        prepares: list[PBFTMessage] = []
        for msg in pre_prep:
            for i in honest:
                if i != leader.node_id:
                    prepares.extend(nodes[i].handle_pre_prepare(msg))
        # Leader also sends its own prepare
        for msg in pre_prep:
            prepares.append(PBFTMessage(
                MessageType.PREPARE, msg.view, msg.sequence, msg.digest, 0))
            nodes[0].log.add(LogEntry(
                MessageType.PREPARE, msg.view, msg.sequence, msg.digest, 0))
        # All honest nodes handle all prepares -> produce commits
        commits: list[PBFTMessage] = []
        for msg in prepares:
            for i in honest:
                commits.extend(nodes[i].handle_prepare(msg))
        # All honest nodes handle all commits
        for msg in commits:
            for i in honest:
                result = nodes[i].handle_commit(msg)
                if result:
                    print(f"  Node {i} committed: '{result}'")
    print(f"\nNode 0 committed: {nodes[0].committed_values}")
