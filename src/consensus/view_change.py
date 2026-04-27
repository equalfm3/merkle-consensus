"""View change protocol for leader failure.

When the PBFT leader is faulty or unresponsive, replicas initiate a
view change to elect a new leader. The protocol collects 2f+1
view-change messages, each containing the node's latest prepared
certificates, and the new leader constructs a new-view message.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from src.consensus.log import ConsensusLog, LogEntry, MessageType


@dataclass
class PreparedCertificate:
    """Evidence that a value was prepared in a previous view.

    Attributes:
        sequence: The sequence number.
        view: The view in which it was prepared.
        digest: The digest of the prepared value.
        value: The prepared value.
    """

    sequence: int
    view: int
    digest: str
    value: str


@dataclass
class ViewChangeMessage:
    """A view-change message sent by a replica.

    Attributes:
        new_view: The proposed new view number.
        sender: Node ID of the sender.
        last_committed_seq: Last committed sequence number.
        prepared_certs: Prepared certificates from the sender.
    """

    new_view: int
    sender: int
    last_committed_seq: int
    prepared_certs: list[PreparedCertificate] = field(default_factory=list)


@dataclass
class NewViewMessage:
    """A new-view message constructed by the new leader.

    Attributes:
        new_view: The new view number.
        leader: The new leader's node ID.
        view_changes: The 2f+1 view-change messages collected.
        pre_prepares: Pre-prepare messages for uncommitted sequences.
    """

    new_view: int
    leader: int
    view_changes: list[ViewChangeMessage]
    pre_prepares: list[tuple[int, str]]


class ViewChangeManager:
    """Manages the view change protocol.

    Collects view-change messages and determines when a new view
    can be established. The new leader is view_number % num_nodes.

    Attributes:
        num_nodes: Total number of nodes.
        max_faults: Maximum Byzantine faults (f).
        current_view: The current view number.
    """

    def __init__(self, num_nodes: int, current_view: int = 0) -> None:
        """Initialize the view change manager.

        Args:
            num_nodes: Total number of nodes.
            current_view: Starting view number.
        """
        self.num_nodes = num_nodes
        self.max_faults = (num_nodes - 1) // 3
        self.quorum_size = 2 * self.max_faults + 1
        self.current_view = current_view
        self._vc_messages: dict[int, list[ViewChangeMessage]] = {}
        self._completed_views: set[int] = set()

    def initiate_view_change(
        self,
        sender: int,
        last_committed_seq: int,
        prepared_certs: list[PreparedCertificate] | None = None,
    ) -> ViewChangeMessage:
        """Create a view-change message for the next view.

        Args:
            sender: The node initiating the view change.
            last_committed_seq: Sender's last committed sequence.
            prepared_certs: Sender's prepared certificates.

        Returns:
            A ViewChangeMessage for the next view.
        """
        new_view = self.current_view + 1
        msg = ViewChangeMessage(
            new_view=new_view,
            sender=sender,
            last_committed_seq=last_committed_seq,
            prepared_certs=prepared_certs or [],
        )
        return msg

    def receive_view_change(self, msg: ViewChangeMessage) -> Optional[NewViewMessage]:
        """Process a received view-change message.

        If 2f+1 view-change messages are collected for the same new view,
        and this node is the new leader, construct a new-view message.

        Args:
            msg: The received view-change message.

        Returns:
            A NewViewMessage if quorum is reached and we are the new leader,
            else None.
        """
        if msg.new_view in self._completed_views:
            return None

        vc_list = self._vc_messages.setdefault(msg.new_view, [])
        existing_senders = {m.sender for m in vc_list}
        if msg.sender not in existing_senders:
            vc_list.append(msg)

        if len(vc_list) >= self.quorum_size:
            self._completed_views.add(msg.new_view)
            new_leader = msg.new_view % self.num_nodes
            pre_prepares = self._compute_pre_prepares(vc_list)
            return NewViewMessage(
                new_view=msg.new_view,
                leader=new_leader,
                view_changes=list(vc_list),
                pre_prepares=pre_prepares,
            )
        return None

    def _compute_pre_prepares(
        self, vc_messages: list[ViewChangeMessage]
    ) -> list[tuple[int, str]]:
        """Determine which sequences need re-proposal in the new view.

        Collects all prepared certificates from view-change messages
        and identifies the highest prepared sequence for each slot.

        Args:
            vc_messages: The collected view-change messages.

        Returns:
            List of (sequence, digest) pairs to re-propose.
        """
        prepared: dict[int, PreparedCertificate] = {}
        for vc in vc_messages:
            for cert in vc.prepared_certs:
                existing = prepared.get(cert.sequence)
                if existing is None or cert.view > existing.view:
                    prepared[cert.sequence] = cert
        return [(cert.sequence, cert.digest) for cert in prepared.values()]

    def apply_new_view(self, msg: NewViewMessage) -> None:
        """Apply a new-view message, advancing to the new view.

        Args:
            msg: The new-view message from the new leader.
        """
        self.current_view = msg.new_view
        self._vc_messages.pop(msg.new_view, None)

    @property
    def pending_view_changes(self) -> dict[int, int]:
        """Return pending view changes and their message counts."""
        return {v: len(msgs) for v, msgs in self._vc_messages.items()}


if __name__ == "__main__":
    print("=== View Change Protocol Demo ===\n")

    num_nodes = 4
    managers = [ViewChangeManager(num_nodes, current_view=0) for _ in range(num_nodes)]

    print(f"Nodes: {num_nodes}, quorum: {managers[0].quorum_size}")
    print(f"Current leader: node {0 % num_nodes}")
    print("Simulating leader failure...\n")

    certs = [PreparedCertificate(sequence=1, view=0, digest="abc", value="tx1")]

    vc_messages = []
    for i in [1, 2, 3]:
        msg = managers[i].initiate_view_change(
            sender=i, last_committed_seq=0, prepared_certs=certs
        )
        vc_messages.append(msg)
        print(f"Node {i} sends view-change for view {msg.new_view}")

    new_view_msg = None
    for msg in vc_messages:
        for i in range(num_nodes):
            result = managers[i].receive_view_change(msg)
            if result is not None:
                new_view_msg = result
                print(f"\nNew-view message created! New leader: node {result.leader}")
                print(f"Re-proposals: {result.pre_prepares}")

    if new_view_msg:
        for m in managers:
            m.apply_new_view(new_view_msg)
        print(f"\nAll nodes advanced to view {managers[0].current_view}")
        print(f"New leader: node {managers[0].current_view % num_nodes}")
