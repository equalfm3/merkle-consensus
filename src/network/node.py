"""Consensus node with message handling.

Wraps the PBFT protocol with a message queue and block building,
forming a complete consensus participant that can be plugged into
the network simulator.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

from src.consensus.pbft import PBFTProtocol, PBFTMessage, PBFTPhase
from src.consensus.log import MessageType, LogEntry
from src.consensus.block import Block, BlockBuilder
from src.consensus.view_change import (
    ViewChangeManager,
    ViewChangeMessage,
    PreparedCertificate,
)


@dataclass
class NetworkMessage:
    """A message in transit between nodes.

    Attributes:
        payload: The actual protocol message.
        source: Sender node ID.
        destination: Receiver node ID (-1 for broadcast).
        msg_class: Classification for routing ('pbft' or 'view_change').
    """

    payload: Any
    source: int
    destination: int = -1
    msg_class: str = "pbft"


class ConsensusNode:
    """A complete consensus node with PBFT and view change support.

    Combines the PBFT protocol, view change manager, and block builder
    into a single node that processes messages from its inbox.

    Attributes:
        node_id: This node's identifier.
        num_nodes: Total nodes in the network.
        is_byzantine: Whether this node behaves maliciously.
    """

    def __init__(
        self, node_id: int, num_nodes: int, is_byzantine: bool = False
    ) -> None:
        """Initialize a consensus node.

        Args:
            node_id: This node's ID.
            num_nodes: Total number of nodes.
            is_byzantine: If True, node may behave maliciously.
        """
        self.node_id = node_id
        self.num_nodes = num_nodes
        self.is_byzantine = is_byzantine
        self.pbft = PBFTProtocol(node_id, num_nodes)
        self.view_mgr = ViewChangeManager(num_nodes)
        self.block_builder = BlockBuilder(proposer=node_id)
        self.inbox: deque[NetworkMessage] = deque()
        self.committed_blocks: list[Block] = []
        self._pending_txs: list[str] = []

    @property
    def is_leader(self) -> bool:
        """Check if this node is the current leader."""
        return self.pbft.is_leader

    def submit_transaction(self, tx: str) -> None:
        """Submit a transaction to this node's pending pool.

        Args:
            tx: Transaction string.
        """
        self._pending_txs.append(tx)

    def propose_block(self) -> list[NetworkMessage]:
        """Propose a new block from pending transactions.

        The leader broadcasts pre-prepare and also adds its own prepare
        message to the log (standard PBFT: leader participates in prepare).

        Returns:
            List of network messages to broadcast.

        Raises:
            RuntimeError: If this node is not the leader.
        """
        if not self._pending_txs:
            return []

        value = ",".join(self._pending_txs)
        msgs = self.pbft.propose(value)
        self._pending_txs.clear()

        out: list[NetworkMessage] = []
        for msg in msgs:
            out.append(NetworkMessage(
                payload=msg, source=self.node_id, destination=-1, msg_class="pbft"
            ))
            # Leader self-prepares (adds its own prepare to the log)
            self.pbft.log.add(LogEntry(
                MessageType.PREPARE, msg.view, msg.sequence, msg.digest, self.node_id
            ))
            prepare = PBFTMessage(
                msg_type=MessageType.PREPARE,
                view=msg.view,
                sequence=msg.sequence,
                digest=msg.digest,
                sender=self.node_id,
            )
            out.append(NetworkMessage(
                payload=prepare, source=self.node_id, destination=-1, msg_class="pbft"
            ))
        return out

    def process_message(self, net_msg: NetworkMessage) -> list[NetworkMessage]:
        """Process an incoming network message.

        Routes the message to the appropriate handler based on its class
        and type, and returns any outgoing messages.

        Args:
            net_msg: The incoming network message.

        Returns:
            List of outgoing network messages.
        """
        if self.is_byzantine:
            return []

        if net_msg.msg_class == "view_change":
            return self._handle_view_change(net_msg.payload)

        msg: PBFTMessage = net_msg.payload
        outgoing: list[NetworkMessage] = []

        if msg.msg_type == MessageType.PRE_PREPARE:
            prepares = self.pbft.handle_pre_prepare(msg)
            for p in prepares:
                outgoing.append(NetworkMessage(
                    payload=p, source=self.node_id, destination=-1
                ))

        elif msg.msg_type == MessageType.PREPARE:
            commits = self.pbft.handle_prepare(msg)
            for c in commits:
                outgoing.append(NetworkMessage(
                    payload=c, source=self.node_id, destination=-1
                ))

        elif msg.msg_type == MessageType.COMMIT:
            result = self.pbft.handle_commit(msg)
            if result is not None:
                txs = result.split(",")
                block = self.block_builder.build(txs)
                self.committed_blocks.append(block)

        return outgoing

    def _handle_view_change(
        self, msg: ViewChangeMessage
    ) -> list[NetworkMessage]:
        """Handle a view-change message.

        Args:
            msg: The view-change message.

        Returns:
            List of outgoing messages (new-view if quorum reached).
        """
        result = self.view_mgr.receive_view_change(msg)
        if result is not None:
            self.view_mgr.apply_new_view(result)
            self.pbft.view = result.new_view
            return [
                NetworkMessage(
                    payload=result,
                    source=self.node_id,
                    destination=-1,
                    msg_class="new_view",
                )
            ]
        return []

    def initiate_view_change(self) -> list[NetworkMessage]:
        """Initiate a view change (when leader is suspected faulty).

        Returns:
            List of view-change messages to broadcast.
        """
        last_seq = len(self.committed_blocks)
        msg = self.view_mgr.initiate_view_change(
            sender=self.node_id, last_committed_seq=last_seq
        )
        return [
            NetworkMessage(
                payload=msg,
                source=self.node_id,
                destination=-1,
                msg_class="view_change",
            )
        ]

    def __repr__(self) -> str:
        """Return a string representation."""
        role = "leader" if self.is_leader else "replica"
        byz = " (byzantine)" if self.is_byzantine else ""
        return (
            f"ConsensusNode(id={self.node_id}, {role}{byz}, "
            f"blocks={len(self.committed_blocks)})"
        )


if __name__ == "__main__":
    print("=== Consensus Node Demo ===\n")

    num_nodes = 4
    nodes = [ConsensusNode(i, num_nodes) for i in range(num_nodes)]
    nodes[3] = ConsensusNode(3, num_nodes, is_byzantine=True)

    leader = nodes[0]
    leader.submit_transaction("alice->bob:100")
    leader.submit_transaction("carol->dave:50")
    print(f"Leader: {leader}")
    print(f"Proposing block with 2 transactions...\n")

    all_msgs = leader.propose_block()
    rounds = 0
    while all_msgs and rounds < 10:
        next_msgs: list[NetworkMessage] = []
        for msg in all_msgs:
            for node in nodes:
                if node.node_id != msg.source:
                    responses = node.process_message(msg)
                    next_msgs.extend(responses)
        all_msgs = next_msgs
        rounds += 1

    print(f"Consensus completed in {rounds} message rounds\n")
    for node in nodes:
        print(f"  {node}")
