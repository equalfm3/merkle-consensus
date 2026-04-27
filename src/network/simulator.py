"""Network simulator with configurable latency and fault injection.

Simulates a fully-connected network of consensus nodes, routing
messages between them with optional fault injection. Supports
running multi-round consensus simulations and collecting metrics.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from typing import Optional

from src.network.node import ConsensusNode, NetworkMessage
from src.network.faults import (
    FaultInjector,
    FaultConfig,
    FaultType,
    create_partition_faults,
    create_byzantine_faults,
)


@dataclass
class SimulationMetrics:
    """Metrics collected during a simulation run.

    Attributes:
        total_messages: Total messages sent.
        dropped_messages: Messages dropped by fault injection.
        rounds_completed: Number of consensus rounds completed.
        blocks_committed: Total blocks committed across all nodes.
        message_rounds: Number of message-passing rounds executed.
    """

    total_messages: int = 0
    dropped_messages: int = 0
    rounds_completed: int = 0
    blocks_committed: int = 0
    message_rounds: int = 0


class NetworkSimulator:
    """Simulates a network of PBFT consensus nodes.

    Creates nodes, routes messages between them, and optionally
    injects faults to test protocol resilience.

    Attributes:
        num_nodes: Total number of nodes.
        num_byzantine: Number of Byzantine nodes.
        nodes: List of consensus nodes.
        fault_injector: Optional fault injector.
        metrics: Simulation metrics.
    """

    def __init__(
        self,
        num_nodes: int,
        num_byzantine: int = 0,
        fault_configs: list[FaultConfig] | None = None,
        seed: int | None = None,
    ) -> None:
        """Initialize the network simulator.

        Args:
            num_nodes: Total number of nodes (must be >= 3f+1).
            num_byzantine: Number of Byzantine nodes.
            fault_configs: Fault injection configurations.
            seed: Random seed for reproducibility.
        """
        self.num_nodes = num_nodes
        self.num_byzantine = num_byzantine
        self.nodes: list[ConsensusNode] = []
        self.metrics = SimulationMetrics()

        for i in range(num_nodes):
            is_byz = i >= (num_nodes - num_byzantine)
            self.nodes.append(ConsensusNode(i, num_nodes, is_byzantine=is_byz))

        self.fault_injector: Optional[FaultInjector] = None
        if fault_configs:
            self.fault_injector = FaultInjector(fault_configs, seed=seed)

    @property
    def leader(self) -> ConsensusNode:
        """Return the current leader node."""
        view = self.nodes[0].pbft.view
        leader_id = view % self.num_nodes
        return self.nodes[leader_id]

    def submit_transactions(self, transactions: list[str]) -> None:
        """Submit transactions to the current leader.

        Args:
            transactions: List of transaction strings.
        """
        leader = self.leader
        for tx in transactions:
            leader.submit_transaction(tx)

    def run_consensus_round(self, max_message_rounds: int = 20) -> bool:
        """Run a single consensus round to completion.

        The leader proposes a block, and messages are routed between
        nodes until consensus is reached or max rounds are exhausted.

        Args:
            max_message_rounds: Maximum message-passing rounds.

        Returns:
            True if consensus was reached.
        """
        leader = self.leader
        initial_msgs = leader.propose_block()
        if not initial_msgs:
            return False

        all_msgs = list(initial_msgs)
        self.metrics.total_messages += len(all_msgs)

        for _ in range(max_message_rounds):
            if self.fault_injector:
                all_msgs = self.fault_injector.process(all_msgs)

            next_msgs: list[NetworkMessage] = []
            for msg in all_msgs:
                for node in self.nodes:
                    if node.node_id != msg.source:
                        responses = node.process_message(msg)
                        next_msgs.extend(responses)

            self.metrics.total_messages += len(next_msgs)
            self.metrics.message_rounds += 1

            if not next_msgs:
                break
            all_msgs = next_msgs

        committed = sum(len(n.committed_blocks) for n in self.nodes)
        if committed > self.metrics.blocks_committed:
            self.metrics.blocks_committed = committed
            self.metrics.rounds_completed += 1
            return True
        return False

    def run_simulation(
        self,
        transaction_batches: list[list[str]],
        max_message_rounds: int = 20,
    ) -> SimulationMetrics:
        """Run a full simulation with multiple transaction batches.

        Args:
            transaction_batches: List of transaction batches.
            max_message_rounds: Max message rounds per consensus round.

        Returns:
            Simulation metrics.
        """
        for batch in transaction_batches:
            self.submit_transactions(batch)
            self.run_consensus_round(max_message_rounds)

        if self.fault_injector:
            fi_stats = self.fault_injector.stats
            self.metrics.dropped_messages = fi_stats.get("DROP", 0)

        return self.metrics

    def get_node_states(self) -> list[dict]:
        """Get the state of all nodes.

        Returns:
            List of node state dictionaries.
        """
        states = []
        for node in self.nodes:
            states.append({
                "node_id": node.node_id,
                "is_leader": node.is_leader,
                "is_byzantine": node.is_byzantine,
                "committed_blocks": len(node.committed_blocks),
                "view": node.pbft.view,
            })
        return states


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network consensus simulator")
    parser.add_argument("--nodes", type=int, default=7, help="Number of nodes")
    parser.add_argument("--faults", type=int, default=2, help="Byzantine nodes")
    parser.add_argument(
        "--scenario",
        choices=["normal", "partition", "byzantine"],
        default="normal",
        help="Fault scenario",
    )
    args = parser.parse_args()

    print(f"=== Network Simulator ({args.nodes} nodes, {args.faults} faults) ===\n")

    fault_configs: list[FaultConfig] | None = None
    if args.scenario == "partition":
        partitioned = set(range(args.nodes - args.faults, args.nodes))
        fault_configs = create_partition_faults(partitioned)
        print(f"Partition scenario: nodes {partitioned} isolated")
    elif args.scenario == "byzantine":
        byz_nodes = set(range(args.nodes - args.faults, args.nodes))
        fault_configs = create_byzantine_faults(byz_nodes)
        print(f"Byzantine scenario: nodes {byz_nodes} malicious")

    sim = NetworkSimulator(
        num_nodes=args.nodes,
        num_byzantine=args.faults,
        fault_configs=fault_configs,
        seed=42,
    )

    batches = [
        [f"tx_{r}_{i}" for i in range(3)]
        for r in range(5)
    ]

    metrics = sim.run_simulation(batches)

    print(f"\nSimulation Results:")
    print(f"  Rounds completed:  {metrics.rounds_completed}")
    print(f"  Blocks committed:  {metrics.blocks_committed}")
    print(f"  Total messages:    {metrics.total_messages}")
    print(f"  Dropped messages:  {metrics.dropped_messages}")
    print(f"  Message rounds:    {metrics.message_rounds}\n")

    print("Node States:")
    for state in sim.get_node_states():
        role = "LEADER" if state["is_leader"] else "replica"
        byz = " (BYZANTINE)" if state["is_byzantine"] else ""
        print(f"  Node {state['node_id']}: {role}{byz}, blocks={state['committed_blocks']}")
