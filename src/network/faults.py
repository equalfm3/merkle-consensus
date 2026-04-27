"""Byzantine fault injection — drop, delay, corrupt messages.

Provides configurable fault models for testing consensus protocol
resilience. Faults can be injected probabilistically or targeted
at specific nodes or message types.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from src.network.node import NetworkMessage


class FaultType(Enum):
    """Types of Byzantine faults that can be injected."""

    DROP = auto()
    DELAY = auto()
    CORRUPT = auto()
    DUPLICATE = auto()
    REORDER = auto()


@dataclass
class FaultConfig:
    """Configuration for a specific fault type.

    Attributes:
        fault_type: The type of fault.
        probability: Probability of applying this fault (0.0 to 1.0).
        target_nodes: If set, only apply to messages from these nodes.
        target_types: If set, only apply to these message classes.
        delay_ticks: For DELAY faults, how many ticks to delay.
    """

    fault_type: FaultType
    probability: float = 0.1
    target_nodes: Optional[set[int]] = None
    target_types: Optional[set[str]] = None
    delay_ticks: int = 1


class FaultInjector:
    """Injects Byzantine faults into network messages.

    Processes messages through configured fault rules, potentially
    dropping, delaying, corrupting, duplicating, or reordering them.

    Attributes:
        configs: List of fault configurations.
        seed: Random seed for reproducibility.
    """

    def __init__(
        self,
        configs: list[FaultConfig] | None = None,
        seed: int | None = None,
    ) -> None:
        """Initialize the fault injector.

        Args:
            configs: Fault configurations to apply.
            seed: Random seed for reproducibility.
        """
        self.configs = configs or []
        self._rng = random.Random(seed)
        self._delayed: list[tuple[int, NetworkMessage]] = []
        self._stats: dict[FaultType, int] = {ft: 0 for ft in FaultType}

    def _should_apply(self, config: FaultConfig, msg: NetworkMessage) -> bool:
        """Check if a fault config applies to a message.

        Args:
            config: The fault configuration.
            msg: The network message.

        Returns:
            True if the fault should be applied.
        """
        if config.target_nodes and msg.source not in config.target_nodes:
            return False
        if config.target_types and msg.msg_class not in config.target_types:
            return False
        return self._rng.random() < config.probability

    def process(self, messages: list[NetworkMessage]) -> list[NetworkMessage]:
        """Process messages through fault injection.

        Args:
            messages: List of messages to potentially fault.

        Returns:
            List of messages after fault injection (some may be
            dropped, delayed, corrupted, duplicated, or reordered).
        """
        result: list[NetworkMessage] = []

        ready_delayed = [
            (ticks - 1, msg) for ticks, msg in self._delayed
        ]
        self._delayed = [(t, m) for t, m in ready_delayed if t > 0]
        result.extend(m for t, m in ready_delayed if t <= 0)

        for msg in messages:
            dropped = False
            delayed = False

            for config in self.configs:
                if not self._should_apply(config, msg):
                    continue

                if config.fault_type == FaultType.DROP:
                    self._stats[FaultType.DROP] += 1
                    dropped = True
                    break

                elif config.fault_type == FaultType.DELAY:
                    self._stats[FaultType.DELAY] += 1
                    self._delayed.append((config.delay_ticks, msg))
                    delayed = True
                    break

                elif config.fault_type == FaultType.CORRUPT:
                    self._stats[FaultType.CORRUPT] += 1
                    corrupted = NetworkMessage(
                        payload=msg.payload,
                        source=msg.source,
                        destination=msg.destination,
                        msg_class="corrupted",
                    )
                    result.append(corrupted)
                    dropped = True
                    break

                elif config.fault_type == FaultType.DUPLICATE:
                    self._stats[FaultType.DUPLICATE] += 1
                    result.append(msg)
                    result.append(msg)
                    dropped = True
                    break

            if not dropped and not delayed:
                result.append(msg)

        for config in self.configs:
            if config.fault_type == FaultType.REORDER:
                if self._rng.random() < config.probability and len(result) > 1:
                    self._stats[FaultType.REORDER] += 1
                    self._rng.shuffle(result)
                    break

        return result

    @property
    def stats(self) -> dict[str, int]:
        """Return fault injection statistics."""
        return {ft.name: count for ft, count in self._stats.items()}

    def reset_stats(self) -> None:
        """Reset fault injection counters."""
        self._stats = {ft: 0 for ft in FaultType}


def create_partition_faults(
    partitioned_nodes: set[int], drop_probability: float = 1.0
) -> list[FaultConfig]:
    """Create fault configs that simulate a network partition.

    Messages from partitioned nodes are dropped with high probability,
    simulating a network split.

    Args:
        partitioned_nodes: Set of node IDs in the partitioned group.
        drop_probability: Probability of dropping messages.

    Returns:
        List of FaultConfig for the partition scenario.
    """
    return [
        FaultConfig(
            fault_type=FaultType.DROP,
            probability=drop_probability,
            target_nodes=partitioned_nodes,
        )
    ]


def create_byzantine_faults(
    byzantine_nodes: set[int],
    corrupt_probability: float = 0.5,
) -> list[FaultConfig]:
    """Create fault configs simulating Byzantine behavior.

    Byzantine nodes may corrupt or drop messages.

    Args:
        byzantine_nodes: Set of Byzantine node IDs.
        corrupt_probability: Probability of corruption.

    Returns:
        List of FaultConfig for Byzantine behavior.
    """
    return [
        FaultConfig(
            fault_type=FaultType.CORRUPT,
            probability=corrupt_probability,
            target_nodes=byzantine_nodes,
        ),
        FaultConfig(
            fault_type=FaultType.DROP,
            probability=corrupt_probability * 0.5,
            target_nodes=byzantine_nodes,
        ),
    ]


if __name__ == "__main__":
    print("=== Fault Injection Demo ===\n")

    msgs = [
        NetworkMessage(payload=f"msg_{i}", source=i % 4, msg_class="pbft")
        for i in range(10)
    ]

    print(f"Original messages: {len(msgs)}")

    configs = [
        FaultConfig(FaultType.DROP, probability=0.2),
        FaultConfig(FaultType.DELAY, probability=0.1, delay_ticks=2),
        FaultConfig(FaultType.REORDER, probability=0.3),
    ]
    injector = FaultInjector(configs, seed=42)

    result = injector.process(msgs)
    print(f"After injection:   {len(result)}")
    print(f"Stats: {injector.stats}\n")

    print("--- Partition scenario ---")
    partition_configs = create_partition_faults({2, 3})
    partition_injector = FaultInjector(partition_configs, seed=42)
    result2 = partition_injector.process(msgs)
    print(f"After partition: {len(result2)} messages")
    print(f"Stats: {partition_injector.stats}\n")

    print("--- Byzantine scenario ---")
    byz_configs = create_byzantine_faults({1})
    byz_injector = FaultInjector(byz_configs, seed=42)
    result3 = byz_injector.process(msgs)
    print(f"After Byzantine: {len(result3)} messages")
    print(f"Stats: {byz_injector.stats}")
