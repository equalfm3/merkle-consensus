"""Network simulation — nodes, message passing, and fault injection."""

from src.network.node import ConsensusNode
from src.network.simulator import NetworkSimulator
from src.network.faults import FaultInjector, FaultType

__all__ = ["ConsensusNode", "NetworkSimulator", "FaultInjector", "FaultType"]
