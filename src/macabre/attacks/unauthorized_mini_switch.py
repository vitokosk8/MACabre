"""Unauthorized mini-switch / hub: several client devices behind one authorized port.

A port authorized for one device can be connected to an unmanaged switch or a hub. The
devices behind it then reach the network through that port, and an authenticator that
checked only the first MAC address does not check the others.

This module sends one frame from each client MAC the operator lists, from one interface,
which is what a port sees when several devices share it through a mini-switch. Unlike
port security exhaustion, the addresses are chosen by the operator, not generated, and the
goal is to see whether the port carries and learns several clients.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, Raw, sendp
from scapy.packet import Packet

from macabre.attacks.common import BROADCAST_MAC, normalize_unicast_mac

MAX_CLIENTS = 16
PAYLOAD = b"MACabre mini-switch probe"


@dataclass(frozen=True)
class MiniSwitchConfig:
    iface: str                          # the port the mini-switch is connected to
    client_macs: tuple[str, ...]        # MACs of the devices behind the mini-switch, at least two
    dry_run: bool = False               # build frames but do not send them

    def __post_init__(self) -> None:
        if not 2 <= len(self.client_macs) <= MAX_CLIENTS:
            raise ValueError(f"Give between 2 and {MAX_CLIENTS} client MACs.")
        normalized = [normalize_unicast_mac(mac) for mac in self.client_macs]
        if len(set(normalized)) != len(normalized):
            raise ValueError("Client MACs must be distinct.")


@dataclass
class MiniSwitchStats:
    frames: int = 0
    clients: int = 0
    status: str = ""


def client_frame(client_mac: str) -> Packet:
    """One frame from a client MAC, to the broadcast address, with a fixed payload."""
    return Ether(src=normalize_unicast_mac(client_mac), dst=BROADCAST_MAC) / Raw(PAYLOAD)


def run_mini_switch(
    config: MiniSwitchConfig,
    stop_event: threading.Event,
    on_progress: Callable[[MiniSwitchStats], None],
    send: Callable[..., Any] | None = None,
) -> MiniSwitchStats:
    """Send one frame from each client MAC, in order, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        stats = MiniSwitchStats(
            clients=len(config.client_macs),
            status=(
                f"Dry run: would send one frame from each of {len(config.client_macs)} client MAC(s) "
                f"through this port. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = MiniSwitchStats(clients=len(config.client_macs))
    for mac in config.client_macs:
        if stop_event.is_set():
            break
        send(client_frame(mac), iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
    return stats
