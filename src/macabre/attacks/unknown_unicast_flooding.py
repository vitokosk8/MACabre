"""Unknown unicast flooding: listens for unicast frames the switch floods to every port.

A switch that does not know the port of a unicast destination floods the frame to all ports
in the VLAN. A host on any port can then see unicast traffic addressed to other hosts.

This module is passive. It sends nothing: it captures for a set time and counts the unicast
frames that are not addressed to this host, and the destinations they go to. It does not
fill the switch's table, because it learns no addresses.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

from scapy.all import AsyncSniffer, Ether
from scapy.packet import Packet

from macabre.attacks.common import read_interface_mac

MAX_DURATION = 3600.0      # seconds; longer captures are refused
TICK_SECONDS = 1.0         # progress is reported this often


@dataclass(frozen=True)
class UnknownUnicastConfig:
    iface: str
    duration: float = 30.0      # seconds to listen; 0 = until stopped
    dry_run: bool = False       # do not capture, only describe what would be captured

    def __post_init__(self) -> None:
        if not 0 <= self.duration <= MAX_DURATION:
            raise ValueError(f"Duration must be between 0 and {MAX_DURATION:g} seconds.")


@dataclass
class UnknownUnicastStats:
    frames: int = 0
    destinations: set[str] = field(default_factory=set)
    status: str = ""


def flooded_destination(packet: Packet, own_mac: str) -> str | None:
    """The destination of a unicast frame addressed to another host, or None for anything else."""
    if not packet.haslayer(Ether):
        return None
    dst = packet[Ether].dst.lower()
    src = packet[Ether].src.lower()
    if dst == own_mac or src == own_mac:
        return None
    if dst == "ff:ff:ff:ff:ff:ff":
        return None
    if int(dst.split(":")[0], 16) & 0x01:  # group bit set: multicast, not unicast
        return None
    return dst


def observe(stats: UnknownUnicastStats, packet: Packet, own_mac: str) -> None:
    """Count one captured frame if it is unicast traffic addressed to another host."""
    dst = flooded_destination(packet, own_mac)
    if dst is None:
        return
    stats.frames += 1
    stats.destinations.add(dst)


def run_unknown_unicast_flooding(
    config: UnknownUnicastConfig,
    stop_event: threading.Event,
    on_progress: Callable[[UnknownUnicastStats], None],
    own_mac: str | None = None,
    make_sniffer: Callable[..., Any] | None = None,
) -> UnknownUnicastStats:
    """Capture for `duration` seconds (or until `stop_event`) and count flooded unicast frames."""
    make_sniffer = make_sniffer or AsyncSniffer

    if config.dry_run:
        stats = UnknownUnicastStats(
            status=(
                f"Dry run: would listen on this port for {config.duration:g} seconds and count "
                f"unicast frames addressed to other hosts. Nothing captured."
            ),
        )
        on_progress(replace(stats))
        return stats

    own = (own_mac or read_interface_mac(config.iface)).lower()
    stats = UnknownUnicastStats()

    def handle(packet: Packet) -> None:
        observe(stats, packet, own)

    sniffer = make_sniffer(iface=config.iface, store=False, prn=handle)
    sniffer.start()
    elapsed = 0.0
    try:
        while not stop_event.is_set() and (config.duration == 0 or elapsed < config.duration):
            stop_event.wait(TICK_SECONDS)
            elapsed += TICK_SECONDS
            on_progress(replace(stats, destinations=set(stats.destinations)))
    finally:
        sniffer.stop()
    stats.status = (
        f"Flooded unicast frames seen: {stats.frames} to {len(stats.destinations)} destination(s)."
    )
    return stats
