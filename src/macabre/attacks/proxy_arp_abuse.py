"""Proxy ARP probe: checks which addresses on other subnets a router answers for.

A host sends ARP requests for addresses that are outside its own subnet. A router with proxy
ARP enabled answers with its own MAC address, so the host sends traffic to the router, which
forwards it to the other network. This module asks for a list of addresses outside the probe's
subnet, and records which ones get an answer and the MAC that answers.

The probe sends requests and reads replies. It does not forward traffic or change anything on
the router.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

from scapy.all import ARP, Ether, srp
from scapy.packet import Packet

from macabre.attacks.arp_spoofing import parse_ipv4
from macabre.attacks.common import BROADCAST_MAC, normalize_unicast_mac, read_interface_mac

MAX_TARGETS = 32
MAX_TIMEOUT = 10.0
ARP_REQUEST = 1
ZERO_MAC = "00:00:00:00:00:00"


@dataclass(frozen=True)
class ProxyArpProbeConfig:
    iface: str                  # attacker interface, on the segment being tested
    sender_ip: str              # the attacker's address on that segment
    prefix_length: int          # the segment's prefix, e.g. 24
    targets: tuple[str, ...]    # addresses to ask for; each must be outside the segment
    timeout: float = 3.0        # seconds to wait for replies
    dry_run: bool = False       # build requests but do not send them

    def __post_init__(self) -> None:
        parse_ipv4(self.sender_ip, "Sender IP")
        if not 1 <= self.prefix_length <= 30:
            raise ValueError("Prefix length must be between 1 and 30.")
        segment = ipaddress.ip_network(f"{self.sender_ip}/{self.prefix_length}", strict=False)
        if not self.targets:
            raise ValueError("At least one target address is required.")
        if len(self.targets) > MAX_TARGETS:
            raise ValueError(f"At most {MAX_TARGETS} targets per run.")
        for target in self.targets:
            address = ipaddress.ip_address(parse_ipv4(target, "Target"))
            if address in segment:
                raise ValueError(f"Target {target} is inside {segment}; only addresses outside it are probed.")
        if not 0 < self.timeout <= MAX_TIMEOUT:
            raise ValueError(f"Timeout must be between 0 and {MAX_TIMEOUT:g} seconds.")

    @property
    def segment(self) -> str:
        return str(ipaddress.ip_network(f"{self.sender_ip}/{self.prefix_length}", strict=False))


@dataclass
class ProxyArpProbeStats:
    segment: str = ""
    answers: dict[str, str] = field(default_factory=dict)   # target IP -> MAC that answered
    status: str = ""


def probe_requests(sender_mac: str, sender_ip: str, targets: tuple[str, ...]) -> list[Packet]:
    """One broadcast ARP request per target, from the attacker's address."""
    source = normalize_unicast_mac(sender_mac)
    return [
        Ether(src=source, dst=BROADCAST_MAC) / ARP(
            op=ARP_REQUEST,
            hwsrc=source,
            psrc=sender_ip,
            hwdst=ZERO_MAC,
            pdst=target,
        )
        for target in targets
    ]


def collect_answers(answered: Any) -> dict[str, str]:
    """Map each target that answered to the MAC address that replied for it."""
    answers: dict[str, str] = {}
    for _sent, received in answered:
        if received is None or not received.haslayer(ARP):
            continue
        arp = received[ARP]
        if arp.op == 2:  # is-at
            answers[arp.psrc] = arp.hwsrc.lower()
    return answers


def run_proxy_arp_probe(
    config: ProxyArpProbeConfig,
    stop_event: threading.Event,
    on_progress: Callable[[ProxyArpProbeStats], None],
    own_mac: str | None = None,
    send_receive: Callable[..., Any] | None = None,
) -> ProxyArpProbeStats:
    """Ask for each target once and record which ones a router answers for."""
    send_receive = send_receive or srp

    if config.dry_run:
        stats = ProxyArpProbeStats(
            segment=config.segment,
            status=(
                f"Dry run: would ask for {len(config.targets)} address(es) outside {config.segment}, "
                f"from {config.sender_ip} on this port. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    if stop_event.is_set():
        return ProxyArpProbeStats(segment=config.segment, status="Stopped before probing.")

    sender_mac = own_mac or read_interface_mac(config.iface)
    requests = probe_requests(sender_mac, config.sender_ip, config.targets)
    answered, _unanswered = send_receive(
        requests, iface=config.iface, timeout=config.timeout, verbose=False,
    )
    answers = collect_answers(answered)
    stats = ProxyArpProbeStats(segment=config.segment, answers=answers)
    if answers:
        listed = ", ".join(f"{ip} via {mac}" for ip, mac in sorted(answers.items()))
        stats.status = (
            f"Answered for {len(answers)} of {len(config.targets)} address(es) outside {config.segment}: {listed}."
        )
    else:
        stats.status = (
            f"No answers for the {len(config.targets)} address(es) outside {config.segment}. "
            f"Proxy ARP is not answering for them from this port."
        )
    on_progress(replace(stats, answers=dict(answers)))
    return stats
