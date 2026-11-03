"""Static MAC impersonation: send frames that carry a statically registered MAC address.

An administrator can bind a MAC address to a port with a static entry. The switch then
keeps that binding and does not relearn it from traffic. This module sends frames whose
source is the registered address from a port that is not the registered one, which is
how a device on another port presents itself as the registered host.

Each frame is a broadcast with an experimental EtherType, so no host parses it as IP or
ARP. Whether the switch keeps the binding and still forwards the frames is the observable
result, and the lab measures it. Whether the switch logs the conflict is not measured.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, Raw, sendp

from macabre.attacks.common import BROADCAST_MAC, normalize_unicast_mac

MAX_RATE = 100.0           # frames per second; higher rates are refused
BATCH_SECONDS = 0.1        # frames are sent in batches this long
EXPERIMENTAL_ETHERTYPE = 0x88B5   # IEEE 802 local experimental EtherType
PAYLOAD = b"MACabre static MAC impersonation probe"


@dataclass(frozen=True)
class StaticMacImpersonationConfig:
    iface: str                  # attacker interface, on a port other than the registered one
    source_mac: str             # the statically registered MAC address to present (required)
    rate: float = 10.0          # frames per second
    count: int = 0              # frames to send in total; 0 = run until stopped
    dry_run: bool = False       # build frames but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        if not 0 < self.rate <= MAX_RATE:
            raise ValueError(f"Rate must be between 0 and {MAX_RATE:g} frames per second.")
        if self.count < 0:
            raise ValueError("Count cannot be negative.")


@dataclass
class StaticMacImpersonationStats:
    source_mac: str = ""
    frames: int = 0
    status: str = ""


def impersonation_frames(source_mac: str, how_many: int) -> list:
    """Broadcast frames whose source is the registered MAC address."""
    source = normalize_unicast_mac(source_mac)
    return [
        Ether(src=source, dst=BROADCAST_MAC, type=EXPERIMENTAL_ETHERTYPE) / Raw(PAYLOAD)
        for _ in range(how_many)
    ]


def run_static_mac_impersonation(
    config: StaticMacImpersonationConfig,
    stop_event: threading.Event,
    on_progress: Callable[[StaticMacImpersonationStats], None],
    send: Callable[..., Any] | None = None,
) -> StaticMacImpersonationStats:
    """Send frames that carry the registered MAC at `rate` per second until `count` or `stop_event`."""
    send = send or sendp
    source = normalize_unicast_mac(config.source_mac)

    if config.dry_run:
        stats = StaticMacImpersonationStats(
            source_mac=source,
            status=(
                f"Dry run: would send about {config.rate:g} frames per second with source {source} "
                f"from this port. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    per_batch = max(1, round(config.rate * BATCH_SECONDS))
    stats = StaticMacImpersonationStats(source_mac=source)
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        batch = per_batch
        if config.count:
            batch = min(batch, config.count - stats.frames)
        send(impersonation_frames(source, batch), iface=config.iface, verbose=False)
        stats.frames += batch
        on_progress(replace(stats))
        stop_event.wait(BATCH_SECONDS)
    return stats
