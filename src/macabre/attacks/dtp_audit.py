"""DTP negotiation audit: find out which ports negotiate a trunk, from the access side.

Dynamic Trunking Protocol (DTP) lets Cisco ports agree whether they become trunks. A port
in a dynamic mode answers a DTP negotiation from a neighbor, and a trunk carries the tagged
traffic of every allowed VLAN. This audit does not change any port. It does two things:

  1. Passive: it listens for the DTP frames the switch port sends, and decodes the trunk
     status, the encapsulation type and the domain each one advertises.
  2. Active (optional): it sends one DTP negotiation frame and checks whether the port
     answers with a trunk status. An answer means the port negotiates a trunk with a
     neighbor that asks for one.

The field values are read as described in the public DTP description used by
switch_spoofing: status 0x03 is a trunk, 0x04 is access. The mapping has not been checked
against a real switch, so confirm a port's mode on that switch before relying on a verdict.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

from scapy.all import AsyncSniffer, Dot3, Ether, sendp
from scapy.packet import Packet

from macabre.attacks.common import Runner, read_interface_mac, run_command
from macabre.attacks.switch_spoofing import (
    DTP_MAC,
    SNAP_HEADER,
    TLV_DOMAIN,
    TLV_NEIGHBOR,
    TLV_STATUS,
    TLV_TYPE,
    build_dtp_frame,
)

STATUS_TRUNK = 0x03             # trunk on or desirable (public DTP description)
STATUS_ACCESS = 0x04            # access (public DTP description)
TYPE_DOT1Q = 0xA5


@dataclass(frozen=True)
class DtpAuditConfig:
    iface: str                  # attacker interface, on the access port under audit
    probe: bool = True          # send one negotiation frame and watch for a trunk answer
    dry_run: bool = False       # describe only; send nothing


@dataclass
class DtpNeighbor:
    mac: str
    status: int
    encapsulation: int
    domain: str

    @property
    def trunk(self) -> bool:
        return self.status == STATUS_TRUNK


@dataclass
class DtpAuditStats:
    sender_mac: str = ""
    frames_seen: int = 0
    neighbors: dict[str, DtpNeighbor] = field(default_factory=dict)
    probe_sent: bool = False
    trunk_answer: bool = False
    status: str = ""


def parse_dtp(payload: bytes) -> dict[int, bytes] | None:
    """TLVs of a DTP frame's payload, or None if the payload is not DTP."""
    if not payload.startswith(SNAP_HEADER) or len(payload) < len(SNAP_HEADER) + 1:
        return None
    body = payload[len(SNAP_HEADER) + 1:]
    fields: dict[int, bytes] = {}
    pos = 0
    while pos + 4 <= len(body):
        kind = int.from_bytes(body[pos:pos + 2], "big")
        length = int.from_bytes(body[pos + 2:pos + 4], "big")
        if length < 4 or pos + length > len(body):
            return None
        fields[kind] = body[pos + 4:pos + length]
        pos += length
    return fields


def frame_layer(packet: Packet) -> Packet | None:
    """The 802.3 or Ethernet layer of a frame, however scapy dissected it."""
    if packet.haslayer(Dot3):
        return packet[Dot3]
    if packet.haslayer(Ether):
        return packet[Ether]
    return None


def decode(packet: Packet) -> DtpNeighbor | None:
    """A DtpNeighbor for a DTP frame, or None for any other frame.

    A sniffed 802.3 frame is dissected as Dot3 and LLC, SNAP and Raw layers, so the SNAP
    header is not in Raw. The whole payload after the frame header is read back as bytes.
    """
    frame = frame_layer(packet)
    if frame is None:
        return None
    fields = parse_dtp(bytes(frame.payload))
    if fields is None or TLV_STATUS not in fields or TLV_TYPE not in fields:
        return None
    sender = frame.src
    if TLV_NEIGHBOR in fields and len(fields[TLV_NEIGHBOR]) == 6:
        sender = fields[TLV_NEIGHBOR].hex(":")
    return DtpNeighbor(
        mac=sender,
        status=fields[TLV_STATUS][0],
        encapsulation=fields[TLV_TYPE][0],
        domain=fields.get(TLV_DOMAIN, b"").decode("ascii", errors="replace"),
    )


def run_dtp_audit(
    config: DtpAuditConfig,
    stop_event: threading.Event,
    on_progress: Callable[[DtpAuditStats], None],
    run: Runner | None = None,
    send: Callable[..., Any] | None = None,
    sniffer_factory: Callable[..., Any] = AsyncSniffer,
) -> DtpAuditStats:
    """Listen for DTP frames on the port until `stop_event`, optionally probing it once."""
    run = run or run_command
    send = send or sendp

    if config.dry_run:
        stats = DtpAuditStats(
            status=(
                f"Dry run: would listen for DTP frames on {config.iface}"
                f"{' and send one negotiation frame' if config.probe else ''}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    sender_mac = read_interface_mac(config.iface, run)
    stats = DtpAuditStats(sender_mac=sender_mac)
    lock = threading.Lock()

    def on_packet(packet: Packet) -> None:
        neighbor = decode(packet)
        if neighbor is None or neighbor.mac == sender_mac:
            return
        with lock:
            stats.frames_seen += 1
            stats.neighbors[neighbor.mac] = neighbor
            if neighbor.trunk:
                stats.trunk_answer = True
            snapshot = replace(stats, neighbors=dict(stats.neighbors))
        on_progress(snapshot)

    sniffer = sniffer_factory(iface=config.iface, store=False, prn=on_packet)
    sniffer.start()
    try:
        if config.probe:
            send(build_dtp_frame(sender_mac), iface=config.iface, verbose=False)
            with lock:
                stats.probe_sent = True
        stop_event.wait()
    finally:
        sniffer.stop()

    with lock:
        if stats.trunk_answer:
            verdict = "The port advertises a trunk and answers the negotiation: it negotiates trunks."
        elif stats.neighbors:
            verdict = "The port advertises access only: it does not negotiate a trunk here."
        else:
            verdict = "No DTP frames were heard, so the port's mode is unknown."
        stats.status = verdict
    return stats
