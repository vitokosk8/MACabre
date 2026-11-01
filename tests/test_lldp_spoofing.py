import struct
import threading

import pytest
from scapy.all import Ether

from macabre.attacks import lldp_spoofing as lldp
from macabre.attacks.lldp_spoofing import LldpSpoofingConfig

ATTACKER = "02:00:00:00:00:30"
LINK_OUTPUT = (
    "2: eth9: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP "
    f"link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"
)


def fake_run(argv):
    return LINK_OUTPUT if argv[:4] == ["ip", "-o", "link", "show"] else ""


def tlvs_of(payload: bytes):
    out, pos = [], 0
    while pos < len(payload):
        (header,) = struct.unpack("!H", payload[pos:pos + 2])
        kind, length = header >> 9, header & 0x1FF
        out.append((kind, payload[pos + 2:pos + 2 + length]))
        pos += 2 + length
        if kind == lldp.TLV_END:
            break
    return out


def test_frame_goes_to_nearest_bridge_with_lldp_ethertype():
    frame = lldp.build_frame(ATTACKER, LldpSpoofingConfig(iface="eth9"))
    assert frame[Ether].dst == "01:80:c2:00:00:0e"
    assert frame[Ether].type == 0x88CC
    assert frame[Ether].src == ATTACKER


def test_mandatory_tlvs_come_first_and_the_message_ends_with_end():
    tlvs = tlvs_of(bytes(lldp.build_frame(ATTACKER, LldpSpoofingConfig(iface="eth9")).load))
    assert [kind for kind, _ in tlvs][:3] == [lldp.TLV_CHASSIS_ID, lldp.TLV_PORT_ID, lldp.TLV_TTL]
    assert tlvs[-1] == (lldp.TLV_END, b"")


def test_chassis_id_defaults_to_the_sender_mac_and_can_be_forged():
    values = dict(tlvs_of(lldp.lldp_payload(ATTACKER, "SW", "Gi0/1")))
    assert values[lldp.TLV_CHASSIS_ID] == b"\x04" + bytes.fromhex("020000000030")
    forged = dict(tlvs_of(lldp.build_frame(ATTACKER, LldpSpoofingConfig(
        iface="eth9", chassis_mac="02:aa:bb:cc:dd:ee")).load))
    assert forged[lldp.TLV_CHASSIS_ID] == b"\x04" + bytes.fromhex("02aabbccddee")


def test_system_name_port_and_ttl_are_encoded():
    values = dict(tlvs_of(lldp.lldp_payload(ATTACKER, "MACabre-SW", "Gi0/1", ttl=180)))
    assert values[lldp.TLV_SYSTEM_NAME] == b"MACabre-SW"
    assert values[lldp.TLV_PORT_ID] == b"\x05Gi0/1"
    assert struct.unpack("!H", values[lldp.TLV_TTL])[0] == 180


def test_capabilities_are_bridge_and_router_by_default():
    values = dict(tlvs_of(lldp.lldp_payload(ATTACKER, "SW", "Gi0/1")))
    system, enabled = struct.unpack("!HH", values[lldp.TLV_CAPABILITIES])
    assert system == enabled == 0x14


def test_management_address_tlv_is_optional_and_encodes_ipv4():
    assert lldp.TLV_MANAGEMENT_ADDRESS not in dict(tlvs_of(lldp.lldp_payload(ATTACKER, "SW", "Gi0/1")))
    values = dict(tlvs_of(lldp.lldp_payload(ATTACKER, "SW", "Gi0/1", address="10.0.0.9")))
    assert values[lldp.TLV_MANAGEMENT_ADDRESS][:6] == bytes([5, 1, 10, 0, 0, 9])


@pytest.mark.parametrize("kwargs", [
    {"system_name": ""},
    {"port_id": "x" * 256},
    {"system_name": "café"},
    {"address": "nope"},
    {"ttl": 70000},
    {"capabilities": 0x10000},
    {"count": -1},
    {"interval": -1.0},
])
def test_invalid_settings_are_rejected(kwargs):
    with pytest.raises(ValueError):
        LldpSpoofingConfig(iface="eth9", **kwargs)


def test_run_sends_the_requested_number_of_advertisements():
    sent = []
    stats = lldp.run_lldp_spoofing(LldpSpoofingConfig(iface="eth9", count=3, interval=0),
                                   threading.Event(), lambda _s: None, run=fake_run,
                                   send=lambda frame, iface, verbose: sent.append((iface, frame)))
    assert stats.frames == 3 and len(sent) == 3
    assert stats.sender_mac == ATTACKER


def test_dry_run_sends_nothing_and_reads_nothing():
    calls, sent = [], []
    stats = lldp.run_lldp_spoofing(LldpSpoofingConfig(iface="eth9", dry_run=True), threading.Event(),
                                   lambda _s: None, run=lambda argv: calls.append(argv) or "",
                                   send=lambda *a, **k: sent.append(a))
    assert calls == [] and sent == []
    assert stats.status.startswith("Dry run")
