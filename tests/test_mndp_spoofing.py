import struct
import threading

import pytest
from scapy.all import IP, UDP, Ether

from macabre.attacks import mndp_spoofing as mndp
from macabre.attacks.mndp_spoofing import MndpSpoofingConfig

ATTACKER = "02:00:00:00:00:30"
LINK_OUTPUT = (
    "2: eth9: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP "
    f"link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"
)


def fake_run(argv):
    return LINK_OUTPUT if argv[:4] == ["ip", "-o", "link", "show"] else ""


def test_frame_is_a_broadcast_to_udp_5678_from_the_sender():
    frame = mndp.build_mndp_frame(ATTACKER, MndpSpoofingConfig(iface="eth9"))
    assert frame[Ether].dst == "ff:ff:ff:ff:ff:ff"
    assert frame[IP].dst == "255.255.255.255"
    assert (frame[UDP].sport, frame[UDP].dport) == (5678, 5678)


def test_header_is_little_endian_sequence_then_zeros():
    payload = mndp.mndp_payload(ATTACKER, "R", "7", "p", "b", "s", "ether1", sequence=258)
    assert struct.unpack("<HH", payload[:4]) == (258, 0)


def test_round_trip_through_the_parser_keeps_every_field():
    payload = mndp.mndp_payload(ATTACKER, "MACabre-RTR", "7.16", "MikroTik", "RB750Gr3", "MACABR",
                                "ether1", uptime=90, address="10.0.0.9")
    fields = mndp.parse_mndp(payload)
    assert fields[mndp.TLV_MAC] == bytes.fromhex("020000000030")
    assert fields[mndp.TLV_IDENTITY] == b"MACabre-RTR"
    assert fields[mndp.TLV_VERSION] == b"7.16"
    assert fields[mndp.TLV_PLATFORM] == b"MikroTik"
    assert fields[mndp.TLV_BOARD] == b"RB750Gr3"
    assert struct.unpack("<I", fields[mndp.TLV_UPTIME])[0] == 90
    assert fields[mndp.TLV_INTERFACE_NAME] == b"ether1"
    assert fields[mndp.TLV_IPV4] == bytes([10, 0, 0, 9])


def test_address_tlv_is_optional():
    assert mndp.TLV_IPV4 not in mndp.parse_mndp(mndp.mndp_payload(ATTACKER, "R", "7", "p", "b", "s", "e"))


def test_parser_rejects_truncated_payloads():
    payload = mndp.mndp_payload(ATTACKER, "R", "7", "p", "b", "s", "e")
    with pytest.raises(ValueError):
        mndp.parse_mndp(payload[:-1])
    with pytest.raises(ValueError):
        mndp.parse_mndp(b"\x00\x00")


@pytest.mark.parametrize("kwargs", [
    {"identity": ""},
    {"identity": "x" * 256},
    {"address": "nope"},
    {"mac": "01:00:0c:cc:cc:cc"},
    {"uptime": -1},
    {"count": -1},
    {"interval": -1.0},
])
def test_invalid_settings_are_rejected(kwargs):
    with pytest.raises(ValueError):
        MndpSpoofingConfig(iface="eth9", **kwargs)


def test_run_sends_the_requested_number_of_announcements():
    sent = []
    stats = mndp.run_mndp_spoofing(MndpSpoofingConfig(iface="eth9", count=3, interval=0),
                                   threading.Event(), lambda _s: None, run=fake_run,
                                   send=lambda frame, iface, verbose: sent.append((iface, frame)))
    assert stats.frames == 3 and len(sent) == 3
    assert stats.sender_mac == ATTACKER


def test_dry_run_sends_nothing_and_reads_nothing():
    calls, sent = [], []
    stats = mndp.run_mndp_spoofing(MndpSpoofingConfig(iface="eth9", dry_run=True), threading.Event(),
                                   lambda _s: None, run=lambda argv: calls.append(argv) or "",
                                   send=lambda *a, **k: sent.append(a))
    assert calls == [] and sent == []
    assert stats.status.startswith("Dry run")
