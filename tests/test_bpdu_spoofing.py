import struct
import threading

import pytest
from scapy.all import Ether

from macabre.attacks import bpdu_spoofing as stp
from macabre.attacks.bpdu_spoofing import BpduSpoofingConfig

ATTACKER = "02:00:00:00:00:30"
LINK_OUTPUT = (
    "2: eth9: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP "
    f"link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"
)


def fake_run(argv):
    return LINK_OUTPUT if argv[:4] == ["ip", "-o", "link", "show"] else ""


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def body_of(frame):
    """Bytes after the 3-byte LLC header of a BPDU frame."""
    return bytes(frame.load)[3:]


def test_frame_goes_to_the_stp_group_address_from_the_sender():
    frame = stp.build_bpdu_frame(ATTACKER)
    assert frame[Ether].dst == "01:80:c2:00:00:00"
    assert frame[Ether].src == ATTACKER


def test_payload_starts_with_llc_and_is_a_35_byte_configuration_bpdu():
    frame = stp.build_bpdu_frame(ATTACKER)
    payload = bytes(frame.load)
    assert payload[:3] == bytes.fromhex("424203")
    assert len(body_of(frame)) == 35


def test_length_field_is_the_802_3_payload_length():
    frame = stp.build_bpdu_frame(ATTACKER)
    assert frame[Ether].type == len(bytes(frame.load)) == 38


def test_protocol_version_and_type_are_configuration_bpdu():
    body = body_of(stp.build_bpdu_frame(ATTACKER))
    protocol_id, version, bpdu_type, flags = struct.unpack("!HBBB", body[:5])
    assert (protocol_id, version, bpdu_type, flags) == (0, 0, 0, 0)


def test_root_defaults_to_the_sender_and_advertises_priority_zero():
    body = body_of(stp.build_bpdu_frame(ATTACKER))
    root_priority = struct.unpack("!H", body[5:7])[0]
    root_mac = body[7:13].hex(":")
    assert root_priority == 0
    assert root_mac == ATTACKER


def test_explicit_root_mac_and_priority_are_encoded():
    body = body_of(stp.build_bpdu_frame(
        ATTACKER, root_priority=8192, root_mac="02:aa:bb:cc:dd:ee", root_path_cost=19,
    ))
    assert struct.unpack("!H", body[5:7])[0] == 8192
    assert body[7:13].hex(":") == "02:aa:bb:cc:dd:ee"
    assert struct.unpack("!I", body[13:17])[0] == 19


def test_bridge_id_and_port_id_are_encoded():
    body = body_of(stp.build_bpdu_frame(ATTACKER, bridge_priority=4096, port_id=0x8005))
    assert struct.unpack("!H", body[17:19])[0] == 4096
    assert body[19:25].hex(":") == ATTACKER
    assert struct.unpack("!H", body[25:27])[0] == 0x8005


def test_timers_are_in_units_of_one_256th_second():
    body = body_of(stp.build_bpdu_frame(ATTACKER))
    message_age, max_age, hello, forward_delay = struct.unpack("!HHHH", body[27:35])
    assert message_age == 0
    assert max_age == 20 * 256
    assert hello == 2 * 256
    assert forward_delay == 15 * 256


@pytest.mark.parametrize("value", [1, 4095, 61441, 65536, -4096])
def test_priority_must_be_a_multiple_of_4096_in_range(value):
    with pytest.raises(ValueError, match="multiple of 4096"):
        BpduSpoofingConfig(iface="eth9", root_priority=value)


def test_priority_ceiling_is_accepted():
    assert BpduSpoofingConfig(iface="eth9", root_priority=61440).root_priority == 61440


def test_invalid_root_mac_is_rejected():
    with pytest.raises(ValueError):
        BpduSpoofingConfig(iface="eth9", root_mac="01:00:0c:cc:cc:cc")


def test_port_id_and_path_cost_must_fit_their_fields():
    with pytest.raises(ValueError, match="Port ID"):
        BpduSpoofingConfig(iface="eth9", port_id=0x10000)
    with pytest.raises(ValueError, match="path cost"):
        BpduSpoofingConfig(iface="eth9", root_path_cost=2**32)


def test_run_sends_the_requested_number_of_frames_on_the_interface():
    sent = []
    config = BpduSpoofingConfig(iface="eth9", count=3, interval=0)
    stats = stp.run_bpdu_spoofing(config, threading.Event(), lambda _s: None,
                                  run=fake_run, send=capture(sent))
    assert stats.frames == 3 and len(sent) == 3
    assert all(iface == "eth9" for iface, _ in sent)
    assert stats.root_id == f"0000.{ATTACKER}"


def test_run_uses_the_explicit_root_mac_in_the_root_id():
    sent = []
    config = BpduSpoofingConfig(iface="eth9", count=1, interval=0, root_mac="02:aa:bb:cc:dd:ee")
    stats = stp.run_bpdu_spoofing(config, threading.Event(), lambda _s: None,
                                  run=fake_run, send=capture(sent))
    assert stats.root_id == "0000.02:aa:bb:cc:dd:ee"


def test_dry_run_sends_nothing_and_reads_nothing():
    calls = []
    sent = []
    config = BpduSpoofingConfig(iface="eth9", count=3, dry_run=True)
    stats = stp.run_bpdu_spoofing(config, threading.Event(), lambda _s: None,
                                  run=lambda argv: calls.append(argv) or "", send=capture(sent))
    assert calls == [] and sent == []
    assert stats.status.startswith("Dry run")


def test_topology_change_flag_is_set_only_when_requested():
    plain = bytes(stp.build_bpdu_frame(ATTACKER).load)[3:]
    flagged = bytes(stp.build_bpdu_frame(ATTACKER, flags=stp.TC_FLAG).load)[3:]
    # Body layout: protocol ID (2), version (1), type (1), flags (1), ...
    assert plain[4] == 0
    assert flagged[4] == 0x01
    assert plain[:4] == flagged[:4] and plain[5:] == flagged[5:]
