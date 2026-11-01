import threading

import pytest
from scapy.all import Ether

from macabre.attacks import switch_spoofing as dtp
from macabre.attacks.switch_spoofing import SwitchSpoofingConfig

ATTACKER = "02:00:00:00:00:30"
LINK_OUTPUT = (
    "2: eth9: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP "
    f"link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"
)


def fake_run(argv):
    return LINK_OUTPUT if argv[:4] == ["ip", "-o", "link", "show"] else ""


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_frame_goes_to_the_dtp_multicast_address_from_the_attacker_mac():
    frame = dtp.build_dtp_frame(ATTACKER)
    assert frame[Ether].dst == "01:00:0c:cc:cc:cc"
    assert frame[Ether].src == ATTACKER


def test_payload_has_llc_snap_header_for_dtp():
    payload = bytes(dtp.build_dtp_frame(ATTACKER).load)
    assert payload[:8] == bytes.fromhex("aaaa03" "00000c" "2004")
    assert payload[8] == 0x01  # DTP version


def test_payload_carries_the_trunk_status_encapsulation_and_neighbor_tlvs():
    payload = dtp.dtp_payload(ATTACKER, "lab")
    body = payload[len(dtp.SNAP_HEADER) + 1:]
    tlvs = []
    while body:
        tlv_type = int.from_bytes(body[0:2], "big")
        length = int.from_bytes(body[2:4], "big")
        tlvs.append((tlv_type, body[4:length]))
        body = body[length:]
    values = dict(tlvs)
    assert values[dtp.TLV_DOMAIN] == b"lab"
    assert values[dtp.TLV_STATUS] == bytes([dtp.STATUS_TRUNK_DESIRABLE])
    assert values[dtp.TLV_TYPE] == bytes([dtp.TYPE_DOT1Q])
    assert values[dtp.TLV_NEIGHBOR] == bytes.fromhex("020000000030")


def test_length_field_is_the_802_3_payload_length():
    frame = dtp.build_dtp_frame(ATTACKER)
    assert frame[Ether].type == len(dtp.dtp_payload(ATTACKER))


def test_run_sends_the_requested_number_of_frames():
    sent = []
    config = SwitchSpoofingConfig(iface="eth9", count=3, interval=0)
    stats = dtp.run_switch_spoofing(config, threading.Event(), lambda _s: None,
                                    run=fake_run, send=capture(sent))
    assert stats.frames == 3 and len(sent) == 3
    assert all(iface == "eth9" for iface, _ in sent)


def test_dry_run_sends_nothing_and_reads_nothing():
    calls = []
    sent = []
    config = SwitchSpoofingConfig(iface="eth9", count=3, dry_run=True)
    stats = dtp.run_switch_spoofing(config, threading.Event(), lambda _s: None,
                                    run=lambda argv: calls.append(argv) or "", send=capture(sent))
    assert calls == [] and sent == []
    assert stats.status.startswith("Dry run")


def test_domain_longer_than_32_bytes_is_rejected():
    with pytest.raises(ValueError, match="at most 32 bytes"):
        SwitchSpoofingConfig(iface="eth9", domain="x" * 33)


def test_stop_event_interrupts_continuous_run():
    stop = threading.Event()
    sent = []

    def on_progress(stats):
        if stats.frames == 2:
            stop.set()

    config = SwitchSpoofingConfig(iface="eth9", count=0, interval=0)
    stats = dtp.run_switch_spoofing(config, stop, on_progress, run=fake_run, send=capture(sent))
    assert stats.frames == 2
