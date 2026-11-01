import threading

import pytest
from scapy.all import ARP, Dot1Q, Ether

from macabre.attacks import double_tagging as dt
from macabre.attacks.double_tagging import DoubleTaggingConfig

ATTACKER = "02:00:00:00:00:30"
LINK_OUTPUT = (
    "2: eth9: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP "
    f"link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"
)


def fake_run(argv):
    return LINK_OUTPUT if argv[:4] == ["ip", "-o", "link", "show"] else ""


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_frame_has_outer_native_tag_and_inner_target_tag():
    frame = dt.build_double_tagged_frame(ATTACKER, 10, 20, "192.0.2.1")
    assert frame[Dot1Q].vlan == 10
    assert frame[Dot1Q].payload[Dot1Q].vlan == 20


def test_tags_are_in_the_wire_order_outer_then_inner():
    raw = bytes(dt.build_double_tagged_frame(ATTACKER, 10, 20, "192.0.2.1"))
    assert raw[12:14] == b"\x81\x00"          # outer TPID
    assert int.from_bytes(raw[14:16], "big") & 0x0FFF == 10
    assert raw[16:18] == b"\x81\x00"          # inner TPID
    assert int.from_bytes(raw[18:20], "big") & 0x0FFF == 20


def test_inner_payload_is_an_arp_probe():
    frame = dt.build_double_tagged_frame(ATTACKER, 10, 20, "192.0.2.1")
    arp = frame[Dot1Q].payload[Dot1Q].payload
    assert isinstance(arp, ARP)
    assert arp.psrc == "0.0.0.0" and arp.pdst == "192.0.2.1"
    assert frame[Ether].src == ATTACKER


def test_run_sends_the_requested_number_of_frames():
    sent = []
    config = DoubleTaggingConfig(iface="eth9", native_vlan=10, target_vlan=20, count=4, interval=0)
    stats = dt.run_double_tagging(config, threading.Event(), lambda _s: None,
                                  run=fake_run, send=capture(sent))
    assert stats.frames == 4 and len(sent) == 4


def test_dry_run_sends_and_reads_nothing():
    calls, sent = [], []
    config = DoubleTaggingConfig(iface="eth9", native_vlan=10, target_vlan=20, count=3, dry_run=True)
    stats = dt.run_double_tagging(config, threading.Event(), lambda _s: None,
                                  run=lambda argv: calls.append(argv) or "", send=capture(sent))
    assert calls == [] and sent == []
    assert "10 then 20" in stats.status


@pytest.mark.parametrize("native, target, message", [
    (0, 20, "native VLAN must be between"),
    (10, 4095, "target VLAN must be between"),
    (10, 10, "must be different"),
])
def test_invalid_vlans_are_rejected(native, target, message):
    with pytest.raises(ValueError, match=message):
        DoubleTaggingConfig(iface="eth9", native_vlan=native, target_vlan=target)


def test_stop_event_interrupts_continuous_run():
    stop = threading.Event()

    def on_progress(stats):
        if stats.frames == 2:
            stop.set()

    config = DoubleTaggingConfig(iface="eth9", native_vlan=10, target_vlan=20, count=0, interval=0)
    stats = dt.run_double_tagging(config, stop, on_progress, run=fake_run, send=capture([]))
    assert stats.frames == 2
