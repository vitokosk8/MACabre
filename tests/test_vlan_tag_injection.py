import threading

import pytest
from scapy.all import ARP, Dot1Q, Ether

from macabre.attacks import vlan_tag_injection as inj
from macabre.attacks.vlan_tag_injection import VlanTagInjectionConfig

ATTACKER = "02:00:00:00:00:30"
LINK_OUTPUT = (
    "2: eth9: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP "
    f"link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"
)


def fake_run(argv):
    return LINK_OUTPUT if argv[:4] == ["ip", "-o", "link", "show"] else ""


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_tag_fields_are_set_as_chosen():
    frame = inj.build_injected_frame(ATTACKER, 20, 5, 1, "192.0.2.1")
    assert frame[Dot1Q].vlan == 20
    assert frame[Dot1Q].prio == 5
    assert frame[Dot1Q].dei == 1


def test_tag_control_information_is_on_the_wire_in_the_right_bits():
    raw = bytes(inj.build_injected_frame(ATTACKER, 20, 5, 1, "192.0.2.1"))
    assert raw[12:14] == b"\x81\x00"
    tci = int.from_bytes(raw[14:16], "big")
    assert tci & 0x0FFF == 20
    assert (tci >> 12) & 0x1 == 1
    assert (tci >> 13) & 0x7 == 5


def test_probe_is_an_arp_request_from_the_zero_address():
    frame = inj.build_injected_frame(ATTACKER, 20, 0, 0, "192.0.2.1")
    assert isinstance(frame[Dot1Q].payload, ARP)
    assert frame[Dot1Q].payload.psrc == "0.0.0.0"
    assert frame[Ether].src == ATTACKER


def test_run_sends_the_requested_number_of_frames():
    sent = []
    config = VlanTagInjectionConfig(iface="eth9", vlan=20, count=3, interval=0)
    stats = inj.run_vlan_tag_injection(config, threading.Event(), lambda _s: None,
                                       run=fake_run, send=capture(sent))
    assert stats.frames == 3 and len(sent) == 3


def test_dry_run_sends_and_reads_nothing():
    calls, sent = [], []
    config = VlanTagInjectionConfig(iface="eth9", vlan=20, count=3, dry_run=True)
    stats = inj.run_vlan_tag_injection(config, threading.Event(), lambda _s: None,
                                       run=lambda argv: calls.append(argv) or "", send=capture(sent))
    assert calls == [] and sent == []
    assert "VLAN 20" in stats.status


@pytest.mark.parametrize("kwargs, message", [
    ({"vlan": 0}, "between 1 and 4094"),
    ({"vlan": 20, "pcp": 8}, "between 0 and 7"),
    ({"vlan": 20, "dei": 2}, "must be 0 or 1"),
    ({"vlan": 20, "probe_ip": "192.0.2.999"}, "Invalid probe IP"),
])
def test_invalid_fields_are_rejected(kwargs, message):
    with pytest.raises(ValueError, match=message):
        VlanTagInjectionConfig(iface="eth9", **kwargs)


def test_stop_event_interrupts_continuous_run():
    stop = threading.Event()

    def on_progress(stats):
        if stats.frames == 2:
            stop.set()

    config = VlanTagInjectionConfig(iface="eth9", vlan=20, count=0, interval=0)
    stats = inj.run_vlan_tag_injection(config, stop, on_progress, run=fake_run, send=capture([]))
    assert stats.frames == 2
