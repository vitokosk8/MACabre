import threading

import pytest
from scapy.all import ARP, Dot1Q, Ether

from macabre.attacks import vlan_hopping as hop
from macabre.attacks.vlan_hopping import VlanHoppingConfig
from macabre.attacks.switch_spoofing import DTP_MAC

ATTACKER = "02:00:00:00:00:30"
LINK_OUTPUT = (
    "2: eth9: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP "
    f"link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"
)


def fake_run(argv):
    return LINK_OUTPUT if argv[:4] == ["ip", "-o", "link", "show"] else ""


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_probe_is_tagged_with_the_target_vlan():
    frame = hop.build_hopping_frame(ATTACKER, 20, "192.0.2.1")
    assert frame[Dot1Q].vlan == 20
    assert frame[Ether].src == ATTACKER
    assert frame[Ether].dst == "ff:ff:ff:ff:ff:ff"


def test_probe_is_an_arp_request_from_the_zero_address():
    frame = hop.build_hopping_frame(ATTACKER, 20, "192.0.2.1")
    assert frame[ARP].op == 1
    assert frame[ARP].psrc == "0.0.0.0"
    assert frame[ARP].pdst == "192.0.2.1"


def test_dtp_advertisement_is_sent_once_before_the_probes():
    sent = []
    config = VlanHoppingConfig(iface="eth9", target_vlan=20, count=3, interval=0)
    stats = hop.run_vlan_hopping(config, threading.Event(), lambda _s: None,
                                 run=fake_run, send=capture(sent))
    assert stats.dtp_sent == 1 and stats.frames == 3
    assert sent[0][1][Ether].dst == DTP_MAC
    assert all(frame[Dot1Q].vlan == 20 for _, frame in sent[1:])


def test_negotiation_can_be_skipped():
    sent = []
    config = VlanHoppingConfig(iface="eth9", target_vlan=20, negotiate=False, count=2, interval=0)
    stats = hop.run_vlan_hopping(config, threading.Event(), lambda _s: None,
                                 run=fake_run, send=capture(sent))
    assert stats.dtp_sent == 0 and len(sent) == 2
    assert all(frame.haslayer(Dot1Q) for _, frame in sent)


def test_dry_run_sends_and_reads_nothing():
    calls, sent = [], []
    config = VlanHoppingConfig(iface="eth9", target_vlan=20, count=3, dry_run=True)
    stats = hop.run_vlan_hopping(config, threading.Event(), lambda _s: None,
                                 run=lambda argv: calls.append(argv) or "", send=capture(sent))
    assert calls == [] and sent == []
    assert stats.status.startswith("Dry run")


@pytest.mark.parametrize("vlan", [0, 4095, -1])
def test_vlan_outside_the_range_is_rejected(vlan):
    with pytest.raises(ValueError, match="between 1 and 4094"):
        VlanHoppingConfig(iface="eth9", target_vlan=vlan)


def test_invalid_probe_ip_is_rejected():
    with pytest.raises(ValueError, match="Invalid probe IP"):
        VlanHoppingConfig(iface="eth9", target_vlan=20, probe_ip="192.0.2.999")


def test_stop_event_interrupts_continuous_run():
    stop = threading.Event()

    def on_progress(stats):
        if stats.frames == 2:
            stop.set()

    config = VlanHoppingConfig(iface="eth9", target_vlan=20, negotiate=False, count=0, interval=0)
    stats = hop.run_vlan_hopping(config, stop, on_progress, run=fake_run, send=capture([]))
    assert stats.frames == 2
