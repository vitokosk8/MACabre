import threading

import pytest
from scapy.all import ARP, Dot1Q, Ether

from macabre.attacks import native_vlan_abuse as nv
from macabre.attacks.native_vlan_abuse import NativeVlanConfig

ATTACKER = "02:00:00:00:00:30"
LINK_OUTPUT = (
    "2: eth9: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP "
    f"link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"
)


def fake_run(argv):
    return LINK_OUTPUT if argv[:4] == ["ip", "-o", "link", "show"] else ""


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_probes_are_untagged_arp_requests():
    frame = nv.build_untagged_probe(ATTACKER, "192.0.2.1")
    assert not frame.haslayer(Dot1Q)
    assert frame[Ether].src == ATTACKER and frame[Ether].dst == "ff:ff:ff:ff:ff:ff"
    assert frame[ARP].op == 1 and frame[ARP].psrc == "0.0.0.0"


def test_run_sends_the_requested_number_of_untagged_probes():
    sent = []
    config = NativeVlanConfig(iface="eth9", count=3, interval=0)
    stats = nv.run_native_vlan_abuse(config, threading.Event(), lambda _s: None,
                                     run=fake_run, send=capture(sent))
    assert stats.frames == 3 and len(sent) == 3
    assert all(not frame.haslayer(Dot1Q) for _, frame in sent)


def test_dry_run_sends_and_reads_nothing():
    calls, sent = [], []
    config = NativeVlanConfig(iface="eth9", count=3, dry_run=True)
    stats = nv.run_native_vlan_abuse(config, threading.Event(), lambda _s: None,
                                     run=lambda argv: calls.append(argv) or "", send=capture(sent))
    assert calls == [] and sent == []
    assert stats.status.startswith("Dry run")


def test_invalid_probe_ip_is_rejected():
    with pytest.raises(ValueError, match="Invalid probe IP"):
        NativeVlanConfig(iface="eth9", probe_ip="192.0.2.999")


def test_stop_event_interrupts_continuous_run():
    stop = threading.Event()

    def on_progress(stats):
        if stats.frames == 2:
            stop.set()

    config = NativeVlanConfig(iface="eth9", count=0, interval=0)
    stats = nv.run_native_vlan_abuse(config, stop, on_progress, run=fake_run, send=capture([]))
    assert stats.frames == 2
