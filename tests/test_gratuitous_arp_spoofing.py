import threading

import pytest
from scapy.all import ARP, Ether

from macabre.attacks import gratuitous_arp_spoofing as garp
from macabre.attacks.gratuitous_arp_spoofing import GratuitousArpConfig

ATTACKER = "02:00:00:00:00:30"
GATEWAY_IP = "10.95.0.1"
LINK_OUTPUT = f"2: eth9: <UP> mtu 1500 link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"


def fake_run(argv):
    return LINK_OUTPUT


def test_announcement_has_sender_and_target_ip_equal_to_spoofed_ip():
    frame = garp.build_gratuitous_arp(ATTACKER, GATEWAY_IP)
    assert frame[ARP].op == 1
    assert frame[ARP].psrc == GATEWAY_IP
    assert frame[ARP].pdst == GATEWAY_IP
    assert frame[ARP].hwsrc == ATTACKER
    assert frame[ARP].hwdst == "00:00:00:00:00:00"


def test_announcement_goes_to_broadcast():
    frame = garp.build_gratuitous_arp(ATTACKER, GATEWAY_IP)
    assert frame[Ether].dst == "ff:ff:ff:ff:ff:ff"
    assert frame[Ether].src == ATTACKER


def test_run_sends_count_announcements_on_the_interface():
    sent = []
    config = GratuitousArpConfig(iface="eth9", spoofed_ip=GATEWAY_IP, count=3, interval=0.0)
    stats = garp.run_gratuitous_arp(
        config, threading.Event(), lambda _s: None, run=fake_run,
        send=lambda frame, iface, verbose: sent.append((iface, frame)),
    )
    assert stats.frames == 3
    assert stats.sender_mac == ATTACKER
    assert {iface for iface, _ in sent} == {"eth9"}


def test_dry_run_sends_nothing():
    sent = []
    config = GratuitousArpConfig(iface="eth9", spoofed_ip=GATEWAY_IP, count=2, interval=0.0, dry_run=True)
    stats = garp.run_gratuitous_arp(config, threading.Event(), lambda _s: None, run=fake_run,
                                    send=lambda *a, **k: sent.append(a))
    assert stats.frames == 2
    assert sent == []


@pytest.mark.parametrize("value, message", [("", "required"), ("10.95.0.999", "Invalid spoofed IP")])
def test_invalid_ip_is_rejected(value, message):
    with pytest.raises(ValueError, match=message):
        GratuitousArpConfig(iface="eth9", spoofed_ip=value)


def test_stop_event_interrupts_continuous_run():
    stop = threading.Event()

    def on_progress(stats):
        if stats.frames == 2:
            stop.set()

    config = GratuitousArpConfig(iface="eth9", spoofed_ip=GATEWAY_IP, count=0, interval=0.0, dry_run=True)
    stats = garp.run_gratuitous_arp(config, stop, on_progress, run=fake_run)
    assert stats.frames == 2
