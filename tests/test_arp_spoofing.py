import threading

import pytest
from scapy.all import ARP, Ether

from macabre.attacks import arp_spoofing as arp
from macabre.attacks.arp_spoofing import ArpSpoofingConfig

ATTACKER = "02:00:00:00:00:30"
GATEWAY_IP = "10.95.0.1"
VICTIM_IP = "10.95.0.10"
VICTIM_MAC = "02:00:00:00:00:10"

LINK_OUTPUT = f"2: eth9: <UP> mtu 1500 link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"


def fake_run(argv):
    return LINK_OUTPUT


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_reply_binds_spoofed_ip_to_attacker_mac():
    sent = []
    config = ArpSpoofingConfig(iface="eth9", spoofed_ip=GATEWAY_IP, victim_ip=VICTIM_IP, count=2, interval=0.0)
    stats = arp.run_arp_spoofing(config, threading.Event(), lambda _s: None, run=fake_run, send=capture(sent))

    assert stats.frames == 2
    assert stats.sender_mac == ATTACKER
    iface, frame = sent[0]
    assert iface == "eth9"
    assert frame[ARP].op == 2
    assert frame[ARP].hwsrc == ATTACKER
    assert frame[ARP].psrc == GATEWAY_IP
    assert frame[ARP].pdst == VICTIM_IP


def test_without_victim_mac_the_reply_is_broadcast():
    frame = arp.build_arp_reply(ATTACKER, GATEWAY_IP, VICTIM_IP)
    assert frame[Ether].dst == "ff:ff:ff:ff:ff:ff"
    assert frame[ARP].hwdst == "00:00:00:00:00:00"


def test_with_victim_mac_the_reply_is_unicast_to_the_victim():
    frame = arp.build_arp_reply(ATTACKER, GATEWAY_IP, VICTIM_IP, VICTIM_MAC)
    assert frame[Ether].dst == VICTIM_MAC
    assert frame[ARP].hwdst == VICTIM_MAC


def test_victim_mac_is_normalized_to_lowercase():
    sent = []
    config = ArpSpoofingConfig(
        iface="eth9", spoofed_ip=GATEWAY_IP, victim_ip=VICTIM_IP, victim_mac="02:AA:BB:CC:DD:EE", count=1, interval=0.0
    )
    arp.run_arp_spoofing(config, threading.Event(), lambda _s: None, run=fake_run, send=capture(sent))
    assert sent[0][1][Ether].dst == "02:aa:bb:cc:dd:ee"


@pytest.mark.parametrize("kwargs, message", [
    ({"spoofed_ip": "", "victim_ip": VICTIM_IP}, "spoofed IP is required"),
    ({"spoofed_ip": GATEWAY_IP, "victim_ip": ""}, "victim IP is required"),
    ({"spoofed_ip": "10.95.0.300", "victim_ip": VICTIM_IP}, "Invalid spoofed IP"),
    ({"spoofed_ip": GATEWAY_IP, "victim_ip": "not-an-ip"}, "Invalid victim IP"),
    ({"spoofed_ip": GATEWAY_IP, "victim_ip": VICTIM_IP, "victim_mac": "nope"}, "Invalid MAC"),
    ({"spoofed_ip": GATEWAY_IP, "victim_ip": VICTIM_IP, "victim_mac": "01:00:5e:00:00:01"}, "unicast"),
])
def test_invalid_parameters_are_rejected(kwargs, message):
    with pytest.raises(ValueError, match=message):
        ArpSpoofingConfig(iface="eth9", **kwargs)


def test_dry_run_builds_nothing_sent():
    sent = []
    config = ArpSpoofingConfig(iface="eth9", spoofed_ip=GATEWAY_IP, victim_ip=VICTIM_IP, count=3, interval=0.0, dry_run=True)
    stats = arp.run_arp_spoofing(config, threading.Event(), lambda _s: None, run=fake_run, send=capture(sent))
    assert stats.frames == 3
    assert sent == []


def test_stop_event_interrupts_continuous_run():
    stop = threading.Event()

    def on_progress(stats):
        if stats.frames == 2:
            stop.set()

    config = ArpSpoofingConfig(iface="eth9", spoofed_ip=GATEWAY_IP, victim_ip=VICTIM_IP, count=0, interval=0.0, dry_run=True)
    stats = arp.run_arp_spoofing(config, stop, on_progress, run=fake_run)
    assert stats.frames == 2
