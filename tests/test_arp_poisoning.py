import threading

import pytest
from scapy.all import ARP, Ether

from macabre.attacks import arp_poisoning as poison
from macabre.attacks.arp_poisoning import ArpPoisoningConfig

ATTACKER = "02:00:00:00:00:30"
VICTIM_IP = "10.95.0.10"
GATEWAY_IP = "10.95.0.1"
VICTIM_MAC = "02:00:00:00:00:10"
GATEWAY_MAC = "02:00:00:00:00:01"
LINK_OUTPUT = f"2: eth9: <UP> mtu 1500 link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"


def fake_run(argv):
    return LINK_OUTPUT


def capture(sent):
    return lambda frame, iface, verbose: sent.append(frame)


def config(**kwargs):
    base = dict(iface="eth9", victim_ip=VICTIM_IP, gateway_ip=GATEWAY_IP, count=2, interval=0.0)
    base.update(kwargs)
    return ArpPoisoningConfig(**base)


def test_each_round_poisons_both_caches():
    sent = []
    stats = poison.run_arp_poisoning(config(victim_mac=VICTIM_MAC, gateway_mac=GATEWAY_MAC),
                                     threading.Event(), lambda _s: None, run=fake_run, send=capture(sent))
    assert stats.rounds == 2
    assert stats.frames == 4
    assert len(sent) == 4


def test_victim_is_told_the_gateway_ip_is_at_attacker_mac():
    sent = []
    poison.run_arp_poisoning(config(count=1, victim_mac=VICTIM_MAC), threading.Event(),
                             lambda _s: None, run=fake_run, send=capture(sent))
    to_victim = sent[0]
    assert to_victim[ARP].psrc == GATEWAY_IP
    assert to_victim[ARP].hwsrc == ATTACKER
    assert to_victim[ARP].pdst == VICTIM_IP
    assert to_victim[Ether].dst == VICTIM_MAC


def test_gateway_is_told_the_victim_ip_is_at_attacker_mac():
    sent = []
    poison.run_arp_poisoning(config(count=1, gateway_mac=GATEWAY_MAC), threading.Event(),
                             lambda _s: None, run=fake_run, send=capture(sent))
    to_gateway = sent[1]
    assert to_gateway[ARP].psrc == VICTIM_IP
    assert to_gateway[ARP].hwsrc == ATTACKER
    assert to_gateway[ARP].pdst == GATEWAY_IP
    assert to_gateway[Ether].dst == GATEWAY_MAC


def test_same_host_for_victim_and_gateway_is_rejected():
    with pytest.raises(ValueError, match="different"):
        ArpPoisoningConfig(iface="eth9", victim_ip=VICTIM_IP, gateway_ip=VICTIM_IP)


def test_invalid_mac_is_rejected():
    with pytest.raises(ValueError, match="Invalid MAC"):
        ArpPoisoningConfig(iface="eth9", victim_ip=VICTIM_IP, gateway_ip=GATEWAY_IP, gateway_mac="nope")


def test_dry_run_sends_nothing():
    sent = []
    stats = poison.run_arp_poisoning(config(dry_run=True), threading.Event(),
                                     lambda _s: None, run=fake_run, send=capture(sent))
    assert stats.rounds == 2
    assert sent == []


def test_stop_event_interrupts_continuous_run():
    stop = threading.Event()

    def on_progress(stats):
        if stats.rounds == 3:
            stop.set()

    stats = poison.run_arp_poisoning(config(count=0, dry_run=True), stop, on_progress, run=fake_run)
    assert stats.rounds == 3
