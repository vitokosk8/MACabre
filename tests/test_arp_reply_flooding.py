import ipaddress
import random
import threading

import pytest
from scapy.all import ARP, Ether

from macabre.attacks import arp_reply_flooding as flood
from macabre.attacks.arp_reply_flooding import ArpReplyFloodingConfig

SUBNET = "10.96.0.0/24"
VICTIM = "10.96.0.10"


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_frames_are_broadcast_arp_replies():
    frame = flood.build_arp_reply("02:00:00:00:00:30", "10.96.0.5", VICTIM)
    assert frame[Ether].dst == "ff:ff:ff:ff:ff:ff"
    assert frame[ARP].op == 2
    assert frame[ARP].hwsrc == "02:00:00:00:00:30"
    assert frame[ARP].psrc == "10.96.0.5"
    assert frame[ARP].pdst == VICTIM


def test_fixed_victim_is_used_for_every_reply():
    sent = []
    config = ArpReplyFloodingConfig(iface="eth9", subnet=SUBNET, victim_ip=VICTIM, count=20)
    flood.run_arp_reply_flooding(config, threading.Event(), lambda _s: None,
                                 rng=random.Random(1), send=capture(sent))
    assert {frame[ARP].pdst for _, frame in sent} == {VICTIM}


def test_random_senders_and_victims_stay_inside_the_subnet_and_vary():
    sent = []
    config = ArpReplyFloodingConfig(iface="eth9", subnet=SUBNET, count=50)
    flood.run_arp_reply_flooding(config, threading.Event(), lambda _s: None,
                                 rng=random.Random(2), send=capture(sent))
    network = ipaddress.IPv4Network(SUBNET)
    senders = {frame[ARP].psrc for _, frame in sent}
    victims = {frame[ARP].pdst for _, frame in sent}
    macs = {frame[ARP].hwsrc for _, frame in sent}
    assert all(ipaddress.IPv4Address(ip) in network for ip in senders | victims)
    assert len(senders) > 1 and len(victims) > 1 and len(macs) == 50
    assert all(int(m.split(":")[0], 16) & 0x01 == 0 for m in macs)


def test_dry_run_sends_nothing():
    sent = []
    config = ArpReplyFloodingConfig(iface="eth9", subnet=SUBNET, count=5, dry_run=True)
    stats = flood.run_arp_reply_flooding(config, threading.Event(), lambda _s: None,
                                         rng=random.Random(3), send=capture(sent))
    assert stats.frames == 5
    assert sent == []


@pytest.mark.parametrize("kwargs, message", [
    ({"subnet": ""}, "Subnet is required"),
    ({"subnet": "10.96.0.0/40"}, "Invalid subnet"),
    ({"subnet": "10.96.0.1/32"}, "at least two"),
    ({"subnet": SUBNET, "victim_ip": "10.96.0.999"}, "Invalid victim IP"),
])
def test_invalid_parameters_are_rejected(kwargs, message):
    with pytest.raises(ValueError, match=message):
        ArpReplyFloodingConfig(iface="eth9", **kwargs)


def test_stop_event_interrupts_continuous_run():
    stop = threading.Event()

    def on_progress(stats):
        if stats.frames == 4:
            stop.set()

    config = ArpReplyFloodingConfig(iface="eth9", subnet=SUBNET, count=0, dry_run=True)
    stats = flood.run_arp_reply_flooding(config, stop, on_progress, rng=random.Random(4))
    assert stats.frames == 4
