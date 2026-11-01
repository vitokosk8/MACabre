import ipaddress
import random
import threading

import pytest
from scapy.all import ARP, Ether

from macabre.attacks import arp_request_flooding as flood
from macabre.attacks.arp_request_flooding import ArpRequestFloodingConfig

SUBNET = "10.95.0.0/24"
GATEWAY = "10.95.0.1"


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_requests_are_broadcast_arp_who_has_requests():
    frame = flood.build_arp_request("02:00:00:00:00:30", "10.95.0.5", GATEWAY)
    assert frame[Ether].dst == "ff:ff:ff:ff:ff:ff"
    assert frame[ARP].op == 1
    assert frame[ARP].hwsrc == "02:00:00:00:00:30"
    assert frame[ARP].psrc == "10.95.0.5"
    assert frame[ARP].pdst == GATEWAY


def test_fixed_target_is_used_for_every_request():
    sent = []
    config = ArpRequestFloodingConfig(iface="eth9", subnet=SUBNET, target_ip=GATEWAY, count=20)
    flood.run_arp_request_flooding(config, threading.Event(), lambda _s: None,
                                   rng=random.Random(1), send=capture(sent))
    assert {frame[ARP].pdst for _, frame in sent} == {GATEWAY}


def test_random_senders_and_targets_stay_inside_the_subnet_and_vary():
    sent = []
    config = ArpRequestFloodingConfig(iface="eth9", subnet=SUBNET, count=50)
    flood.run_arp_request_flooding(config, threading.Event(), lambda _s: None,
                                   rng=random.Random(2), send=capture(sent))
    network = ipaddress.IPv4Network(SUBNET)
    senders = {frame[ARP].psrc for _, frame in sent}
    targets = {frame[ARP].pdst for _, frame in sent}
    macs = {frame[ARP].hwsrc for _, frame in sent}
    assert all(ipaddress.IPv4Address(ip) in network for ip in senders | targets)
    assert len(senders) > 1 and len(targets) > 1 and len(macs) == 50
    assert all(int(m.split(":")[0], 16) & 0x01 == 0 for m in macs)


def test_dry_run_sends_nothing():
    sent = []
    config = ArpRequestFloodingConfig(iface="eth9", subnet=SUBNET, count=5, dry_run=True)
    stats = flood.run_arp_request_flooding(config, threading.Event(), lambda _s: None,
                                           rng=random.Random(3), send=capture(sent))
    assert stats.frames == 5
    assert sent == []


@pytest.mark.parametrize("kwargs, message", [
    ({"subnet": ""}, "Subnet is required"),
    ({"subnet": "10.95.0.0/40"}, "Invalid subnet"),
    ({"subnet": "10.95.0.1/32"}, "at least two"),
    ({"subnet": SUBNET, "target_ip": "10.95.0.999"}, "Invalid target IP"),
])
def test_invalid_parameters_are_rejected(kwargs, message):
    with pytest.raises(ValueError, match=message):
        ArpRequestFloodingConfig(iface="eth9", **kwargs)


def test_stop_event_interrupts_continuous_run():
    stop = threading.Event()

    def on_progress(stats):
        if stats.frames == 4:
            stop.set()

    config = ArpRequestFloodingConfig(iface="eth9", subnet=SUBNET, count=0, dry_run=True)
    stats = flood.run_arp_request_flooding(config, stop, on_progress, rng=random.Random(4))
    assert stats.frames == 4
