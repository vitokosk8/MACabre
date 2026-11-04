import random
import threading

import pytest
from scapy.all import ARP, Ether

from macabre.attacks.arp_table_exhaustion import (
    MAX_RATE,
    ArpTableExhaustionConfig,
    fake_sender_request,
    run_arp_table_exhaustion,
)

VICTIM = "10.77.0.10"
SUBNET = "10.77.0.128/25"


def test_requests_ask_for_the_victim_and_come_from_new_senders():
    rng = random.Random(4)
    frames = [fake_sender_request(rng, SUBNET, VICTIM) for _ in range(40)]
    senders = {f[ARP].psrc for f in frames}
    macs = {f[ARP].hwsrc for f in frames}
    assert all(f[ARP].pdst == VICTIM for f in frames)
    assert all(f[Ether].dst == "ff:ff:ff:ff:ff:ff" for f in frames)
    assert all(f[Ether].src == f[ARP].hwsrc for f in frames)
    assert len(macs) == 40
    assert len(senders) > 30  # random senders, almost all distinct
    for ip in senders:
        assert ip.startswith("10.77.0.") and int(ip.split(".")[-1]) >= 129


def test_config_rejects_bad_inputs():
    with pytest.raises(ValueError):
        ArpTableExhaustionConfig(iface="eth0", victim_ip="not-an-ip", subnet=SUBNET)
    with pytest.raises(ValueError):
        ArpTableExhaustionConfig(iface="eth0", victim_ip=VICTIM, subnet="10.77.0.1/32")
    with pytest.raises(ValueError):
        ArpTableExhaustionConfig(iface="eth0", victim_ip=VICTIM, subnet=SUBNET, rate=MAX_RATE + 1)
    with pytest.raises(ValueError):
        ArpTableExhaustionConfig(iface="eth0", victim_ip=VICTIM, subnet=SUBNET, count=-1)


def test_run_sends_exactly_count_requests():
    sent = []
    stats = run_arp_table_exhaustion(
        ArpTableExhaustionConfig(iface="eth0", victim_ip=VICTIM, subnet=SUBNET, rate=100, count=15),
        threading.Event(),
        lambda s: None,
        rng=random.Random(5),
        send=lambda frames, **kw: sent.extend(frames),
    )
    assert stats.requests == 15
    assert len(sent) == 15


def test_dry_run_sends_nothing():
    sent = []
    stats = run_arp_table_exhaustion(
        ArpTableExhaustionConfig(iface="eth0", victim_ip=VICTIM, subnet=SUBNET, count=10, dry_run=True),
        threading.Event(),
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert stats.requests == 0
    assert "Nothing sent" in stats.status


def test_stop_event_set_before_run_sends_nothing():
    stop = threading.Event()
    stop.set()
    sent = []
    run_arp_table_exhaustion(
        ArpTableExhaustionConfig(iface="eth0", victim_ip=VICTIM, subnet=SUBNET),
        stop,
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
