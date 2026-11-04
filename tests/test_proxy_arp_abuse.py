import threading

import pytest
from scapy.all import ARP, Ether

from macabre.attacks.proxy_arp_abuse import (
    MAX_TARGETS,
    ProxyArpProbeConfig,
    collect_answers,
    probe_requests,
    run_proxy_arp_probe,
)

SENDER = "10.1.0.30"
OWN_MAC = "02:00:00:00:00:30"
ROUTER_MAC = "02:00:00:00:00:01"


def config(**overrides):
    values = dict(iface="eth0", sender_ip=SENDER, prefix_length=24, targets=("10.2.0.50",))
    values.update(overrides)
    return ProxyArpProbeConfig(**values)


def test_requests_come_from_the_sender_and_ask_for_each_target():
    frames = probe_requests(OWN_MAC, SENDER, ("10.2.0.50", "10.3.0.9"))
    assert len(frames) == 2
    for frame, target in zip(frames, ("10.2.0.50", "10.3.0.9")):
        assert frame[Ether].src == OWN_MAC
        assert frame[Ether].dst == "ff:ff:ff:ff:ff:ff"
        assert frame[ARP].op == 1
        assert frame[ARP].psrc == SENDER
        assert frame[ARP].pdst == target


def test_targets_inside_the_segment_are_refused():
    with pytest.raises(ValueError):
        config(targets=("10.1.0.99",))


def test_bad_inputs_are_refused():
    with pytest.raises(ValueError):
        config(sender_ip="not-an-ip")
    with pytest.raises(ValueError):
        config(prefix_length=0)
    with pytest.raises(ValueError):
        config(targets=())
    with pytest.raises(ValueError):
        config(targets=tuple(f"10.2.0.{i}" for i in range(1, MAX_TARGETS + 2)))
    with pytest.raises(ValueError):
        config(timeout=0)


def reply(target, mac):
    return (Ether(src=OWN_MAC) / ARP(op=1, psrc=SENDER, pdst=target),
            Ether(src=mac) / ARP(op=2, psrc=target, hwsrc=mac, pdst=SENDER))


def test_collect_answers_keeps_only_is_at_replies():
    answered = [reply("10.2.0.50", ROUTER_MAC), reply("10.2.0.51", ROUTER_MAC)]
    answered.append((Ether() / ARP(op=1), None))
    assert collect_answers(answered) == {"10.2.0.50": ROUTER_MAC, "10.2.0.51": ROUTER_MAC}


def test_run_reports_the_router_that_answers():
    seen = {}

    def fake_send_receive(requests, **kwargs):
        seen["count"] = len(requests)
        seen["timeout"] = kwargs["timeout"]
        return [reply("10.2.0.50", ROUTER_MAC)], []

    stats = run_proxy_arp_probe(
        config(), threading.Event(), lambda s: None, own_mac=OWN_MAC, send_receive=fake_send_receive,
    )
    assert seen == {"count": 1, "timeout": 3.0}
    assert stats.answers == {"10.2.0.50": ROUTER_MAC}
    assert "Answered for 1 of 1" in stats.status


def test_run_reports_no_answers():
    stats = run_proxy_arp_probe(
        config(), threading.Event(), lambda s: None,
        own_mac=OWN_MAC, send_receive=lambda requests, **kw: ([], []),
    )
    assert stats.answers == {}
    assert "No answers" in stats.status


def test_dry_run_sends_nothing():
    sent = []
    stats = run_proxy_arp_probe(
        config(dry_run=True), threading.Event(), lambda s: None,
        own_mac=OWN_MAC, send_receive=lambda *a, **kw: sent.append(a) or ([], []),
    )
    assert sent == []
    assert "Nothing sent" in stats.status
