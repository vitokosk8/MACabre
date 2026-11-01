import threading

import pytest
from scapy.all import ARP, Ether

from macabre.attacks import mab_bypass as mab
from macabre.attacks.mab_bypass import MabBypassConfig

ATTACKER = "02:00:00:00:00:30"
ALLOWED = "02:00:00:00:00:50"
GATEWAY = "10.99.0.1"


def make_run(calls, original=ATTACKER):
    def run(argv):
        calls.append(argv)
        if argv[:4] == ["ip", "-o", "link", "show"]:
            return f"2: eth9: <UP> link/ether {original} brd ff:ff:ff:ff:ff:ff"
        return ""
    return run


def test_probe_is_an_arp_request_from_the_allowed_mac_with_no_sender_address():
    frame = mab.probe_frame(ALLOWED, GATEWAY)
    assert frame[Ether].src == ALLOWED
    assert frame[ARP].op == 1 and frame[ARP].hwsrc == ALLOWED
    assert frame[ARP].psrc == "0.0.0.0" and frame[ARP].pdst == GATEWAY


def test_only_the_gateways_reply_to_the_allowed_mac_counts():
    reply = Ether(src="02:aa:aa:aa:aa:01") / ARP(op=2, psrc=GATEWAY, hwsrc="02:aa:aa:aa:aa:01", hwdst=ALLOWED)
    assert mab.is_reply(reply, ALLOWED, GATEWAY)
    other_host = Ether() / ARP(op=2, psrc="10.99.0.7", hwsrc="02:aa:aa:aa:aa:07", hwdst=ALLOWED)
    assert not mab.is_reply(other_host, ALLOWED, GATEWAY)
    to_someone_else = Ether() / ARP(op=2, psrc=GATEWAY, hwsrc="02:aa:aa:aa:aa:01", hwdst=ATTACKER)
    assert not mab.is_reply(to_someone_else, ALLOWED, GATEWAY)


class FakeSniffer:
    """Delivers the scripted packets to the callback when started, then stops."""
    packets = []

    def __init__(self, **kwargs):
        self.prn = kwargs["prn"]

    def start(self):
        for packet in FakeSniffer.packets:
            self.prn(packet)

    def stop(self):
        pass


def run_probe(replies, calls, original=ATTACKER):
    FakeSniffer.packets = replies
    sent = []
    stop = threading.Event()
    stop.set()  # the wait returns at once, so the test does not sleep
    stats = mab.run_mab_bypass(MabBypassConfig(iface="eth9", target_mac=ALLOWED, gateway_ip=GATEWAY),
                               stop, lambda _s: None, run=make_run(calls, original),
                               send=lambda frame, iface, verbose: sent.append(frame),
                               sniffer_factory=FakeSniffer)
    return stats, sent


def test_reply_means_the_port_accepted_the_allowed_identity_and_mac_is_restored():
    calls = []
    reply = Ether(src="02:aa:aa:aa:aa:01") / ARP(op=2, psrc=GATEWAY, hwsrc="02:aa:aa:aa:aa:01", hwdst=ALLOWED)
    stats, sent = run_probe([reply], calls)
    assert stats.reply and stats.probes == 1 and len(sent) == 1
    assert ["ip", "link", "set", "dev", "eth9", "address", ALLOWED] in calls
    assert ["ip", "link", "set", "dev", "eth9", "address", ATTACKER] in calls  # restored


def test_no_reply_means_the_port_did_not_accept_it():
    calls = []
    stats, _ = run_probe([], calls)
    assert not stats.reply
    assert "did not accept" in stats.status
    assert ["ip", "link", "set", "dev", "eth9", "address", ATTACKER] in calls


def test_mac_is_restored_even_if_the_probe_fails():
    calls = []

    def failing_send(frame, iface, verbose):
        raise OSError("link went away")

    FakeSniffer.packets = []
    with pytest.raises(OSError):
        mab.run_mab_bypass(MabBypassConfig(iface="eth9", target_mac=ALLOWED, gateway_ip=GATEWAY),
                           threading.Event(), lambda _s: None, run=make_run(calls),
                           send=failing_send, sniffer_factory=FakeSniffer)
    assert ["ip", "link", "set", "dev", "eth9", "address", ATTACKER] in calls


@pytest.mark.parametrize("kwargs", [{"target_mac": "01:00:0c:cc:cc:cc"}, {"gateway_ip": "nope"},
                                    {"wait_seconds": 0}])
def test_invalid_settings_are_rejected(kwargs):
    base = {"iface": "eth9", "target_mac": ALLOWED, "gateway_ip": GATEWAY}
    base.update(kwargs)
    with pytest.raises(ValueError):
        MabBypassConfig(**base)


def test_dry_run_changes_nothing():
    calls = []
    stats = mab.run_mab_bypass(MabBypassConfig(iface="eth9", target_mac=ALLOWED, gateway_ip=GATEWAY, dry_run=True),
                               threading.Event(), lambda _s: None, run=make_run(calls),
                               send=lambda *a, **k: None, sniffer_factory=FakeSniffer)
    assert calls == [] and stats.status.startswith("Dry run")
