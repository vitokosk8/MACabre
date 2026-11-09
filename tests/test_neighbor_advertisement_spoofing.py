import threading

import pytest
from scapy.all import Ether
from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr, IPv6

from macabre.attacks import neighbor_advertisement_spoofing as na
from macabre.attacks.neighbor_advertisement_spoofing import SolicitedAdvertisementConfig

TARGET = "2001:db8:1::20"
REQUESTER = "2001:db8:1::10"
REQUESTER_MAC = "02:00:00:00:00:10"
SOURCE = "02:00:00:00:00:30"


def config(**overrides):
    values = dict(iface="a1", source_mac=SOURCE, target=TARGET)
    values.update(overrides)
    return SolicitedAdvertisementConfig(**values)


def solicitation(target=TARGET, src=REQUESTER):
    return (Ether(src=REQUESTER_MAC, dst="33:33:ff:00:00:20")
            / IPv6(src=src, dst="ff02::1:ff00:20", hlim=255)
            / ICMPv6ND_NS(tgt=target)
            / ICMPv6NDOptSrcLLAddr(lladdr=REQUESTER_MAC))


def sniffer(packets):
    """Stand-in for scapy.sniff: feeds the packets that pass lfilter to prn, like the real call."""
    def run(**kwargs):
        for packet in packets:
            if kwargs["lfilter"](packet):
                kwargs["prn"](packet)
    return run


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_the_reply_is_a_solicited_advertisement_without_override():
    frame = na.build_solicited_advertisement(config(), solicitation())
    assert frame[ICMPv6ND_NA].tgt == TARGET
    assert frame[ICMPv6ND_NA].S == 1
    assert frame[ICMPv6ND_NA].O == 0
    assert frame[ICMPv6NDOptDstLLAddr].lladdr == SOURCE


def test_the_reply_is_unicast_to_the_requester_from_the_operators_mac():
    frame = na.build_solicited_advertisement(config(), solicitation())
    assert frame.dst == REQUESTER_MAC
    assert frame.src == SOURCE
    assert frame[IPv6].dst == REQUESTER
    assert frame[IPv6].src == TARGET
    assert frame[IPv6].hlim == 255


def test_each_matching_solicitation_gets_one_reply():
    sent = []
    packets = [solicitation(), solicitation(), solicitation()]
    stats = na.run_solicited_advertisement_spoofing(config(answers=2), threading.Event(), lambda _s: None,
                                                    sniff_func=sniffer(packets), send=capture(sent))
    assert len(sent) == 2 and stats.frames == 2
    assert all(iface == "a1" for iface, _ in sent)


def test_solicitations_for_other_addresses_are_ignored():
    sent = []
    na.run_solicited_advertisement_spoofing(config(), threading.Event(), lambda _s: None,
                                            sniff_func=sniffer([solicitation(target="2001:db8:1::99")]),
                                            send=capture(sent))
    assert sent == []


def test_duplicate_address_probes_from_the_unspecified_address_are_ignored():
    sent = []
    na.run_solicited_advertisement_spoofing(config(), threading.Event(), lambda _s: None,
                                            sniff_func=sniffer([solicitation(src="::")]), send=capture(sent))
    assert sent == []


def test_dry_run_sends_nothing():
    sent = []
    stats = na.run_solicited_advertisement_spoofing(config(dry_run=True), threading.Event(), lambda _s: None,
                                                    sniff_func=sniffer([solicitation()]), send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")


def test_a_set_stop_event_sends_nothing():
    sent = []
    event = threading.Event()
    event.set()
    na.run_solicited_advertisement_spoofing(config(), event, lambda _s: None,
                                            sniff_func=sniffer([solicitation()]), send=capture(sent))
    assert sent == []


@pytest.mark.parametrize("overrides", [
    dict(iface=""),
    dict(source_mac="01:00:5e:00:00:01"),
    dict(source_mac="not-a-mac"),
    dict(target=""),
    dict(target="ff02::1"),
    dict(answers=0),
    dict(answers=na.MAX_ANSWERS + 1),
    dict(timeout=0.1),
    dict(timeout=120),
])
def test_invalid_parameters_are_rejected(overrides):
    with pytest.raises(ValueError):
        config(**overrides)
