import ipaddress
import threading

import pytest
from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, IPv6

from macabre.attacks import neighbor_solicitation_spoofing as ns
from macabre.attacks.neighbor_solicitation_spoofing import NeighborSolicitationSpoofingConfig

ATTACKER = "02:00:00:00:00:30"
TARGET = "2001:db8:1::20"


def config(**overrides):
    values = dict(iface="a1", source_mac=ATTACKER, target=TARGET, frames=2)
    values.update(overrides)
    return NeighborSolicitationSpoofingConfig(**values)


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_solicited_node_address_uses_the_low_24_bits():
    assert str(ns.solicited_node(ipaddress.IPv6Address(TARGET))) == "ff02::1:ff00:20"


def test_solicited_node_mac_is_33_33_plus_the_low_32_bits():
    assert ns.solicited_node_mac(ipaddress.IPv6Address("ff02::1:ff00:20")) == "33:33:ff:00:00:20"


def test_the_frame_impersonates_the_target_and_carries_the_operator_mac():
    frame = ns.build_solicitation(config())
    assert frame[IPv6].src == TARGET
    assert frame[IPv6].dst == "ff02::1:ff00:20"
    assert frame[IPv6].hlim == 255
    assert frame[ICMPv6ND_NS].tgt == TARGET
    assert frame[ICMPv6NDOptSrcLLAddr].lladdr == ATTACKER
    assert frame.dst == "33:33:ff:00:00:20"
    assert frame.src == ATTACKER


def test_each_frame_is_sent_on_the_interface_without_waiting():
    sent = []
    stats = ns.run_neighbor_solicitation_spoofing(config(), threading.Event(), lambda _s: None,
                                                  send=capture(sent))
    assert stats.frames == 2
    assert [iface for iface, _ in sent] == ["a1", "a1"]


def test_dry_run_sends_nothing():
    sent = []
    stats = ns.run_neighbor_solicitation_spoofing(config(dry_run=True), threading.Event(),
                                                  lambda _s: None, send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")


def test_a_set_stop_event_stops_before_the_first_frame():
    sent = []
    event = threading.Event()
    event.set()
    stats = ns.run_neighbor_solicitation_spoofing(config(), event, lambda _s: None, send=capture(sent))
    assert sent == [] and stats.frames == 0


@pytest.mark.parametrize("overrides, message", [
    (dict(target=""), "Target IPv6 address is required"),
    (dict(target="not-an-address"), "is not an IPv6 address"),
    (dict(target="ff02::1"), "unicast"),
    (dict(target="::"), "unicast"),
    (dict(frames=0), "Frames must be between"),
    (dict(frames=ns.MAX_FRAMES + 1), "Frames must be between"),
    (dict(source_mac="01:00:5e:00:00:01"), "unicast"),
])
def test_invalid_parameters_are_rejected(overrides, message):
    with pytest.raises(ValueError, match=message):
        config(**overrides)


def test_a_receiver_moves_the_frame_to_its_solicited_node_group():
    frame = ns.build_solicitation(config(receiver="2001:db8:1::10"))
    assert frame[IPv6].dst == "ff02::1:ff00:10"
    assert frame.dst == "33:33:ff:00:00:10"
    assert frame[ICMPv6ND_NS].tgt == "2001:db8:1::10"
    assert frame[IPv6].src == TARGET
    assert frame[IPv6].src == TARGET


def test_an_invalid_receiver_is_rejected():
    with pytest.raises(ValueError, match="unicast"):
        config(receiver="ff02::1")
