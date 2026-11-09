import threading

import pytest
from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, IPv6

from macabre.attacks import duplicate_address_detection_dos as dad
from macabre.attacks.duplicate_address_detection_dos import DuplicateAddressDetectionDosConfig

TARGET = "2001:db8:1::50"
SOURCE = "02:00:00:00:00:30"


def config(**overrides):
    values = dict(iface="a1", source_mac=SOURCE, target=TARGET)
    values.update(overrides)
    return DuplicateAddressDetectionDosConfig(**values)


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_the_advertisement_answers_for_the_tentative_address_with_override():
    frame = dad.build_duplicate_advertisement(config())
    assert frame[ICMPv6ND_NA].tgt == TARGET
    assert frame[ICMPv6ND_NA].O == 1
    assert frame[ICMPv6ND_NA].S == 0
    assert frame[ICMPv6NDOptDstLLAddr].lladdr == SOURCE


def test_the_advertisement_goes_to_all_nodes_from_the_operators_mac():
    frame = dad.build_duplicate_advertisement(config())
    assert frame.dst == "33:33:00:00:00:01"
    assert frame[IPv6].dst == "ff02::1"
    assert frame[IPv6].hlim == 255
    assert frame.src == SOURCE


def test_run_sends_the_requested_number_of_advertisements():
    sent = []
    stats = dad.run_duplicate_address_detection_dos(config(frames=3, interval=0.01), threading.Event(),
                                                    lambda _s: None, send=capture(sent))
    assert len(sent) == 3 and stats.frames == 3
    assert all(iface == "a1" for iface, _ in sent)


def test_dry_run_sends_nothing():
    sent = []
    stats = dad.run_duplicate_address_detection_dos(config(dry_run=True), threading.Event(),
                                                    lambda _s: None, send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")


def test_a_set_stop_event_stops_before_the_first_advertisement():
    sent = []
    event = threading.Event()
    event.set()
    stats = dad.run_duplicate_address_detection_dos(config(frames=5), event, lambda _s: None, send=capture(sent))
    assert sent == [] and stats.frames == 0


@pytest.mark.parametrize("overrides", [
    dict(iface=""),
    dict(source_mac="01:00:5e:00:00:01"),
    dict(source_mac="not-a-mac"),
    dict(target=""),
    dict(target="ff02::1"),
    dict(target="not-an-address"),
    dict(frames=0),
    dict(frames=dad.MAX_FRAMES + 1),
    dict(interval=0.001),
    dict(interval=5),
])
def test_invalid_parameters_are_rejected(overrides):
    with pytest.raises(ValueError):
        config(**overrides)
