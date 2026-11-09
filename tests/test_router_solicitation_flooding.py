import threading

import pytest
from scapy.layers.inet6 import ICMPv6ND_RS, ICMPv6NDOptSrcLLAddr, IPv6

from macabre.attacks import router_solicitation_flooding as rs
from macabre.attacks.router_solicitation_flooding import RouterSolicitationFloodingConfig

SOURCE = "02:00:00:00:00:30"


def config(**overrides):
    values = dict(iface="a1", source_mac=SOURCE)
    values.update(overrides)
    return RouterSolicitationFloodingConfig(**values)


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_the_solicitation_goes_to_all_routers_with_the_operators_mac():
    frame = rs.build_solicitation(config())
    assert frame.dst == "33:33:00:00:00:02"
    assert frame[IPv6].dst == "ff02::2"
    assert frame[IPv6].hlim == 255
    assert frame[IPv6].src.startswith("fe80::")
    assert frame.haslayer(ICMPv6ND_RS)
    assert frame[ICMPv6NDOptSrcLLAddr].lladdr == SOURCE


def test_run_sends_the_requested_number_of_solicitations():
    sent = []
    stats = rs.run_router_solicitation_flooding(config(frames=4, interval=0.001), threading.Event(),
                                                lambda _s: None, send=capture(sent))
    assert len(sent) == 4 and stats.frames == 4
    assert all(iface == "a1" for iface, _ in sent)


def test_dry_run_sends_nothing():
    sent = []
    stats = rs.run_router_solicitation_flooding(config(dry_run=True), threading.Event(),
                                                lambda _s: None, send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")


def test_a_set_stop_event_stops_before_the_first_solicitation():
    sent = []
    event = threading.Event()
    event.set()
    stats = rs.run_router_solicitation_flooding(config(frames=5), event, lambda _s: None, send=capture(sent))
    assert sent == [] and stats.frames == 0


@pytest.mark.parametrize("overrides", [
    dict(iface=""),
    dict(source_mac="01:00:5e:00:00:01"),
    dict(source_mac="not-a-mac"),
    dict(frames=0),
    dict(frames=rs.MAX_FRAMES + 1),
    dict(interval=0.0001),
    dict(interval=5),
])
def test_invalid_parameters_are_rejected(overrides):
    with pytest.raises(ValueError):
        config(**overrides)
