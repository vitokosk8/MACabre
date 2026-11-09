import threading

import pytest

from macabre.attacks import l2_loop_amplification as l2
from macabre.attacks.l2_loop_amplification import L2LoopAmplificationConfig


def config(**overrides):
    values = dict(iface="h0")
    values.update(overrides)
    return L2LoopAmplificationConfig(**values)


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_each_frame_has_a_random_unicast_source_and_the_group_destination():
    sent = []
    l2.run_l2_loop_amplification(config(frames=3, interval=0.01, seed=7), threading.Event(),
                                 lambda _s: None, send=capture(sent))
    assert len(sent) == 3
    sources = {frame.src for _, frame in sent}
    assert len(sources) == 3
    for iface, frame in sent:
        assert iface == "h0"
        assert frame.dst == "ff:ff:ff:ff:ff:ff"
        assert frame.type == l2.EXPERIMENTAL_ETHERTYPE
        assert int(frame.src.split(":")[0], 16) & 0x01 == 0  # unicast source


def test_the_same_seed_gives_the_same_sources():
    first, second = [], []
    l2.run_l2_loop_amplification(config(frames=2, interval=0.01, seed=3), threading.Event(),
                                 lambda _s: None, send=capture(first))
    l2.run_l2_loop_amplification(config(frames=2, interval=0.01, seed=3), threading.Event(),
                                 lambda _s: None, send=capture(second))
    assert [f.src for _, f in first] == [f.src for _, f in second]


def test_a_multicast_destination_is_allowed():
    sent = []
    l2.run_l2_loop_amplification(config(destination="01:00:5e:00:00:01", interval=0.01),
                                 threading.Event(), lambda _s: None, send=capture(sent))
    assert sent[0][1].dst == "01:00:5e:00:00:01"


@pytest.mark.parametrize("destination", ["", "00:11:22:33:44:55", "not-a-mac"])
def test_a_unicast_or_invalid_destination_is_rejected(destination):
    with pytest.raises(ValueError):
        config(destination=destination)


@pytest.mark.parametrize("overrides, message", [
    (dict(iface=""), "Interface is required"),
    (dict(frames=0), "between 1 and"),
    (dict(frames=l2.MAX_FRAMES + 1), "between 1 and"),
    (dict(interval=0), "Interval must be positive"),
    (dict(payload_size=0), "Payload must be between"),
])
def test_invalid_parameters_are_rejected(overrides, message):
    with pytest.raises(ValueError, match=message):
        config(**overrides)


def test_dry_run_sends_nothing():
    sent = []
    stats = l2.run_l2_loop_amplification(config(dry_run=True), threading.Event(),
                                         lambda _s: None, send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")


def test_a_set_stop_event_stops_before_the_first_frame():
    sent = []
    event = threading.Event()
    event.set()
    stats = l2.run_l2_loop_amplification(config(frames=5), event, lambda _s: None, send=capture(sent))
    assert sent == [] and stats.frames == 0


def test_amplification_factor_is_copies_per_frame():
    assert l2.amplification_factor(copies=50, frames=5) == 10
    assert l2.amplification_factor(copies=0, frames=1) == 0


def test_amplification_factor_rejects_bad_counts():
    with pytest.raises(ValueError):
        l2.amplification_factor(copies=1, frames=0)
    with pytest.raises(ValueError):
        l2.amplification_factor(copies=-1, frames=1)


def test_the_source_mac_is_never_the_destination_or_a_group_address():
    sent = []
    l2.run_l2_loop_amplification(config(frames=20, interval=0.01, seed=11), threading.Event(),
                                 lambda _s: None, send=capture(sent))
    for _, frame in sent:
        assert frame.src != frame.dst
