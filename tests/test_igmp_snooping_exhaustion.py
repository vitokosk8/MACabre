import threading

import pytest

from macabre.attacks import igmp_snooping_exhaustion as ise
from macabre.attacks.igmp_snooping_exhaustion import IgmpSnoopingExhaustionConfig
from macabre.attacks.igmp_spoofing import group_mac

SENDER = "02:00:00:00:00:20"


def config(**overrides):
    values = dict(iface="eth9", source_mac=SENDER, base_group="239.100.0.1", count=5)
    values.update(overrides)
    return IgmpSnoopingExhaustionConfig(**values)


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_group_range_is_consecutive_and_distinct():
    groups = ise.group_range("239.100.0.1", 4)
    assert groups == ("239.100.0.1", "239.100.0.2", "239.100.0.3", "239.100.0.4")
    assert len(set(groups)) == 4


def test_each_report_targets_its_own_group_mac():
    sent = []
    ise.run_igmp_snooping_exhaustion(config(count=3), threading.Event(), lambda _s: None, send=capture(sent))
    groups = ise.group_range("239.100.0.1", 3)
    for (iface, frame), group in zip(sent, groups):
        assert iface == "eth9"
        assert frame.dst == group_mac(group)
        assert frame.getlayer("IGMP").gaddr == group


def test_one_report_per_group_is_sent():
    sent = []
    stats = ise.run_igmp_snooping_exhaustion(config(count=7), threading.Event(), lambda _s: None, send=capture(sent))
    assert stats.reports == 7 and len(sent) == 7


def test_base_outside_administratively_scoped_range_is_refused():
    with pytest.raises(ValueError, match="239.0.0.0/8"):
        config(base_group="224.0.1.1")


def test_range_leaving_239_slash_8_is_refused():
    with pytest.raises(ValueError, match="leaves 239.0.0.0/8"):
        config(base_group="239.255.255.250", count=10)


def test_local_control_range_is_refused():
    with pytest.raises(ValueError, match="local control range"):
        config(base_group="224.0.0.5")


@pytest.mark.parametrize("count", [0, 8193])
def test_count_out_of_range_is_refused(count):
    with pytest.raises(ValueError, match="between 1 and"):
        config(count=count)


def test_source_mac_is_required():
    with pytest.raises(ValueError):
        config(source_mac="")


def test_dry_run_sends_nothing():
    sent = []
    stats = ise.run_igmp_snooping_exhaustion(config(dry_run=True), threading.Event(), lambda _s: None,
                                             send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")


def test_stop_event_ends_the_run_early():
    sent = []
    stop = threading.Event()
    stop.set()
    stats = ise.run_igmp_snooping_exhaustion(config(count=5), stop, lambda _s: None, send=capture(sent))
    assert sent == [] and stats.reports == 0
