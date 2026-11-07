import threading

import pytest
from scapy.layers.inet6 import ICMPv6MLReport, IPv6ExtHdrHopByHop, RouterAlert

from macabre.attacks import mld_spoofing_flooding as mld
from macabre.attacks.mld_spoofing_flooding import MldSpoofingFloodingConfig

ATTACKER = "02:00:00:00:10:03"
GROUP = "ff0e::1000"


def config(**overrides):
    values = dict(iface="eth9", source_mac=ATTACKER, base_group=GROUP, count=1)
    values.update(overrides)
    return MldSpoofingFloodingConfig(**values)


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_report_names_the_group_as_type_131():
    report = mld.build_report(ATTACKER, GROUP).getlayer(ICMPv6MLReport)
    assert report.type == 131
    assert str(report.mladdr) == GROUP


def test_report_has_hop_limit_1_and_a_router_alert_option():
    frame = mld.build_report(ATTACKER, GROUP)
    assert frame.getlayer("IPv6").hlim == 1
    alert = frame.getlayer(IPv6ExtHdrHopByHop)
    assert alert is not None
    assert alert.getlayer(RouterAlert) is not None


def test_report_is_sent_to_the_group_with_its_mac_and_a_link_local_source():
    frame = mld.build_report(ATTACKER, GROUP)
    ip = frame.getlayer("IPv6")
    assert ip.dst == GROUP
    assert ip.src == "fe80::ff:fe00:1003"
    assert frame.dst == "33:33:00:00:10:00"
    assert frame.src == ATTACKER


def test_group_mac_uses_the_last_32_bits_of_the_group():
    assert mld.group_mac("ff0e::1:2:3:4") == "33:33:00:03:00:04"


def test_range_takes_consecutive_groups_inside_ff0e():
    groups = mld.group_range("ff0e::1000", 3)
    assert groups == ("ff0e::1000", "ff0e::1001", "ff0e::1002")


def test_run_sends_one_report_per_group():
    sent = []
    stats = mld.run_mld_spoofing_flooding(config(count=5), threading.Event(), lambda _s: None, send=capture(sent))
    assert stats.reports == 5 and len(sent) == 5
    assert all(iface == "eth9" for iface, _ in sent)


def test_dry_run_sends_nothing():
    sent = []
    stats = mld.run_mld_spoofing_flooding(config(dry_run=True), threading.Event(), lambda _s: None, send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")


def test_stop_event_ends_the_run_early():
    sent = []
    stop = threading.Event()
    stop.set()
    stats = mld.run_mld_spoofing_flooding(config(), stop, lambda _s: None, send=capture(sent))
    assert sent == [] and stats.reports == 0


def test_range_must_stay_inside_ff0e():
    with pytest.raises(ValueError, match="ff0e"):
        config(base_group="ff0e:ffff:ffff:ffff:ffff:ffff:ffff:ffff", count=2)


@pytest.mark.parametrize("group", ["ff02::1", "2001:db8::1", "not-an-address"])
def test_base_group_must_be_global_multicast(group):
    with pytest.raises(ValueError):
        config(base_group=group)


@pytest.mark.parametrize("count", [0, 8193])
def test_count_out_of_range_is_refused(count):
    with pytest.raises(ValueError, match="Groups"):
        config(count=count)


def test_source_mac_is_required():
    with pytest.raises(ValueError):
        config(source_mac="")
