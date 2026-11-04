import threading

import pytest
from scapy.all import IGMP, IP, Ether
from scapy.layers.inet import IPOption_Router_Alert

from macabre.attacks.igmp_spoofing import (
    MAX_GROUPS,
    MAX_REPORTS,
    IgmpSpoofingConfig,
    build_report,
    group_mac,
    run_igmp_spoofing,
    validate_group,
)

SOURCE = "02:00:00:00:00:20"
GROUP = "239.1.2.3"


def test_group_mac_uses_the_low_23_bits_of_the_group():
    assert group_mac("239.1.2.3") == "01:00:5e:01:02:03"
    # 239.129.2.3 differs from 239.1.2.3 only in bit 23, which the MAC drops: the known aliasing.
    assert group_mac("239.129.2.3") == "01:00:5e:01:02:03"


def test_report_is_an_igmpv2_membership_report_for_the_group():
    frame = build_report(SOURCE, "10.0.0.20", GROUP)
    assert frame[Ether].src == SOURCE
    assert frame[Ether].dst == "01:00:5e:01:02:03"
    assert frame[IP].src == "10.0.0.20"
    assert frame[IP].dst == GROUP
    assert frame[IP].proto == 2
    assert frame[IP].ttl == 1
    assert frame[IGMP].type == 0x16
    assert frame[IGMP].gaddr == GROUP


def test_report_carries_the_router_alert_option():
    frame = build_report(SOURCE, "0.0.0.0", GROUP)
    assert frame[IP].haslayer(IPOption_Router_Alert)


def test_config_rejects_bad_groups():
    for bad in ("10.0.0.1", "224.0.0.1", "not-an-ip", "240.0.0.1"):
        with pytest.raises(ValueError):
            validate_group(bad)
    with pytest.raises(ValueError):
        IgmpSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=("10.0.0.1",))


def test_config_rejects_bad_counts_and_addresses():
    with pytest.raises(ValueError):
        IgmpSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=())
    with pytest.raises(ValueError):
        IgmpSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=tuple(f"239.0.0.{i}" for i in range(MAX_GROUPS + 1)))
    with pytest.raises(ValueError):
        IgmpSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=(GROUP,), reports=0)
    with pytest.raises(ValueError):
        IgmpSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=(GROUP,), reports=MAX_REPORTS + 1)
    with pytest.raises(ValueError):
        IgmpSpoofingConfig(iface="eth0", source_mac="not-a-mac", groups=(GROUP,))
    with pytest.raises(ValueError):
        IgmpSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=(GROUP,), source_ip="bad")


def test_run_sends_reports_per_group():
    sent = []
    stats = run_igmp_spoofing(
        IgmpSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=(GROUP, "239.9.9.9"), reports=2),
        threading.Event(),
        lambda s: None,
        send=lambda frames, **kw: sent.append(frames),
    )
    assert stats.reports == 4
    assert len(sent) == 4


def test_dry_run_sends_nothing():
    sent = []
    stats = run_igmp_spoofing(
        IgmpSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=(GROUP,), dry_run=True),
        threading.Event(),
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert "Nothing sent" in stats.status


def test_stop_event_set_before_run_sends_nothing():
    stop = threading.Event()
    stop.set()
    sent = []
    stats = run_igmp_spoofing(
        IgmpSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=(GROUP,)),
        stop,
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert stats.reports == 0
