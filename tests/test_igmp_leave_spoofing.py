import threading

import pytest
from scapy.all import IGMP, IP, Ether
from scapy.layers.inet import IPOption_Router_Alert

from macabre.attacks.igmp_leave_spoofing import (
    MAX_LEAVES,
    IgmpLeaveSpoofingConfig,
    build_leave,
    run_igmp_leave_spoofing,
)
from macabre.attacks.igmp_spoofing import MAX_GROUPS

SOURCE = "02:00:00:00:00:20"
GROUP = "239.1.2.3"


def test_leave_is_an_igmpv2_leave_to_all_routers():
    frame = build_leave(SOURCE, "10.0.0.20", GROUP)
    assert frame[Ether].src == SOURCE
    assert frame[Ether].dst == "01:00:5e:00:00:02"
    assert frame[IP].dst == "224.0.0.2"
    assert frame[IP].ttl == 1
    assert frame[IP].proto == 2
    assert frame[IP].haslayer(IPOption_Router_Alert)
    assert frame[IGMP].type == 0x17
    assert frame[IGMP].gaddr == GROUP


def test_config_rejects_bad_groups_and_counts():
    with pytest.raises(ValueError):
        IgmpLeaveSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=("10.0.0.1",))
    with pytest.raises(ValueError):
        IgmpLeaveSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=())
    with pytest.raises(ValueError):
        IgmpLeaveSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=tuple(f"239.0.0.{i}" for i in range(MAX_GROUPS + 1)))
    with pytest.raises(ValueError):
        IgmpLeaveSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=(GROUP,), leaves=0)
    with pytest.raises(ValueError):
        IgmpLeaveSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=(GROUP,), leaves=MAX_LEAVES + 1)
    with pytest.raises(ValueError):
        IgmpLeaveSpoofingConfig(iface="eth0", source_mac="bad", groups=(GROUP,))
    with pytest.raises(ValueError):
        IgmpLeaveSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=(GROUP,), source_ip="bad")


def test_run_sends_leaves_per_group():
    sent = []
    stats = run_igmp_leave_spoofing(
        IgmpLeaveSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=(GROUP, "239.9.9.9"), leaves=2),
        threading.Event(),
        lambda s: None,
        send=lambda frames, **kw: sent.append(frames),
    )
    assert stats.leaves == 4
    assert len(sent) == 4


def test_dry_run_sends_nothing():
    sent = []
    stats = run_igmp_leave_spoofing(
        IgmpLeaveSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=(GROUP,), dry_run=True),
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
    stats = run_igmp_leave_spoofing(
        IgmpLeaveSpoofingConfig(iface="eth0", source_mac=SOURCE, groups=(GROUP,)),
        stop,
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert stats.leaves == 0
