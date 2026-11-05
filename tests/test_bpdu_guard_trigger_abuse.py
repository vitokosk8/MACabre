import threading

import pytest
from scapy.all import Ether, Raw

from macabre.attacks.bpdu_guard_trigger_abuse import (
    MAX_BPDUS,
    BpduGuardTriggerConfig,
    build_trigger,
    run_bpdu_guard_trigger,
)

SOURCE = "02:00:00:00:00:20"


def test_trigger_is_a_stp_configuration_bpdu_from_the_source():
    frame = build_trigger(SOURCE)
    assert frame[Ether].src == SOURCE
    assert frame[Ether].dst == "01:80:c2:00:00:00"
    assert frame.haslayer(Raw)
    # LLC header for STP: DSAP and SSAP 0x42
    assert bytes(frame[Raw])[:3] == b"\x42\x42\x03"


def test_config_rejects_bad_counts_and_mac():
    with pytest.raises(ValueError):
        BpduGuardTriggerConfig(iface="eth0", source_mac=SOURCE, bpdus=0)
    with pytest.raises(ValueError):
        BpduGuardTriggerConfig(iface="eth0", source_mac=SOURCE, bpdus=MAX_BPDUS + 1)
    with pytest.raises(ValueError):
        BpduGuardTriggerConfig(iface="eth0", source_mac="bad")


def test_run_sends_each_bpdu_once():
    sent = []
    stats = run_bpdu_guard_trigger(
        BpduGuardTriggerConfig(iface="eth0", source_mac=SOURCE, bpdus=4),
        threading.Event(),
        lambda s: None,
        send=lambda frame, **kw: sent.append(frame),
    )
    assert stats.bpdus == 4
    assert len(sent) == 4


def test_dry_run_sends_nothing():
    sent = []
    stats = run_bpdu_guard_trigger(
        BpduGuardTriggerConfig(iface="eth0", source_mac=SOURCE, dry_run=True),
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
    stats = run_bpdu_guard_trigger(
        BpduGuardTriggerConfig(iface="eth0", source_mac=SOURCE),
        stop,
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert stats.bpdus == 0
