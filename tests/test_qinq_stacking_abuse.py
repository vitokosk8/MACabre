import threading

import pytest
from scapy.all import Dot1Q, Ether

from macabre.attacks.qinq_stacking_abuse import (
    EXPERIMENTAL_ETHERTYPE,
    MAX_FRAMES,
    TPID_CUSTOMER,
    TPID_PROVIDER,
    QinQStackingConfig,
    run_qinq_stacking,
    stacked_frame,
)

SOURCE = "02:00:00:00:00:30"


def test_frame_has_provider_outer_tag_and_customer_inner_tag():
    frame = stacked_frame(SOURCE, provider_vid=100, customer_vid=20)
    assert frame[Ether].type == TPID_PROVIDER
    assert frame[Dot1Q].vlan == 100
    assert frame[Dot1Q].type == TPID_CUSTOMER
    inner = frame[Dot1Q].payload
    assert isinstance(inner, Dot1Q)
    assert inner.vlan == 20
    assert inner.type == EXPERIMENTAL_ETHERTYPE


def test_config_rejects_bad_vlans_and_counts():
    with pytest.raises(ValueError):
        QinQStackingConfig(iface="eth0", provider_vid=0, customer_vid=20, source_mac=SOURCE)
    with pytest.raises(ValueError):
        QinQStackingConfig(iface="eth0", provider_vid=100, customer_vid=4095, source_mac=SOURCE)
    with pytest.raises(ValueError):
        QinQStackingConfig(iface="eth0", provider_vid=100, customer_vid=20, source_mac=SOURCE, frames=0)
    with pytest.raises(ValueError):
        QinQStackingConfig(iface="eth0", provider_vid=100, customer_vid=20, source_mac=SOURCE,
                           frames=MAX_FRAMES + 1)
    with pytest.raises(ValueError):
        QinQStackingConfig(iface="eth0", provider_vid=100, customer_vid=20, source_mac="not-a-mac")


def test_run_sends_the_frames_once():
    sent = []
    stats = run_qinq_stacking(
        QinQStackingConfig(iface="eth0", provider_vid=100, customer_vid=20, source_mac=SOURCE, frames=3),
        threading.Event(),
        lambda s: None,
        send=lambda frames, **kw: sent.extend(frames),
    )
    assert stats.frames == 3
    assert len(sent) == 3


def test_dry_run_sends_nothing():
    sent = []
    stats = run_qinq_stacking(
        QinQStackingConfig(iface="eth0", provider_vid=100, customer_vid=20, source_mac=SOURCE, dry_run=True),
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
    run_qinq_stacking(
        QinQStackingConfig(iface="eth0", provider_vid=100, customer_vid=20, source_mac=SOURCE),
        stop,
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
