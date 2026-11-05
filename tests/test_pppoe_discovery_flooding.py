import random
import threading

import pytest
from scapy.all import Ether
from scapy.layers.ppp import PPPoED

from macabre.attacks.pppoe_discovery_flooding import (
    MAX_FRAMES,
    PppoeDiscoveryFloodingConfig,
    build_padi,
    run_pppoe_discovery_flooding,
)

SOURCE = "02:00:00:00:00:31"


def test_padi_is_a_broadcast_discovery_frame_with_code_09_and_session_zero():
    frame = build_padi(SOURCE)
    assert frame[Ether].src == SOURCE
    assert frame[Ether].dst == "ff:ff:ff:ff:ff:ff"
    assert frame[Ether].type == 0x8863
    assert frame[PPPoED].code == 0x09
    assert frame[PPPoED].sessionid == 0


def test_config_rejects_bad_counts_and_macs():
    for frames in (0, MAX_FRAMES + 1):
        with pytest.raises(ValueError):
            PppoeDiscoveryFloodingConfig(iface="eth0", frames=frames)
    with pytest.raises(ValueError):
        PppoeDiscoveryFloodingConfig(iface="eth0", source_mac="not-a-mac")
    with pytest.raises(ValueError):
        PppoeDiscoveryFloodingConfig(iface="eth0", source_mac="01:00:5e:00:00:01")


def test_empty_source_mac_is_allowed_and_means_random():
    config = PppoeDiscoveryFloodingConfig(iface="eth0", frames=3)
    assert config.source_mac == ""


def test_random_mode_uses_a_different_client_for_each_frame():
    sent = []
    stats = run_pppoe_discovery_flooding(
        PppoeDiscoveryFloodingConfig(iface="eth9", frames=30),
        threading.Event(),
        lambda s: None,
        rng=random.Random(1),
        send=lambda frame, iface, verbose: sent.append((iface, frame)),
    )
    assert stats.frames == 30
    assert len(sent) == 30
    assert all(iface == "eth9" for iface, _ in sent)
    assert len({frame[Ether].src for _, frame in sent}) == 30


def test_fixed_mode_uses_the_given_source_for_every_frame():
    sent = []
    run_pppoe_discovery_flooding(
        PppoeDiscoveryFloodingConfig(iface="eth9", frames=5, source_mac=SOURCE),
        threading.Event(),
        lambda s: None,
        rng=random.Random(2),
        send=lambda frame, iface, verbose: sent.append(frame),
    )
    assert {frame[Ether].src for frame in sent} == {SOURCE}


def test_dry_run_sends_nothing():
    sent = []
    stats = run_pppoe_discovery_flooding(
        PppoeDiscoveryFloodingConfig(iface="eth9", frames=4, dry_run=True),
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
    stats = run_pppoe_discovery_flooding(
        PppoeDiscoveryFloodingConfig(iface="eth9", frames=4),
        stop,
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert stats.frames == 0
