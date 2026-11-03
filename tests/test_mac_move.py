import threading

import pytest
from scapy.all import Ether

from macabre.attacks.mac_move import (
    EXPERIMENTAL_ETHERTYPE,
    MAX_FRAMES,
    MacMoveConfig,
    move_frames,
    run_mac_move,
)


def test_move_frames_carry_the_target_as_source():
    frames = move_frames("02:00:00:00:00:50", 3)
    assert len(frames) == 3
    for frame in frames:
        assert frame[Ether].src == "02:00:00:00:00:50"
        assert frame[Ether].dst == "ff:ff:ff:ff:ff:ff"
        assert frame[Ether].type == EXPERIMENTAL_ETHERTYPE


def test_config_rejects_bad_target_and_frame_counts():
    with pytest.raises(ValueError):
        MacMoveConfig(iface="eth0", target_mac="not-a-mac")
    with pytest.raises(ValueError):
        MacMoveConfig(iface="eth0", target_mac="02:00:00:00:00:50", frames=0)
    with pytest.raises(ValueError):
        MacMoveConfig(iface="eth0", target_mac="02:00:00:00:00:50", frames=MAX_FRAMES + 1)


def test_run_sends_the_move_frames_once():
    sent = []
    stats = run_mac_move(
        MacMoveConfig(iface="eth0", target_mac="02:00:00:00:00:50", frames=4),
        threading.Event(),
        lambda s: None,
        send=lambda frames, **kw: sent.extend(frames),
    )
    assert stats.frames == 4
    assert len(sent) == 4


def test_dry_run_sends_nothing():
    sent = []
    stats = run_mac_move(
        MacMoveConfig(iface="eth0", target_mac="02:00:00:00:00:50", dry_run=True),
        threading.Event(),
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert stats.frames == 0
    assert "Nothing sent" in stats.status


def test_stop_event_set_before_run_sends_nothing():
    stop = threading.Event()
    stop.set()
    sent = []
    run_mac_move(
        MacMoveConfig(iface="eth0", target_mac="02:00:00:00:00:50"),
        stop,
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
