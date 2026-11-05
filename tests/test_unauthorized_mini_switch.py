import threading

import pytest
from scapy.all import Ether

from macabre.attacks.common import BROADCAST_MAC
from macabre.attacks.unauthorized_mini_switch import (
    MAX_CLIENTS,
    MiniSwitchConfig,
    client_frame,
    run_mini_switch,
)

A = "02:00:00:00:00:10"
B = "02:00:00:00:00:11"


def test_client_frame_carries_the_client_mac_to_broadcast():
    frame = client_frame(A)
    assert frame[Ether].src == A
    assert frame[Ether].dst == BROADCAST_MAC


def test_config_needs_two_to_max_distinct_macs():
    with pytest.raises(ValueError):
        MiniSwitchConfig(iface="eth0", client_macs=(A,))
    with pytest.raises(ValueError):
        MiniSwitchConfig(iface="eth0", client_macs=tuple(f"02:00:00:00:01:{i:02x}" for i in range(MAX_CLIENTS + 1)))
    with pytest.raises(ValueError):
        MiniSwitchConfig(iface="eth0", client_macs=(A, A))
    with pytest.raises(ValueError):
        MiniSwitchConfig(iface="eth0", client_macs=(A, "bad"))


def test_run_sends_one_frame_per_client_in_order():
    sent = []
    stats = run_mini_switch(
        MiniSwitchConfig(iface="eth0", client_macs=(A, B)),
        threading.Event(),
        lambda s: None,
        send=lambda frame, **kw: sent.append(frame[Ether].src),
    )
    assert sent == [A, B]
    assert stats.frames == 2
    assert stats.clients == 2


def test_dry_run_sends_nothing():
    sent = []
    stats = run_mini_switch(
        MiniSwitchConfig(iface="eth0", client_macs=(A, B), dry_run=True),
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
    stats = run_mini_switch(
        MiniSwitchConfig(iface="eth0", client_macs=(A, B)),
        stop,
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert stats.frames == 0
