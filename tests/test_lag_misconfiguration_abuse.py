import random
import threading

import pytest
from scapy.all import Ether
from scapy.contrib.lacp import LACP

from macabre.attacks.lacp_spoofing import SLOW_PROTOCOLS_MAC
from macabre.attacks.lag_misconfiguration_abuse import (
    LONG_TIMEOUT_STATE,
    SHORT_TIMEOUT_STATE,
    LagMisconfigurationConfig,
    run_lag_misconfiguration,
    timeout_state,
)

SYSTEM = "02:00:00:00:00:83"


def _config(**overrides):
    values = dict(iface="eth9", system_mac=SYSTEM, frames=3, interval=0.5)
    values.update(overrides)
    return LagMisconfigurationConfig(**values)


def test_long_timeout_clears_the_timeout_bit():
    assert timeout_state("long") == LONG_TIMEOUT_STATE == 0x3D
    assert LONG_TIMEOUT_STATE & 0x02 == 0


def test_short_timeout_sets_the_timeout_bit():
    assert timeout_state("short") == SHORT_TIMEOUT_STATE == 0x3F
    assert SHORT_TIMEOUT_STATE & 0x02 == 0x02


def test_unknown_timeout_mode_is_rejected():
    with pytest.raises(ValueError):
        timeout_state("medium")


def test_lacpdus_carry_the_claimed_actor_and_the_timeout_state():
    sent = []
    run_lag_misconfiguration(
        _config(timeout="short", frames=2), threading.Event(), lambda _s: None,
        send=lambda frame, iface, verbose: sent.append((iface, frame)),
    )
    assert len(sent) == 2
    for iface, frame in sent:
        assert iface == "eth9"
        assert frame[Ether].src == SYSTEM
        assert frame[Ether].dst == SLOW_PROTOCOLS_MAC
        assert frame[LACP].actor_system == SYSTEM
        assert frame[LACP].actor_state == SHORT_TIMEOUT_STATE


def test_long_timeout_frames_do_not_set_the_timeout_bit():
    sent = []
    run_lag_misconfiguration(
        _config(timeout="long", frames=1), threading.Event(), lambda _s: None,
        send=lambda frame, iface, verbose: sent.append(frame),
    )
    assert sent[0][LACP].actor_state == LONG_TIMEOUT_STATE


def test_partner_fields_stay_empty():
    sent = []
    run_lag_misconfiguration(
        _config(frames=1), threading.Event(), lambda _s: None,
        send=lambda frame, iface, verbose: sent.append(frame),
    )
    assert sent[0][LACP].partner_system == "00:00:00:00:00:00"
    assert sent[0][LACP].partner_key == 0


def test_dry_run_sends_nothing_and_reports_the_plan():
    sent = []
    stats = run_lag_misconfiguration(
        _config(dry_run=True, timeout="long"), threading.Event(), lambda _s: None,
        send=lambda *args, **kwargs: sent.append(args),
    )
    assert sent == []
    assert stats.frames == 0
    assert "Dry run" in stats.status and "long timeout" in stats.status


def test_random_system_id_is_used_when_none_is_given():
    sent = []
    stats = run_lag_misconfiguration(
        _config(system_mac="", frames=1), threading.Event(), lambda _s: None,
        rng=random.Random(11), send=lambda frame, iface, verbose: sent.append(frame),
    )
    assert stats.sender_mac == sent[0][Ether].src
    first_octet = int(sent[0][Ether].src.split(":")[0], 16)
    assert first_octet & 0x02 and not first_octet & 0x01


def test_stop_event_ends_the_run_early():
    stop = threading.Event()
    sent = []

    def send(frame, iface, verbose):
        sent.append(frame)
        stop.set()

    stats = run_lag_misconfiguration(_config(frames=5), stop, lambda _s: None, send=send)
    assert stats.frames == 1 and len(sent) == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"frames": 0},
        {"frames": 1001},
        {"interval": 0.1},
        {"timeout": "medium"},
        {"key": 0x10000},
        {"key": -1},
        {"system_mac": "not-a-mac"},
    ],
)
def test_invalid_configuration_is_rejected(overrides):
    with pytest.raises(ValueError):
        _config(**overrides)
