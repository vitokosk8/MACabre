import random
import threading

import pytest
from scapy.all import Ether
from scapy.contrib.lacp import LACP

from macabre.attacks.lacp_negotiation_flooding import (
    LacpNegotiationFloodingConfig,
    parse_states,
    run_lacp_negotiation_flooding,
    state_schedule,
)
from macabre.attacks.lacp_spoofing import SLOW_PROTOCOLS_MAC, build_lacpdu

SYSTEM = "02:00:00:00:00:82"


def _config(**overrides):
    values = dict(iface="eth9", system_mac=SYSTEM, frames=4, interval=0.01)
    values.update(overrides)
    return LacpNegotiationFloodingConfig(**values)


def test_default_states_alternate_between_two_values():
    config = LacpNegotiationFloodingConfig(iface="eth9")
    assert config.states == (0x3F, 0x07)
    assert state_schedule(config.states, 5) == [0x3F, 0x07, 0x3F, 0x07, 0x3F]


def test_lacpdus_carry_the_claimed_actor_and_the_scheduled_state():
    sent = []
    stats = run_lacp_negotiation_flooding(
        _config(states=(0x3F, 0x07), frames=4), threading.Event(), lambda _s: None,
        send=lambda frame, iface, verbose: sent.append((iface, frame)),
    )
    assert stats.frames == 4 and len(sent) == 4
    assert {iface for iface, _ in sent} == {"eth9"}
    for (_, frame), state in zip(sent, [0x3F, 0x07, 0x3F, 0x07]):
        assert frame[Ether].src == SYSTEM
        assert frame[Ether].dst == SLOW_PROTOCOLS_MAC
        assert frame[LACP].actor_system == SYSTEM
        assert frame[LACP].actor_state == state


def test_state_changes_are_counted_between_consecutive_frames():
    stats = run_lacp_negotiation_flooding(
        _config(states=(0x3F, 0x07), frames=5), threading.Event(), lambda _s: None,
        send=lambda frame, iface, verbose: None,
    )
    assert stats.state_changes == 4


def test_a_single_state_causes_no_changes():
    stats = run_lacp_negotiation_flooding(
        _config(states=(0x3F,), frames=5), threading.Event(), lambda _s: None,
        send=lambda frame, iface, verbose: None,
    )
    assert stats.state_changes == 0


def test_partner_fields_stay_empty():
    frame = build_lacpdu(SYSTEM, state=0x07)
    assert frame[LACP].partner_system == "00:00:00:00:00:00"
    assert frame[LACP].partner_key == 0


def test_dry_run_sends_nothing_and_reports_the_plan():
    sent = []
    stats = run_lacp_negotiation_flooding(
        _config(dry_run=True), threading.Event(), lambda _s: None,
        send=lambda *args, **kwargs: sent.append(args),
    )
    assert sent == []
    assert stats.frames == 0
    assert "Dry run" in stats.status and "Nothing sent" in stats.status


def test_random_system_id_is_used_when_none_is_given():
    sent = []
    stats = run_lacp_negotiation_flooding(
        _config(system_mac="", frames=1), threading.Event(), lambda _s: None,
        rng=random.Random(7), send=lambda frame, iface, verbose: sent.append(frame),
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

    stats = run_lacp_negotiation_flooding(_config(frames=10), stop, lambda _s: None, send=send)
    assert stats.frames == 1 and len(sent) == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"frames": 0},
        {"frames": 1001},
        {"interval": 0.001},
        {"interval": 0},
        {"states": ()},
        {"states": (0x3F,) * 9},
        {"states": (0x100,)},
        {"key": -1},
        {"key": 0x10000},
        {"system_mac": "not-a-mac"},
    ],
)
def test_invalid_configuration_is_rejected(overrides):
    with pytest.raises(ValueError):
        _config(**overrides)


def test_parse_states_accepts_hex_and_decimal():
    assert parse_states("0x3F, 7") == (0x3F, 7)


@pytest.mark.parametrize("text", ["", " , ", "0x3G", "abc"])
def test_parse_states_rejects_bad_input(text):
    with pytest.raises(ValueError):
        parse_states(text)
