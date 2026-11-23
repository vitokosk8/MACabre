import threading

import pytest
from scapy.all import Ether
from scapy.layers.ppp import PPPoED

from macabre.attacks.pppoe_session_spoofing import (
    CODE_PADT,
    PppoeSessionSpoofingConfig,
    build_padt,
    run_pppoe_session_spoofing,
)

AC = "02:00:00:00:00:86"
CLIENT = "02:00:00:00:00:87"


def _config(**overrides):
    values = dict(iface="eth9", source_mac=AC, client_mac=CLIENT, session_id=5, frames=2, interval=0.1)
    values.update(overrides)
    return PppoeSessionSpoofingConfig(**values)


def test_padt_is_a_discovery_frame_from_the_claimed_concentrator_to_the_client():
    frame = build_padt(AC, CLIENT, 5)
    assert frame[Ether].src == AC
    assert frame[Ether].dst == CLIENT
    assert frame[Ether].type == 0x8863
    assert frame[PPPoED].code == CODE_PADT == 0xA7
    assert frame[PPPoED].sessionid == 5
    # On the wire: version/type (1), code (1), session ID (2), length (2) = 0 for a PADT with no tags.
    assert bytes(frame)[18:20] == b"\x00\x00"


def test_run_sends_the_configured_number_of_padts():
    sent = []
    stats = run_pppoe_session_spoofing(
        _config(frames=3), threading.Event(), lambda _s: None,
        send=lambda frame, iface, verbose: sent.append((iface, frame)),
    )
    assert stats.frames == 3 and len(sent) == 3
    assert {iface for iface, _ in sent} == {"eth9"}
    assert all(frame[PPPoED].sessionid == 5 for _, frame in sent)


def test_dry_run_sends_nothing():
    sent = []
    stats = run_pppoe_session_spoofing(
        _config(dry_run=True), threading.Event(), lambda _s: None,
        send=lambda *args, **kwargs: sent.append(args),
    )
    assert sent == [] and stats.frames == 0
    assert "Dry run" in stats.status and "Nothing sent" in stats.status


def test_stop_event_ends_the_run_early():
    stop = threading.Event()
    sent = []

    def send(frame, iface, verbose):
        sent.append(frame)
        stop.set()

    stats = run_pppoe_session_spoofing(_config(frames=5), stop, lambda _s: None, send=send)
    assert stats.frames == 1 and len(sent) == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"session_id": 0},
        {"session_id": 0x10000},
        {"frames": 0},
        {"frames": 21},
        {"interval": 0.01},
        {"source_mac": "not-a-mac"},
        {"client_mac": "not-a-mac"},
    ],
)
def test_invalid_configuration_is_rejected(overrides):
    with pytest.raises(ValueError):
        _config(**overrides)
