import threading

import pytest
from scapy.all import Ether
from scapy.layers.eap import EAP, EAPOL

from macabre.attacks.eapol_replay import (
    MAX_CAPTURE_SECONDS,
    MAX_REPEATS,
    EapolReplayConfig,
    run_eapol_replay,
    select_responses,
)

VICTIM = "02:00:00:00:00:61"
OTHER = "02:00:00:00:00:62"


def eap_frame(src, code, ident):
    return Ether(src=src, dst="01:80:c2:00:00:03", type=0x888E) / EAPOL(version=2, type=0) / EAP(
        code=code, id=ident, type=4 if code == 2 else None
    )


def test_select_keeps_only_the_victims_responses_in_capture_order():
    frames = [
        eap_frame(VICTIM, 2, 1),
        eap_frame("01:80:c2:00:00:01", 1, 1),
        eap_frame(OTHER, 2, 2),
        eap_frame(VICTIM, 2, 3),
    ]
    selected = select_responses(frames, VICTIM)
    assert [f[EAP].id for f in selected] == [1, 3]
    assert all(f[Ether].src == VICTIM for f in selected)


def test_config_rejects_bad_mac_capture_time_and_repeats():
    with pytest.raises(ValueError):
        EapolReplayConfig(iface="eth0", victim_mac="not-a-mac")
    with pytest.raises(ValueError):
        EapolReplayConfig(iface="eth0", victim_mac=VICTIM, capture_seconds=0)
    with pytest.raises(ValueError):
        EapolReplayConfig(iface="eth0", victim_mac=VICTIM, capture_seconds=MAX_CAPTURE_SECONDS + 1)
    with pytest.raises(ValueError):
        EapolReplayConfig(iface="eth0", victim_mac=VICTIM, repeats=0)
    with pytest.raises(ValueError):
        EapolReplayConfig(iface="eth0", victim_mac=VICTIM, repeats=MAX_REPEATS + 1)


def test_replay_sends_each_captured_response_the_given_number_of_times():
    captured = [eap_frame(VICTIM, 2, 1), eap_frame(VICTIM, 2, 2), eap_frame(OTHER, 2, 9)]
    sent = []
    stats = run_eapol_replay(
        EapolReplayConfig(iface="eth9", victim_mac=VICTIM, repeats=3),
        threading.Event(),
        lambda s: None,
        capture=lambda iface, mac, seconds, stop: captured,
        send=lambda frame, iface, verbose: sent.append((iface, frame[EAP].id)),
    )
    assert stats.captured == 2
    assert stats.replayed == 6
    assert len(sent) == 6
    assert all(iface == "eth9" for iface, _ in sent)
    assert [ident for _, ident in sent] == [1, 2, 1, 2, 1, 2]


def test_dry_run_captures_and_sends_nothing():
    calls = []
    stats = run_eapol_replay(
        EapolReplayConfig(iface="eth9", victim_mac=VICTIM, dry_run=True),
        threading.Event(),
        lambda s: None,
        capture=lambda *a: calls.append(a) or [],
        send=lambda *a, **kw: calls.append(a),
    )
    assert calls == []
    assert "Nothing sent" in stats.status


def test_stop_event_during_replay_stops_sending():
    stop = threading.Event()
    captured = [eap_frame(VICTIM, 2, 1), eap_frame(VICTIM, 2, 2)]
    sent = []

    def send(frame, iface, verbose):
        sent.append(frame)
        stop.set()

    stats = run_eapol_replay(
        EapolReplayConfig(iface="eth9", victim_mac=VICTIM, repeats=2),
        stop,
        lambda s: None,
        capture=lambda *a: captured,
        send=send,
    )
    assert len(sent) == 1
    assert stats.replayed == 1
