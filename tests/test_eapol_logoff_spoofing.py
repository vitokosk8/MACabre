import threading

import pytest
from scapy.all import Ether
from scapy.layers.eap import EAPOL

from macabre.attacks.eapol_logoff_spoofing import (
    MAX_LOGOFFS,
    PAE_GROUP_MAC,
    EapolLogoffSpoofingConfig,
    build_logoff,
    run_eapol_logoff_spoofing,
)

VICTIM = "02:00:00:00:00:61"


def test_logoff_claims_the_victim_mac_and_goes_to_the_pae_group():
    frame = build_logoff(VICTIM)
    assert frame[Ether].src == VICTIM
    assert frame[Ether].dst == PAE_GROUP_MAC == "01:80:c2:00:00:03"
    assert frame[Ether].type == 0x888E
    assert frame[EAPOL].type == 2
    assert frame[EAPOL].version == 2


def test_config_requires_a_valid_source_and_bounded_count():
    with pytest.raises(ValueError):
        EapolLogoffSpoofingConfig(iface="eth0", source_mac="not-a-mac")
    with pytest.raises(ValueError):
        EapolLogoffSpoofingConfig(iface="eth0", source_mac="01:80:c2:00:00:03")
    with pytest.raises(ValueError):
        EapolLogoffSpoofingConfig(iface="eth0", source_mac=VICTIM, logoffs=0)
    with pytest.raises(ValueError):
        EapolLogoffSpoofingConfig(iface="eth0", source_mac=VICTIM, logoffs=MAX_LOGOFFS + 1)


def test_run_sends_the_requested_number_of_logoffs_from_the_victim_mac():
    sent = []
    stats = run_eapol_logoff_spoofing(
        EapolLogoffSpoofingConfig(iface="eth9", source_mac=VICTIM, logoffs=3),
        threading.Event(),
        lambda s: None,
        send=lambda frame, iface, verbose: sent.append((iface, frame)),
    )
    assert stats.logoffs == 3
    assert len(sent) == 3
    assert all(iface == "eth9" for iface, _ in sent)
    assert {frame[Ether].src for _, frame in sent} == {VICTIM}


def test_dry_run_sends_nothing():
    sent = []
    stats = run_eapol_logoff_spoofing(
        EapolLogoffSpoofingConfig(iface="eth9", source_mac=VICTIM, dry_run=True),
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
    stats = run_eapol_logoff_spoofing(
        EapolLogoffSpoofingConfig(iface="eth9", source_mac=VICTIM, logoffs=2),
        stop,
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert stats.logoffs == 0
