import random
import threading

import pytest
from scapy.all import Ether
from scapy.layers.eap import EAPOL

from macabre.attacks.eapol_start_flooding import (
    MAX_FRAMES,
    PAE_GROUP_MAC,
    EapolStartFloodingConfig,
    build_start,
    run_eapol_start_flooding,
)

SOURCE = "02:00:00:00:00:61"


def test_start_is_an_eapol_start_to_the_pae_group_address():
    frame = build_start(SOURCE)
    assert frame[Ether].src == SOURCE
    assert frame[Ether].dst == PAE_GROUP_MAC == "01:80:c2:00:00:03"
    assert frame[Ether].type == 0x888E
    assert frame[EAPOL].type == 1
    assert frame[EAPOL].version == 2


def test_config_rejects_bad_counts_and_macs():
    for frames in (0, MAX_FRAMES + 1):
        with pytest.raises(ValueError):
            EapolStartFloodingConfig(iface="eth0", frames=frames)
    with pytest.raises(ValueError):
        EapolStartFloodingConfig(iface="eth0", source_mac="not-a-mac")
    with pytest.raises(ValueError):
        EapolStartFloodingConfig(iface="eth0", source_mac="01:80:c2:00:00:03")


def test_random_mode_uses_a_different_supplicant_for_each_frame():
    sent = []
    stats = run_eapol_start_flooding(
        EapolStartFloodingConfig(iface="eth9", frames=30),
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
    run_eapol_start_flooding(
        EapolStartFloodingConfig(iface="eth9", frames=5, source_mac=SOURCE),
        threading.Event(),
        lambda s: None,
        rng=random.Random(2),
        send=lambda frame, iface, verbose: sent.append(frame),
    )
    assert {frame[Ether].src for frame in sent} == {SOURCE}


def test_dry_run_sends_nothing():
    sent = []
    stats = run_eapol_start_flooding(
        EapolStartFloodingConfig(iface="eth9", frames=4, dry_run=True),
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
    stats = run_eapol_start_flooding(
        EapolStartFloodingConfig(iface="eth9", frames=4),
        stop,
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert stats.frames == 0
