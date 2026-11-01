import random
import threading

import pytest
from scapy.all import Ether

from macabre.attacks import mac_spoofing as spoof
from macabre.attacks.common import BROADCAST_MAC
from macabre.attacks.mac_spoofing import MacSpoofingConfig


def test_frames_claim_the_target_mac_as_source():
    sent = []
    config = MacSpoofingConfig(iface="eth9", target_mac="02:00:00:00:00:10", count=4)
    spoof.run_spoofing(
        config,
        threading.Event(),
        lambda _s: None,
        rng=random.Random(1),
        send=lambda frame, iface, verbose: sent.append((iface, frame)),
    )
    assert len(sent) == 4
    assert {iface for iface, _ in sent} == {"eth9"}
    assert {frame[Ether].src for _, frame in sent} == {"02:00:00:00:00:10"}


def test_frames_go_to_broadcast_with_experimental_ethertype():
    frame = spoof.build_spoof_frame("02:00:00:00:00:10", random.Random(2))
    assert frame[Ether].dst == BROADCAST_MAC
    assert frame[Ether].type == 0x88B5


def test_target_is_normalized_to_lowercase():
    sent = []
    config = MacSpoofingConfig(iface="a", target_mac="02:AA:BB:CC:DD:EE", count=1)
    spoof.run_spoofing(
        config,
        threading.Event(),
        lambda _s: None,
        rng=random.Random(3),
        send=lambda frame, iface, verbose: sent.append(frame),
    )
    assert sent[0][Ether].src == "02:aa:bb:cc:dd:ee"


def test_missing_target_is_rejected():
    with pytest.raises(ValueError, match="required"):
        MacSpoofingConfig(iface="a", target_mac="")


def test_invalid_target_is_rejected():
    with pytest.raises(ValueError, match="Invalid MAC"):
        MacSpoofingConfig(iface="a", target_mac="not-a-mac")


def test_multicast_target_is_rejected():
    with pytest.raises(ValueError, match="unicast"):
        MacSpoofingConfig(iface="a", target_mac="01:00:5e:00:00:01")


def test_dry_run_counts_without_sending(monkeypatch):
    sent = []
    monkeypatch.setattr(spoof, "sendp", lambda *a, **k: sent.append(a))
    config = MacSpoofingConfig(iface="a", target_mac="02:00:00:00:00:10", count=3, dry_run=True)
    stats = spoof.run_spoofing(config, threading.Event(), lambda _s: None, rng=random.Random(4))
    assert stats.frames == 3
    assert sent == []


def test_stop_event_interrupts_continuous_run():
    stop = threading.Event()

    def on_progress(stats):
        if stats.frames == 2:
            stop.set()

    config = MacSpoofingConfig(iface="a", target_mac="02:00:00:00:00:10", count=0, dry_run=True)
    stats = spoof.run_spoofing(config, stop, on_progress, rng=random.Random(5))
    assert stats.frames == 2
