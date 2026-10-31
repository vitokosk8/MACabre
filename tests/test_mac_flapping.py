import random
import threading

import pytest
from scapy.all import Ether

from macabre.attacks import mac_flapping as flap
from macabre.attacks.mac_flapping import MacFlappingConfig


def test_same_target_mac_is_used_in_every_frame():
    sent = []
    config = MacFlappingConfig(
        iface_a="a", iface_b="b", target_mac="02:00:00:00:00:10", count=6, interval=0.0
    )
    flap.run_flapping(
        config,
        threading.Event(),
        lambda _s: None,
        rng=random.Random(1),
        send=lambda frame, iface, verbose: sent.append((iface, frame)),
    )
    assert {frame[Ether].src for _, frame in sent} == {"02:00:00:00:00:10"}


def test_frames_alternate_between_the_two_interfaces():
    sent = []
    config = MacFlappingConfig(iface_a="ethA", iface_b="ethB", count=6, interval=0.0)
    stats = flap.run_flapping(
        config,
        threading.Event(),
        lambda _s: None,
        rng=random.Random(2),
        send=lambda frame, iface, verbose: sent.append(iface),
    )
    assert stats.frames == 6
    assert sent == ["ethA", "ethB", "ethA", "ethB", "ethA", "ethB"]


def test_random_target_is_lowercase_unicast_and_stable_across_frames():
    sent = []
    config = MacFlappingConfig(iface_a="a", iface_b="b", count=4, interval=0.0)
    flap.run_flapping(
        config,
        threading.Event(),
        lambda _s: None,
        rng=random.Random(3),
        send=lambda frame, iface, verbose: sent.append(frame),
    )
    sources = {f[Ether].src for f in sent}
    assert len(sources) == 1
    src = sources.pop()
    assert src == src.lower()
    assert int(src.split(":")[0], 16) & 0x01 == 0


def test_dry_run_counts_without_sending(monkeypatch):
    sent = []
    monkeypatch.setattr(flap, "sendp", lambda *a, **k: sent.append(a))
    config = MacFlappingConfig(iface_a="a", iface_b="b", count=5, dry_run=True)
    stats = flap.run_flapping(config, threading.Event(), lambda _s: None, rng=random.Random(4))
    assert stats.frames == 5
    assert sent == []


def test_same_interface_for_both_ports_is_rejected():
    with pytest.raises(ValueError, match="different"):
        MacFlappingConfig(iface_a="eth0", iface_b="eth0")


def test_invalid_target_mac_is_rejected():
    with pytest.raises(ValueError, match="Invalid MAC"):
        MacFlappingConfig(iface_a="a", iface_b="b", target_mac="not-a-mac")


def test_stop_event_interrupts_continuous_run():
    stop = threading.Event()

    def on_progress(stats):
        if stats.frames == 3:
            stop.set()

    config = MacFlappingConfig(iface_a="a", iface_b="b", count=0, dry_run=True)
    stats = flap.run_flapping(config, stop, on_progress, rng=random.Random(5))
    assert stats.frames == 3
