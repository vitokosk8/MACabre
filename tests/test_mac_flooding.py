import random
import threading

from scapy.all import Ether, Raw

from macabre.attacks import mac_flooding as flood
from macabre.attacks.mac_flooding import MacFloodingConfig, build_flood_frame


def test_flood_frame_has_random_unicast_source_and_destination():
    rng = random.Random(10)
    for _ in range(100):
        frame = build_flood_frame(rng)
        src_octets = [int(p, 16) for p in frame[Ether].src.split(":")]
        dst_octets = [int(p, 16) for p in frame[Ether].dst.split(":")]
        assert src_octets[0] & 0x01 == 0 and src_octets[0] & 0x02 == 0x02
        assert dst_octets[0] & 0x01 == 0  # unicast: never a broadcast/multicast
        assert frame[Ether].dst != "ff:ff:ff:ff:ff:ff"
        assert frame[Ether].src != frame[Ether].dst


def test_flood_frame_has_minimum_payload_size():
    frame = build_flood_frame(random.Random(11))
    assert len(frame[Raw].load) == flood.PAYLOAD_SIZE


def test_flood_frames_are_distinct():
    rng = random.Random(12)
    sources = {build_flood_frame(rng)[Ether].src for _ in range(500)}
    assert len(sources) == 500


def test_dry_run_counts_without_sending(monkeypatch):
    sent = []
    monkeypatch.setattr(flood, "sendp", lambda *a, **k: sent.append(a))

    progress = []
    config = MacFloodingConfig(iface="lo", count=7, interval=0.0, dry_run=True)
    stats = flood.run_flooding(config, threading.Event(), progress.append, rng=random.Random(1))

    assert stats.frames == 7
    assert [p.frames for p in progress] == list(range(1, 8))
    assert sent == []


def test_live_run_sends_on_the_configured_interface(monkeypatch):
    sent = []
    monkeypatch.setattr(flood, "sendp", lambda frame, iface, verbose: sent.append(iface))

    config = MacFloodingConfig(iface="eth3", count=4, interval=0.0)
    stats = flood.run_flooding(config, threading.Event(), lambda _s: None, rng=random.Random(2))

    assert stats.frames == 4
    assert sent == ["eth3"] * 4


def test_stop_event_interrupts_continuous_run():
    stop = threading.Event()

    def on_progress(stats):
        if stats.frames == 5:
            stop.set()

    config = MacFloodingConfig(iface="lo", count=0, interval=0.0, dry_run=True)
    stats = flood.run_flooding(config, stop, on_progress, rng=random.Random(3))

    assert stats.frames == 5
