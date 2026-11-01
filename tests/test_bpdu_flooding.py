import random
import struct
import threading

import pytest

from macabre.attacks import bpdu_flooding as flood
from macabre.attacks.bpdu_flooding import BpduFloodingConfig


def capture(sent):
    return lambda frames, iface, verbose: sent.append((iface, frames))


def test_every_frame_advertises_the_worst_priority_and_a_random_bridge():
    frames = flood.flood_frames(random.Random(1), 20)
    sources = set()
    for frame in frames:
        body = bytes(frame.load)[3:]
        assert struct.unpack("!H", body[5:7])[0] == 61440
        assert struct.unpack("!H", body[17:19])[0] == 61440
        sources.add(frame.src)
    assert len(sources) == 20
    assert all(int(src.split(":")[0], 16) & 0x02 for src in sources)  # locally administered


def test_run_sends_the_requested_total_in_batches():
    sent = []
    stats = flood.run_bpdu_flooding(BpduFloodingConfig(iface="eth9", rate=100, count=25),
                                    threading.Event(), lambda _s: None,
                                    rng=random.Random(2), send=capture(sent))
    assert stats.frames == 25
    assert sum(len(batch) for _, batch in sent) == 25
    assert all(iface == "eth9" for iface, _ in sent)


def test_dry_run_sends_nothing():
    sent = []
    stats = flood.run_bpdu_flooding(BpduFloodingConfig(iface="eth9", rate=100, count=5, dry_run=True),
                                    threading.Event(), lambda _s: None,
                                    rng=random.Random(3), send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")


@pytest.mark.parametrize("rate", [0, -1, 5001])
def test_rate_must_be_within_limits(rate):
    with pytest.raises(ValueError, match="Rate"):
        BpduFloodingConfig(iface="eth9", rate=rate)
