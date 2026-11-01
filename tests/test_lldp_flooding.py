import random
import threading

import pytest

from macabre.attacks import lldp_flooding as flood
from macabre.attacks.lldp_flooding import LldpFloodingConfig
from macabre.attacks.lldp_spoofing import TLV_CHASSIS_ID, TLV_SYSTEM_NAME, build_lldp_frame


def capture(sent):
    return lambda frames, iface, verbose: sent.append((iface, frames))


def tlvs_of(payload: bytes):
    import struct
    out, pos = [], 0
    while pos < len(payload):
        (header,) = struct.unpack("!H", payload[pos:pos + 2])
        kind, length = header >> 9, header & 0x1FF
        out.append((kind, payload[pos + 2:pos + 2 + length]))
        pos += 2 + length
    return out


def test_every_frame_is_from_a_random_local_mac_for_a_different_chassis():
    frames = flood.flood_frames(random.Random(1), 20)
    sources = {frame.src for frame in frames}
    assert len(sources) == 20
    assert all(int(src.split(":")[0], 16) & 0x02 for src in sources)
    names, chassis = set(), set()
    for frame in frames:
        values = dict(tlvs_of(bytes(frame.load)))
        names.add(values[TLV_SYSTEM_NAME])
        chassis.add(values[TLV_CHASSIS_ID])
    assert len(names) == 20 and len(chassis) == 20


def test_run_sends_the_requested_total_in_batches():
    sent = []
    stats = flood.run_lldp_flooding(LldpFloodingConfig(iface="eth9", rate=100, count=25),
                                    threading.Event(), lambda _s: None, rng=random.Random(2),
                                    send=capture(sent))
    assert stats.frames == 25
    assert sum(len(frames) for _, frames in sent) == 25


def test_rate_sets_the_batch_size():
    sent = []
    flood.run_lldp_flooding(LldpFloodingConfig(iface="eth9", rate=50, count=10),
                            threading.Event(), lambda _s: None, rng=random.Random(3), send=capture(sent))
    assert len(sent[0][1]) == 5


@pytest.mark.parametrize("rate", [0, -1, 5001])
def test_rate_must_be_positive_and_capped(rate):
    with pytest.raises(ValueError, match="Rate"):
        LldpFloodingConfig(iface="eth9", rate=rate)


def test_dry_run_sends_nothing():
    sent = []
    stats = flood.run_lldp_flooding(LldpFloodingConfig(iface="eth9", rate=100, count=10, dry_run=True),
                                    threading.Event(), lambda _s: None, send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")
