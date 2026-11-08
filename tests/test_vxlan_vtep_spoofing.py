import threading

import pytest
from scapy.layers.vxlan import VXLAN

from macabre.attacks import vxlan_vtep_spoofing as vx
from macabre.attacks.vxlan_vtep_spoofing import VxlanVtepSpoofingConfig

ATTACKER = "02:00:00:00:10:03"
TARGET_MAC = "02:00:00:00:10:02"
CLAIM = "02:00:00:00:00:50"


def config(**overrides):
    values = dict(iface="eth9", source_mac=ATTACKER, outer_src_ip="10.0.0.3", outer_dst_ip="10.0.0.2",
                  outer_dst_mac=TARGET_MAC, vni=42, inner_src_mac=CLAIM, frames=2)
    values.update(overrides)
    return VxlanVtepSpoofingConfig(**values)


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_frame_carries_vni_and_outer_addresses():
    frame = vx.build_frame(config())
    assert frame.getlayer(VXLAN).vni == 42
    assert frame.getlayer("IP").src == "10.0.0.3"
    assert frame.getlayer("IP").dst == "10.0.0.2"
    assert frame.dst == TARGET_MAC and frame.src == ATTACKER


def test_inner_frame_claims_the_given_source_mac():
    inner = vx.build_frame(config()).getlayer(VXLAN).payload
    assert inner.src == CLAIM
    assert inner.dst == "ff:ff:ff:ff:ff:ff"


def test_run_sends_the_configured_number_of_frames():
    sent = []
    stats = vx.run_vxlan_vtep_spoofing(config(frames=4), threading.Event(), lambda _s: None, send=capture(sent))
    assert stats.frames == 4 and len(sent) == 4
    assert all(iface == "eth9" for iface, _ in sent)


def test_dry_run_sends_nothing():
    sent = []
    stats = vx.run_vxlan_vtep_spoofing(config(dry_run=True), threading.Event(), lambda _s: None, send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")


def test_stop_event_ends_the_run_early():
    sent = []
    stop = threading.Event()
    stop.set()
    stats = vx.run_vxlan_vtep_spoofing(config(), stop, lambda _s: None, send=capture(sent))
    assert sent == [] and stats.frames == 0


@pytest.mark.parametrize("vni", [0, 0x1000000])
def test_vni_out_of_range_is_refused(vni):
    with pytest.raises(ValueError, match="VNI"):
        config(vni=vni)


@pytest.mark.parametrize("field", ["outer_src_ip", "outer_dst_ip"])
def test_invalid_outer_address_is_refused(field):
    with pytest.raises(ValueError, match="IPv4"):
        config(**{field: "not-an-ip"})


@pytest.mark.parametrize("frames", [0, 101])
def test_frame_count_out_of_range_is_refused(frames):
    with pytest.raises(ValueError, match="Frames"):
        config(frames=frames)


def test_inner_mac_is_required():
    with pytest.raises(ValueError):
        config(inner_src_mac="")
