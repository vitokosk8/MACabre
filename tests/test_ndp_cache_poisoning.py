import threading

import pytest
from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr

from macabre.attacks import ndp_cache_poisoning as ndp
from macabre.attacks.ndp_cache_poisoning import NdpCachePoisoningConfig

ATTACKER = "02:00:00:00:10:03"
TARGET = "2001:db8:c0::2"


def config(**overrides):
    values = dict(iface="eth9", source_mac=ATTACKER, target=TARGET, frames=2)
    values.update(overrides)
    return NdpCachePoisoningConfig(**values)


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_advertisement_binds_the_target_and_sets_override():
    na = ndp.build_advertisement(config()).getlayer(ICMPv6ND_NA)
    assert str(na.tgt) == TARGET
    assert na.O == 1 and na.S == 0 and na.R == 0


def test_target_link_layer_option_is_the_operator_mac():
    option = ndp.build_advertisement(config()).getlayer(ICMPv6NDOptDstLLAddr)
    assert option.lladdr == ATTACKER


def test_advertisement_uses_hop_limit_255_all_nodes_and_link_local_source():
    frame = ndp.build_advertisement(config())
    ip = frame.getlayer("IPv6")
    assert ip.hlim == 255
    assert ip.dst == "ff02::1"
    assert ip.src == "fe80::ff:fe00:1003"
    assert frame.dst == "33:33:00:00:00:01" and frame.src == ATTACKER


def test_run_sends_the_configured_number_of_advertisements():
    sent = []
    stats = ndp.run_ndp_cache_poisoning(config(frames=4), threading.Event(), lambda _s: None, send=capture(sent))
    assert stats.frames == 4 and len(sent) == 4
    assert all(iface == "eth9" for iface, _ in sent)


def test_dry_run_sends_nothing():
    sent = []
    stats = ndp.run_ndp_cache_poisoning(config(dry_run=True), threading.Event(), lambda _s: None, send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")


def test_stop_event_ends_the_run_early():
    sent = []
    stop = threading.Event()
    stop.set()
    stats = ndp.run_ndp_cache_poisoning(config(), stop, lambda _s: None, send=capture(sent))
    assert sent == [] and stats.frames == 0


@pytest.mark.parametrize("target", ["not-an-address", "10.0.0.1", "ff02::1", "::"])
def test_target_must_be_a_unicast_ipv6_address(target):
    with pytest.raises(ValueError):
        config(target=target)


def test_target_is_required():
    with pytest.raises(ValueError, match="Target"):
        config(target="")


@pytest.mark.parametrize("frames", [0, 101])
def test_frame_count_out_of_range_is_refused(frames):
    with pytest.raises(ValueError, match="Frames"):
        config(frames=frames)


def test_source_mac_is_required():
    with pytest.raises(ValueError):
        config(source_mac="")
