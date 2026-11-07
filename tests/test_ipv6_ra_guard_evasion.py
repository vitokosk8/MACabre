import threading

import pytest
from scapy.layers.inet6 import ICMPv6ND_RA, IPv6, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment

from macabre.attacks import ipv6_ra_guard_evasion as ev
from macabre.attacks.ipv6_ra_guard_evasion import RaGuardEvasionConfig, build_advertisements

ATTACKER = "02:00:00:00:10:03"


def config(**overrides):
    values = dict(iface="eth9", source_mac=ATTACKER)
    values.update(overrides)
    return RaGuardEvasionConfig(**values)


def test_plain_is_a_single_router_advertisement():
    frames = build_advertisements(config(variant="plain"))
    assert len(frames) == 1
    assert frames[0].getlayer(ICMPv6ND_RA) is not None
    assert frames[0].getlayer(IPv6).nh == 58


def test_destination_options_puts_the_advertisement_behind_an_extension_header():
    frame = build_advertisements(config(variant="destination_options"))[0]
    ip = frame.getlayer(IPv6)
    assert ip.nh == 60
    assert frame.getlayer(IPv6ExtHdrDestOpt) is not None
    assert frame.getlayer(ICMPv6ND_RA) is not None


def test_fragmented_sends_two_fragments_of_one_message():
    frames = build_advertisements(config(variant="fragmented"))
    assert len(frames) == 2
    first, second = (f.getlayer(IPv6ExtHdrFragment) for f in frames)
    assert first.offset == 0 and first.m == 1
    assert second.offset == 1 and second.m == 0
    assert first.id == second.id == 0x4D41
    assert frames[0].getlayer(IPv6).nh == 44


def test_fragments_reassemble_to_the_plain_advertisement():
    plain = build_advertisements(config(variant="plain"))[0]
    plain_icmp = bytes(plain.getlayer(IPv6).payload)
    frags = build_advertisements(config(variant="fragmented"))
    rebuilt = b"".join(bytes(f.getlayer(IPv6ExtHdrFragment).payload) for f in frags)
    assert rebuilt == plain_icmp


def test_first_fragment_holds_only_the_first_eight_octets():
    first = build_advertisements(config(variant="fragmented"))[0]
    assert len(bytes(first.getlayer(IPv6ExtHdrFragment).payload)) == 8


def test_the_fragments_are_sent_to_the_all_nodes_group():
    for frame in build_advertisements(config(variant="fragmented")):
        assert frame.getlayer(IPv6).dst == "ff02::1"
        assert frame.getlayer(IPv6).hlim == 255


@pytest.mark.parametrize("variant", ["bogus", ""])
def test_unknown_variant_is_refused(variant):
    with pytest.raises(ValueError, match="Variant"):
        config(variant=variant)


def test_lifetime_and_frames_are_bounded():
    with pytest.raises(ValueError, match="Router lifetime"):
        config(router_lifetime=0)
    with pytest.raises(ValueError, match="Frames"):
        config(frames=0)


def test_dry_run_sends_nothing():
    sent = []
    stats = ev.run_ra_guard_evasion(
        config(dry_run=True, variant="fragmented"), threading.Event(), lambda _s: None,
        send=lambda frame, **_kw: sent.append(frame),
    )
    assert sent == []
    assert "fragmented" in stats.status


def test_each_frame_is_sent_once_per_round():
    sent = []
    stats = ev.run_ra_guard_evasion(
        config(variant="fragmented", frames=3), threading.Event(), lambda _s: None,
        send=lambda frame, iface, verbose: sent.append(frame),
    )
    assert stats.frames == 6 and len(sent) == 6
