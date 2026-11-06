import threading

import pytest
from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, IPv6

from macabre.attacks import rogue_router_advertisement as rra
from macabre.attacks.rogue_router_advertisement import RogueRouterAdvertisementConfig

ROUTER = "02:00:00:00:10:03"


def config(**overrides):
    values = dict(iface="eth9", source_mac=ROUTER, prefix="2001:db8:bad::/64", frames=2)
    values.update(overrides)
    return RogueRouterAdvertisementConfig(**values)


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_link_local_is_derived_from_the_mac():
    assert rra.link_local_from_mac(ROUTER) == "fe80::ff:fe00:1003"


def test_advertisement_has_hop_limit_255_and_all_nodes_destination():
    frame = rra.build_advertisement(config())
    ip = frame.getlayer(IPv6)
    assert ip.hlim == 255
    assert ip.dst == "ff02::1"
    assert ip.src == "fe80::ff:fe00:1003"


def test_advertisement_carries_router_lifetime_and_slaac_prefix():
    frame = rra.build_advertisement(config(router_lifetime=600))
    ra = frame.getlayer(ICMPv6ND_RA)
    assert ra.routerlifetime == 600
    prefix = frame.getlayer(ICMPv6NDOptPrefixInfo)
    assert prefix.prefix == "2001:db8:bad::"
    assert prefix.prefixlen == 64
    assert prefix.A == 1 and prefix.L == 1


def test_source_link_layer_option_is_the_router_mac():
    frame = rra.build_advertisement(config())
    assert frame.getlayer(ICMPv6NDOptSrcLLAddr).lladdr == ROUTER


def test_run_sends_the_configured_number_of_advertisements():
    sent = []
    stats = rra.run_rogue_router_advertisement(config(frames=3), threading.Event(), lambda _s: None,
                                               send=capture(sent))
    assert stats.frames == 3 and len(sent) == 3


def test_dry_run_sends_nothing():
    sent = []
    stats = rra.run_rogue_router_advertisement(config(dry_run=True), threading.Event(), lambda _s: None,
                                               send=capture(sent))
    assert sent == [] and stats.status.startswith("Dry run")


def test_prefix_must_be_a_slaac_64():
    with pytest.raises(ValueError, match="/64"):
        config(prefix="2001:db8::/48")


def test_prefix_must_be_ipv6():
    with pytest.raises(ValueError, match="IPv6"):
        config(prefix="10.0.0.0/24")


@pytest.mark.parametrize("lifetime", [0, 65536])
def test_router_lifetime_out_of_range_is_refused(lifetime):
    with pytest.raises(ValueError, match="Router lifetime"):
        config(router_lifetime=lifetime)
