import threading

import pytest
from scapy.all import BOOTP, DHCP, IP, UDP, Ether

from macabre.attacks import dhcp_nak_injection as nak
from macabre.attacks.dhcp_nak_injection import NakInjectionConfig

SERVER = "10.0.0.1"
SERVER_MAC = "02:00:00:00:00:01"
CLIENT = "02:00:00:00:00:50"
OTHER = "02:00:00:00:00:51"
ATTACKER = "02:00:00:00:00:30"


def request(options, client=CLIENT, dst=SERVER, xid=4321, src_ip="10.0.0.50"):
    chaddr = bytes.fromhex(client.replace(":", "")).ljust(16, b"\x00")
    return (
        Ether(src=client, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=src_ip, dst=dst)
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=chaddr, xid=xid, ciaddr=src_ip)
        / DHCP(options=[("message-type", "request"), *options, "end"])
    )


def renewal(**kwargs):
    return request([], **kwargs)


def selection(server=SERVER, **kwargs):
    return request([("server_id", server), ("requested_addr", "10.0.0.50")], **kwargs)


def config(**kwargs):
    return NakInjectionConfig(iface="eth9", server_ip=SERVER, server_mac=SERVER_MAC, **kwargs)


def options_of(packet):
    return {o[0]: o[1] for o in packet[DHCP].options if isinstance(o, tuple)}


def test_nak_comes_from_the_server_address_and_mac_with_the_request_xid():
    nak_frame = nak.build_nak(config(), SERVER_MAC, renewal(xid=777))
    assert nak_frame[Ether].src == SERVER_MAC
    assert nak_frame[IP].src == SERVER
    assert nak_frame[BOOTP].xid == 777
    assert nak_frame[BOOTP].op == 2
    assert nak_frame[BOOTP].chaddr[:6].hex(":") == CLIENT
    assert (nak_frame[UDP].sport, nak_frame[UDP].dport) == (67, 68)


def test_nak_is_typed_nak_and_names_the_server_identifier_and_no_lease():
    options = options_of(nak.build_nak(config(), SERVER_MAC, renewal()))
    assert options["message-type"] == "nak"
    assert options["server_id"] == SERVER
    assert "lease_time" not in options and "subnet_mask" not in options


def test_renewal_unicast_to_the_server_is_answered():
    assert nak.respond(config(), SERVER_MAC, renewal()) is not None


def test_selection_of_this_server_is_answered():
    assert nak.respond(config(), SERVER_MAC, selection()) is not None


def test_selection_of_another_server_is_ignored():
    assert nak.respond(config(), SERVER_MAC, selection(server="10.0.0.9")) is None


def test_reboot_request_broadcast_without_server_id_is_answered():
    reboot = request([], dst="255.255.255.255")
    assert nak.respond(config(), SERVER_MAC, reboot) is not None


def test_request_to_another_address_without_server_id_is_ignored():
    assert nak.respond(config(), SERVER_MAC, request([], dst="10.0.0.9")) is None


@pytest.mark.parametrize("kind", ["discover", "offer", "ack", "nak"])
def test_only_requests_are_answered(kind):
    packet = request([])
    packet[DHCP].options[0] = ("message-type", kind)
    assert nak.respond(config(), SERVER_MAC, packet) is None


def test_server_replies_and_own_frames_are_ignored():
    reply = nak.build_nak(config(), SERVER_MAC, renewal())
    assert nak.respond(config(), SERVER_MAC, reply) is None
    own = renewal()
    own[Ether].src = SERVER_MAC
    assert nak.respond(config(), SERVER_MAC, own) is None


def test_target_mac_limits_the_refused_clients():
    assert nak.respond(config(target_mac=CLIENT), SERVER_MAC, renewal(client=CLIENT)) is not None
    assert nak.respond(config(target_mac=CLIENT), SERVER_MAC, renewal(client=OTHER)) is None


def test_server_mac_and_address_are_required_and_validated():
    with pytest.raises(ValueError, match="MAC is required"):
        NakInjectionConfig(iface="eth9", server_ip=SERVER, server_mac="")
    with pytest.raises(ValueError, match="IPv4"):
        NakInjectionConfig(iface="eth9", server_ip="not-an-ip", server_mac=SERVER_MAC)
    with pytest.raises(ValueError):
        NakInjectionConfig(iface="eth9", server_ip=SERVER, server_mac="01:00:0c:cc:cc:cc")


class FakeSniffer:
    handler = None

    def __init__(self, **kwargs):
        FakeSniffer.handler = kwargs["prn"]

    def start(self):
        pass

    def stop(self):
        pass


def test_sniffed_requests_are_answered_and_counted():
    sent = []
    stats_seen = []
    stop = threading.Event()
    stop.set()
    nak.run_nak_injection(config(), stop, stats_seen.append,
                          send=lambda frame, iface, verbose: sent.append((iface, frame)),
                          sniffer_factory=FakeSniffer)
    handler = FakeSniffer.handler
    handler(renewal())
    handler(selection(server="10.0.0.9"))
    handler(Ether(src=CLIENT, dst="ff:ff:ff:ff:ff:ff"))  # no IP or DHCP layers
    assert len(sent) == 1 and sent[0][0] == "eth9"
    assert sent[0][1][BOOTP].op == 2


def test_dry_run_sends_nothing_and_creates_no_sniffer():
    sent = []
    created = []

    class Recording(FakeSniffer):
        def __init__(self, **kwargs):
            created.append(kwargs)

    stats = nak.run_nak_injection(config(dry_run=True), threading.Event(), lambda _s: None,
                                  send=lambda *a, **k: sent.append(a), sniffer_factory=Recording)
    assert sent == [] and created == []
    assert stats.status.startswith("Dry run")
