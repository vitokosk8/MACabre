import random
import threading

import pytest
from scapy.all import BOOTP, DHCP, IP, UDP, Ether

from macabre.attacks import dhcp_starvation as dhcp
from macabre.attacks.dhcp_starvation import (
    DhcpStarvationConfig,
    Offer,
    build_discover,
    build_request,
    parse_offer,
)


def _offer_packet(xid: int, mac: str, yiaddr: str, server_id: str):
    chaddr = bytes.fromhex(mac.replace(":", "")).ljust(16, b"\x00")
    return (
        Ether(src="02:00:00:00:00:01", dst=mac)
        / IP(src=server_id, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, chaddr=chaddr, xid=xid, yiaddr=yiaddr, flags=0x8000)
        / DHCP(options=[("message-type", "offer"), ("server_id", server_id), "end"])
    )


class FakeCollector:
    """Answers every DISCOVER that was sent, as a real server would."""

    def __init__(self, sent_frames: list, server_id: str = "10.0.0.1"):
        self._sent = sent_frames
        self._server_id = server_id
        self._answered = 0

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def take(self) -> list[Offer]:
        offers = []
        for frame in self._sent[self._answered:]:
            if frame[DHCP].options[0] == ("message-type", "discover"):
                offers.append(
                    Offer(
                        xid=frame[BOOTP].xid,
                        mac=frame[Ether].src,
                        yiaddr=f"10.0.0.{100 + len(offers)}",
                        server_id=self._server_id,
                    )
                )
        self._answered = len(self._sent)
        return offers


def test_random_mac_is_unicast_locally_administered():
    rng = random.Random(1234)
    for _ in range(200):
        mac = dhcp.random_mac(rng)
        octets = [int(part, 16) for part in mac.split(":")]
        assert len(octets) == 6
        assert octets[0] & 0x01 == 0      # unicast
        assert octets[0] & 0x02 == 0x02   # locally administered


def test_build_discover_fields():
    mac = "02:11:22:33:44:55"
    frame = build_discover(mac, xid=0xDEADBEEF)

    assert frame[Ether].src == mac
    assert frame[Ether].dst == dhcp.BROADCAST_MAC
    assert frame[IP].src == "0.0.0.0"
    assert frame[IP].dst == "255.255.255.255"
    assert frame[UDP].sport == 68
    assert frame[UDP].dport == 67
    assert frame[BOOTP].xid == 0xDEADBEEF
    assert frame[BOOTP].chaddr[:6] == bytes.fromhex("021122334455")
    assert frame[BOOTP].chaddr[6:] == b"\x00" * 10
    assert frame[DHCP].options[0] == ("message-type", "discover")


def test_build_request_fields():
    mac = "02:11:22:33:44:55"
    frame = build_request(mac, xid=77, requested_ip="10.0.0.42", server_id="10.0.0.1")

    assert frame[Ether].src == mac
    assert frame[BOOTP].xid == 77
    assert frame[BOOTP].chaddr[:6] == bytes.fromhex("021122334455")
    options = dict(o for o in frame[DHCP].options if isinstance(o, tuple))
    assert options["message-type"] == "request"
    assert options["requested_addr"] == "10.0.0.42"
    assert options["server_id"] == "10.0.0.1"


def test_parse_offer_extracts_xid_mac_address_and_server():
    mac = "02:aa:bb:cc:dd:ee"
    packet = _offer_packet(xid=99, mac=mac, yiaddr="10.0.0.55", server_id="10.0.0.1")

    offer = parse_offer(packet)

    assert offer == Offer(xid=99, mac=mac, yiaddr="10.0.0.55", server_id="10.0.0.1")


def test_parse_offer_ignores_non_offer_messages():
    packet = (
        Ether()
        / IP()
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, xid=1)
        / DHCP(options=[("message-type", "ack"), ("server_id", "10.0.0.1"), "end"])
    )
    assert parse_offer(packet) is None


def test_parse_offer_accepts_numeric_message_type_as_received_on_the_wire():
    # Packets read from the network carry the RFC 2132 numeric type (2 = OFFER).
    packet = (
        Ether()
        / IP()
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, xid=7, chaddr=b"\x02\x00\x00\x00\x00\x01".ljust(16, b"\x00"), yiaddr="10.0.0.60")
        / DHCP(options=[("message-type", 2), ("server_id", "10.0.0.1"), "end"])
    )
    offer = parse_offer(packet)
    assert offer == Offer(xid=7, mac="02:00:00:00:00:01", yiaddr="10.0.0.60", server_id="10.0.0.1")


def test_parse_offer_ignores_non_dhcp_packets():
    assert parse_offer(Ether() / IP() / UDP()) is None


def test_dry_run_generates_exact_count_without_sending(monkeypatch):
    sent = []
    monkeypatch.setattr(dhcp, "sendp", lambda *a, **k: sent.append((a, k)))

    progress = []
    config = DhcpStarvationConfig(iface="lo", count=5, interval=0.0, dry_run=True)
    stats = dhcp.run_starvation(
        config, threading.Event(), progress.append, rng=random.Random(1)
    )

    assert stats.discovers == 5
    assert stats.requests == 0
    assert [p.discovers for p in progress] == [1, 2, 3, 4, 5]
    assert sent == []


def test_discover_only_mode_sends_discovers_without_collector(monkeypatch):
    sent = []
    monkeypatch.setattr(dhcp, "sendp", lambda frame, iface, verbose: sent.append(frame))

    config = DhcpStarvationConfig(iface="eth9", count=3, interval=0.0, request=False)
    stats = dhcp.run_starvation(
        config,
        threading.Event(),
        lambda _s: None,
        rng=random.Random(2),
        collector_factory=lambda _iface: pytest.fail("no collector expected"),
    )

    assert stats.discovers == 3
    assert stats.requests == 0
    assert len(sent) == 3
    assert all(f[DHCP].options[0] == ("message-type", "discover") for f in sent)


def test_full_handshake_answers_every_offer_with_request(monkeypatch):
    monkeypatch.setattr(dhcp, "GRACE_PERIOD", 0.0)
    sent = []

    def fake_send(frame, iface, verbose):
        assert iface == "eth9"
        sent.append(frame)

    config = DhcpStarvationConfig(iface="eth9", count=5, interval=0.0, request=True)
    stats = dhcp.run_starvation(
        config,
        threading.Event(),
        lambda _s: None,
        rng=random.Random(3),
        send=fake_send,
        collector_factory=lambda _iface: FakeCollector(sent),
    )

    assert stats.discovers == 5
    assert stats.offers == 5
    assert stats.requests == 5

    requests = [f for f in sent if f[DHCP].options[0] == ("message-type", "request")]
    assert len(requests) == 5
    discover_xids = {f[BOOTP].xid for f in sent if f[DHCP].options[0] == ("message-type", "discover")}
    assert {r[BOOTP].xid for r in requests} == discover_xids


def test_offers_for_other_clients_are_ignored(monkeypatch):
    monkeypatch.setattr(dhcp, "GRACE_PERIOD", 0.0)
    sent = []

    class ForeignCollector(FakeCollector):
        def take(self):
            return [Offer(xid=12345, mac="02:99:99:99:99:99", yiaddr="10.0.0.9", server_id="10.0.0.1")]

    config = DhcpStarvationConfig(iface="eth9", count=2, interval=0.0, request=True)
    stats = dhcp.run_starvation(
        config,
        threading.Event(),
        lambda _s: None,
        rng=random.Random(4),
        send=lambda frame, iface, verbose: sent.append(frame),
        collector_factory=lambda _iface: ForeignCollector(sent),
    )

    assert stats.requests == 0
    assert all(f[DHCP].options[0] == ("message-type", "discover") for f in sent)


def test_stop_event_interrupts_continuous_run():
    stop = threading.Event()
    progress = []

    def on_progress(stats):
        progress.append(stats.discovers)
        if stats.discovers == 4:
            stop.set()

    config = DhcpStarvationConfig(iface="lo", count=0, interval=0.0, dry_run=True)
    stats = dhcp.run_starvation(config, stop, on_progress, rng=random.Random(5))

    assert stats.discovers == 4
