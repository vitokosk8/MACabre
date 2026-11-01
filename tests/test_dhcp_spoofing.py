import threading

import pytest
from scapy.all import BOOTP, Ether

from macabre.attacks import dhcp_spoofing as spoof
from macabre.attacks.dhcp_spoofing import DhcpSpoofingConfig
from macabre.attacks.dhcp_starvation import build_discover, build_request
from macabre.attacks.rogue_dhcp_server import respond

LEGIT_MAC = "02:00:00:00:00:01"
LEGIT_IP = "10.99.0.1"
ATTACKER_MAC = "02:00:00:00:00:30"
CLIENT = "02:00:00:00:00:50"
OTHER = "02:00:00:00:00:60"


def config(**overrides):
    values = dict(iface="eth9", server_ip=LEGIT_IP, server_mac=LEGIT_MAC,
                  offer_ip="10.99.0.200", router="10.99.0.250")
    values.update(overrides)
    return DhcpSpoofingConfig(**values)


def test_offer_carries_the_legitimate_server_identity_and_the_chosen_gateway():
    rogue = config().to_rogue_config()
    kind, offer = respond(rogue, LEGIT_MAC, build_discover(CLIENT, 9))
    assert kind == "offer"
    assert offer[Ether].src == LEGIT_MAC
    assert offer[BOOTP].siaddr == LEGIT_IP
    options = {o[0]: o[1] for o in offer.getlayer("DHCP").options if isinstance(o, tuple)}
    assert options["server_id"] == LEGIT_IP
    assert options["router"] == "10.99.0.250"


def test_target_limits_answers_to_one_client():
    sent, sniffed = [], []
    sniffer_stub = lambda **kwargs: type("S", (), {"start": lambda self: None, "stop": lambda self: None})()
    cfg = config(target_mac=CLIENT, dry_run=False)
    # Run the handler directly: feed a DISCOVER from another client through the sniffer callback.
    captured = {}

    def factory(**kwargs):
        captured["prn"] = kwargs["prn"]
        return sniffer_stub(**kwargs)

    stop = threading.Event()
    stop.set()
    spoof.run_dhcp_spoofing(cfg, stop, lambda _s: None,
                            send=lambda frame, iface, verbose: sent.append(frame),
                            sniffer_factory=factory)
    captured["prn"](build_discover(OTHER, 1))
    assert sent == []
    captured["prn"](build_discover(CLIENT, 2))
    assert len(sent) == 1


def test_request_for_the_legitimate_server_is_acked_with_its_identity():
    rogue = config().to_rogue_config()
    kind, ack = respond(rogue, LEGIT_MAC, build_request(CLIENT, 5, "10.99.0.200", LEGIT_IP))
    assert kind == "ack"
    assert ack[Ether].src == LEGIT_MAC


def test_legitimate_server_mac_is_required():
    with pytest.raises(ValueError, match="MAC is required"):
        config(server_mac="")


def test_bad_target_mac_is_rejected():
    with pytest.raises(ValueError):
        config(target_mac="01:00:00:00:00:01")


def test_dry_run_sends_nothing_and_listens_to_nothing():
    sent, sniffers = [], []
    stats = spoof.run_dhcp_spoofing(config(dry_run=True), threading.Event(), lambda _s: None,
                                    send=lambda *a, **k: sent.append(a),
                                    sniffer_factory=lambda **k: sniffers.append(k))
    assert sent == [] and sniffers == []
    assert stats.status.startswith("Dry run")
