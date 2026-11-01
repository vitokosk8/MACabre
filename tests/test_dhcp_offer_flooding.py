import random
import threading

import pytest
from scapy.all import BOOTP, DHCP

from macabre.attacks import dhcp_offer_flooding as flood
from macabre.attacks.dhcp_offer_flooding import OfferFloodConfig
from macabre.attacks.dhcp_starvation import build_discover

ATTACKER = "02:00:00:00:00:30"
CLIENT = "02:00:00:00:00:50"
LINK_OUTPUT = (
    "2: eth9: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP "
    f"link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"
)


def fake_run(argv):
    return LINK_OUTPUT if argv[:4] == ["ip", "-o", "link", "show"] else ""


class FakeSniffer:
    """Stands in for the live sniffer: records the callback and never listens."""
    handler = None

    def __init__(self, **kwargs):
        FakeSniffer.handler = kwargs["prn"]

    def start(self):
        pass

    def stop(self):
        pass


def run_with_stop_set(config, rng, sent):
    """Run the attack with its stop event already set, so it returns after setting up the sniffer."""
    stop = threading.Event()
    stop.set()
    flood.run_offer_flooding(config, stop, lambda _s: None, rng=rng, run=fake_run,
                             send=lambda burst, iface, verbose: sent.append(burst),
                             sniffer_factory=FakeSniffer)
    return FakeSniffer.handler


def test_offers_answer_the_discover_xid_and_client_mac():
    offer = flood.build_offer(random.Random(1), "192.168.0.0/24", build_discover(CLIENT, 4321))
    assert offer[BOOTP].xid == 4321
    assert offer[BOOTP].chaddr[:6].hex(":") == CLIENT
    options = {o[0]: o[1] for o in offer[DHCP].options if isinstance(o, tuple)}
    assert options["message-type"] == "offer"


def test_each_offer_comes_from_a_different_invented_server():
    rng = random.Random(2)
    discover = build_discover(CLIENT, 1)
    offers = [flood.build_offer(rng, "192.168.0.0/24", discover) for _ in range(20)]
    assert len({o[BOOTP].siaddr for o in offers}) > 15
    assert len({o.src for o in offers}) == 20


def test_a_discover_triggers_a_burst_of_the_configured_size():
    sent = []
    handler = run_with_stop_set(OfferFloodConfig(iface="eth9", offers_per_discover=4),
                                random.Random(4), sent)
    handler(build_discover(CLIENT, 77))
    assert len(sent) == 1 and len(sent[0]) == 4


def test_own_discovers_are_ignored():
    sent = []
    handler = run_with_stop_set(OfferFloodConfig(iface="eth9", offers_per_discover=2),
                                random.Random(5), sent)
    handler(build_discover(ATTACKER, 1))
    assert sent == []


@pytest.mark.parametrize("network", ["not-a-network", "192.168.0.0/30"])
def test_bad_networks_are_rejected(network):
    with pytest.raises(ValueError):
        OfferFloodConfig(iface="eth9", network=network)


@pytest.mark.parametrize("count", [0, 51])
def test_offers_per_discover_must_be_within_limits(count):
    with pytest.raises(ValueError, match="between 1 and 50"):
        OfferFloodConfig(iface="eth9", offers_per_discover=count)


def test_dry_run_sends_nothing_and_listens_to_nothing():
    calls, sent, sniffers = [], [], []
    stats = flood.run_offer_flooding(
        OfferFloodConfig(iface="eth9", dry_run=True), threading.Event(), lambda _s: None,
        run=lambda argv: calls.append(argv) or "", send=lambda *a, **k: sent.append(a),
        sniffer_factory=lambda **k: sniffers.append(k),
    )
    assert calls == [] and sent == [] and sniffers == []
    assert stats.status.startswith("Dry run")
