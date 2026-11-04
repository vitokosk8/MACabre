import random
import threading

import pytest
from scapy.all import BOOTP, DHCP, Ether

from macabre.attacks.dhcp_relay_option82 import (
    MAX_DISCOVERS,
    OPTION_RELAY_AGENT,
    RelayOption82Config,
    build_discover,
    option82_value,
    run_relay_option82,
)

CLIENT = "02:00:00:00:00:50"


def config(**overrides):
    values = dict(iface="eth0", circuit_id="pool-a")
    values.update(overrides)
    return RelayOption82Config(**values)


def test_option82_carries_circuit_then_remote_sub_options():
    assert option82_value("pool-a", "sw1") == b"\x01\x06pool-a" + b"\x02\x03sw1"
    assert option82_value("pool-a", "") == b"\x01\x06pool-a"


def test_discover_carries_the_forged_option82_and_the_client_mac():
    frame = build_discover(CLIENT, xid=77, circuit_id="pool-a", remote_id="")
    assert frame[Ether].src == CLIENT
    assert frame[BOOTP].xid == 77
    values = {o[0]: o[1] for o in frame[DHCP].options if isinstance(o, tuple)}
    assert values[OPTION_RELAY_AGENT] == b"\x01\x06pool-a"
    assert values["message-type"] == "discover"


@pytest.mark.parametrize("overrides", [
    dict(circuit_id="", remote_id=""),
    dict(circuit_id="x" * 256),
    dict(client_mac="not-a-mac"),
    dict(discovers=0),
    dict(discovers=MAX_DISCOVERS + 1),
])
def test_bad_inputs_are_refused(overrides):
    with pytest.raises(ValueError):
        config(**overrides)


def test_run_sends_each_discover_once_with_a_fresh_xid():
    sent = []
    stats = run_relay_option82(
        config(discovers=3), threading.Event(), lambda s: None,
        rng=random.Random(4), send=lambda frame, **kw: sent.append(frame),
    )
    assert stats.discovers == 3
    assert len({f[BOOTP].xid for f in sent}) == 3


def test_fixed_client_mac_is_used_for_every_discover():
    sent = []
    run_relay_option82(
        config(discovers=2, client_mac=CLIENT), threading.Event(), lambda s: None,
        rng=random.Random(4), send=lambda frame, **kw: sent.append(frame),
    )
    assert {f[Ether].src for f in sent} == {CLIENT}


def test_dry_run_sends_nothing():
    sent = []
    stats = run_relay_option82(
        config(dry_run=True), threading.Event(), lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert "Nothing sent" in stats.status
