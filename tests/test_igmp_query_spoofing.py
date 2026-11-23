import threading

import pytest
from scapy.all import IGMP, IP, Ether

from macabre.attacks.igmp_query_spoofing import (
    GENERAL_GROUP,
    IgmpQuerySpoofingConfig,
    build_query,
    run_igmp_query_spoofing,
)

MAC = "02:00:00:00:00:84"
SOURCE_IP = "10.0.0.1"
GROUP = "239.1.2.3"


def _config(**overrides):
    values = dict(iface="eth9", source_mac=MAC, source_ip=SOURCE_IP, queries=3, interval=0.5)
    values.update(overrides)
    return IgmpQuerySpoofingConfig(**values)


def test_general_query_goes_to_all_hosts_with_type_0x11():
    frame = build_query(MAC, SOURCE_IP, GENERAL_GROUP, 100)
    assert frame[Ether].src == MAC
    assert frame[Ether].dst == "01:00:5e:00:00:01"
    assert frame[IP].src == SOURCE_IP
    assert frame[IP].dst == "224.0.0.1"
    assert frame[IP].proto == 2 and frame[IP].ttl == 1
    assert frame[IGMP].type == 0x11
    assert frame[IGMP].gaddr == GENERAL_GROUP


def test_group_query_is_sent_to_the_group():
    frame = build_query(MAC, SOURCE_IP, GROUP, 50)
    assert frame[IP].dst == GROUP
    assert frame[Ether].dst == "01:00:5e:01:02:03"
    assert frame[IGMP].gaddr == GROUP
    assert frame[IGMP].mrcode == 50


def test_router_alert_option_is_set():
    frame = build_query(MAC, SOURCE_IP)
    # Router Alert option: type 0x94, length 4, value 0.
    assert b"\x94\x04\x00\x00" in bytes(frame[IP])


def test_run_sends_the_configured_number_of_queries():
    sent = []
    stats = run_igmp_query_spoofing(
        _config(queries=2), threading.Event(), lambda _s: None,
        send=lambda frame, iface, verbose: sent.append((iface, frame)),
    )
    assert stats.queries == 2 and len(sent) == 2
    assert {iface for iface, _ in sent} == {"eth9"}


def test_dry_run_sends_nothing():
    sent = []
    stats = run_igmp_query_spoofing(
        _config(dry_run=True), threading.Event(), lambda _s: None,
        send=lambda *args, **kwargs: sent.append(args),
    )
    assert sent == [] and stats.queries == 0
    assert "Dry run" in stats.status and "Nothing sent" in stats.status


def test_stop_event_ends_the_run_early():
    stop = threading.Event()
    sent = []

    def send(frame, iface, verbose):
        sent.append(frame)
        stop.set()

    stats = run_igmp_query_spoofing(_config(queries=5), stop, lambda _s: None, send=send)
    assert stats.queries == 1 and len(sent) == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"source_ip": "224.0.0.9"},
        {"source_ip": "0.0.0.0"},
        {"source_ip": "not-an-ip"},
        {"group": "10.0.0.5"},
        {"group": "224.0.0.5"},
        {"max_response": 256},
        {"queries": 0},
        {"queries": 101},
        {"interval": 0.1},
        {"source_mac": "not-a-mac"},
    ],
)
def test_invalid_configuration_is_rejected(overrides):
    with pytest.raises(ValueError):
        _config(**overrides)
