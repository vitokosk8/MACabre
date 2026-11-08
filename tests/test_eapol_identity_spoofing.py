import random
import threading

import pytest
from scapy.all import Ether
from scapy.layers.eap import EAP, EAPOL
from scapy.packet import Raw

from macabre.attacks.eapol_identity_spoofing import (
    MAX_IDENTITIES,
    MAX_IDENTITY_LENGTH,
    EapolIdentitySpoofingConfig,
    build_identity_response,
    is_identity_request,
    run_eapol_identity_spoofing,
)

SOURCE = "02:00:00:00:00:71"


def request_to(mac, identifier):
    return Ether(src="02:00:00:00:00:01", dst=mac, type=0x888E) / EAPOL(version=2, type=0) / EAP(
        code=1, id=identifier, type=1
    )


def test_identity_response_carries_the_claimed_identity_and_the_request_identifier():
    frame = build_identity_response(SOURCE, 42, "bob")
    assert frame[Ether].src == SOURCE
    assert frame[Ether].dst == "01:80:c2:00:00:03"
    assert frame[EAP].code == 2
    assert frame[EAP].id == 42
    assert frame[EAP].type == 1
    assert frame[Raw].load == b"bob"


def test_only_identity_requests_addressed_to_the_source_count():
    assert is_identity_request(request_to(SOURCE, 1), SOURCE)
    assert not is_identity_request(request_to("02:00:00:00:00:99", 1), SOURCE)
    response = Ether(dst=SOURCE, type=0x888E) / EAPOL(version=2, type=0) / EAP(code=2, id=1, type=1)
    assert not is_identity_request(response, SOURCE)


def test_config_rejects_missing_or_bad_identities_and_timeouts():
    with pytest.raises(ValueError):
        EapolIdentitySpoofingConfig(iface="eth0", identities=())
    with pytest.raises(ValueError):
        EapolIdentitySpoofingConfig(iface="eth0", identities=("",))
    with pytest.raises(ValueError):
        EapolIdentitySpoofingConfig(iface="eth0", identities=("x" * (MAX_IDENTITY_LENGTH + 1),))
    with pytest.raises(ValueError):
        EapolIdentitySpoofingConfig(iface="eth0", identities=tuple(f"u{i}" for i in range(MAX_IDENTITIES + 1)))
    with pytest.raises(ValueError):
        EapolIdentitySpoofingConfig(iface="eth0", identities=("bob",), response_timeout=0)
    with pytest.raises(ValueError):
        EapolIdentitySpoofingConfig(iface="eth0", source_mac="not-a-mac", identities=("bob",))


def test_each_identity_is_answered_with_the_identifier_from_its_request():
    sent = []
    identifiers = iter([7, 8])
    stats = run_eapol_identity_spoofing(
        EapolIdentitySpoofingConfig(iface="eth9", source_mac=SOURCE, identities=("bob", "carol"), response_timeout=2),
        threading.Event(),
        lambda s: None,
        wait=lambda iface, mac, timeout: next(identifiers),
        send=lambda frame, iface, verbose: sent.append(frame),
    )
    assert stats.exchanges == 2
    assert stats.requests_seen == 2
    assert stats.responses == 2
    responses = [f for f in sent if f.haslayer(EAP) and f[EAP].code == 2]
    assert [f[EAP].id for f in responses] == [7, 8]
    assert [f[Raw].load for f in responses] == [b"bob", b"carol"]


def test_no_identity_request_means_no_response_is_sent():
    sent = []
    stats = run_eapol_identity_spoofing(
        EapolIdentitySpoofingConfig(iface="eth9", source_mac=SOURCE, identities=("bob",), response_timeout=2),
        threading.Event(),
        lambda s: None,
        wait=lambda iface, mac, timeout: None,
        send=lambda frame, iface, verbose: sent.append(frame),
    )
    assert stats.requests_seen == 0
    assert stats.responses == 0
    assert all(not (f.haslayer(EAP) and f[EAP].code == 2) for f in sent)


def test_dry_run_sends_and_waits_for_nothing():
    calls = []
    stats = run_eapol_identity_spoofing(
        EapolIdentitySpoofingConfig(iface="eth9", source_mac=SOURCE, identities=("bob",), dry_run=True),
        threading.Event(),
        lambda s: None,
        wait=lambda *a: calls.append(a),
        send=lambda *a, **kw: calls.append(a),
    )
    assert calls == []
    assert "Nothing sent" in stats.status


def test_each_exchange_uses_a_new_random_mac_when_no_source_is_given():
    frames = []
    run_eapol_identity_spoofing(
        EapolIdentitySpoofingConfig(iface="eth9", identities=("bob", "carol", "dave"), response_timeout=1),
        threading.Event(),
        lambda s: None,
        rng=random.Random(5),
        wait=lambda iface, mac, timeout: 1,
        send=lambda frame, iface, verbose: frames.append(frame),
    )
    starts = [f for f in frames if f[EAPOL].type == 1]
    assert len({f[Ether].src for f in starts}) == 3
