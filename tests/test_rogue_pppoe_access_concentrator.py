import random
import threading

import pytest
from scapy.all import Ether
from scapy.layers.ppp import PPPoED, PPPoED_Tags, PPPoETag

from macabre.attacks.rogue_pppoe_access_concentrator import (
    CODE_PADO,
    CODE_PADS,
    TAG_AC_COOKIE,
    TAG_AC_NAME,
    TAG_SERVICE_NAME,
    RoguePppoeAcConfig,
    _Session,
    _tags,
    build_pado,
    run_rogue_pppoe_ac,
    respond,
)

AC_MAC = "02:00:00:00:00:44"
CLIENT = "02:00:00:00:00:31"
CONFIG = RoguePppoeAcConfig(iface="eth9", ac_mac=AC_MAC, ac_name="MACabre-AC")


def padi(src=CLIENT, service=b""):
    return (
        Ether(src=src, dst="ff:ff:ff:ff:ff:ff", type=0x8863)
        / PPPoED(code=0x09, sessionid=0)
        / PPPoED_Tags(tag_list=[PPPoETag(tag_type=TAG_SERVICE_NAME, tag_value=service)])
    )


def padr_with(cookie_value, src=CLIENT):
    tags = [PPPoETag(tag_type=TAG_AC_COOKIE, tag_value=cookie_value)] if cookie_value is not None else []
    return Ether(src=src, dst=AC_MAC, type=0x8863) / PPPoED(code=0x19, sessionid=0) / PPPoED_Tags(tag_list=tags)


def test_pado_is_unicast_to_the_client_and_carries_the_ac_name_and_cookie():
    frame = build_pado(CONFIG, CLIENT, padi(), b"\x01" * 16)
    assert frame[Ether].src == AC_MAC
    assert frame[Ether].dst == CLIENT
    assert frame[Ether].type == 0x8863
    assert frame[PPPoED].code == CODE_PADO
    assert frame[PPPoED].sessionid == 0
    assert _tags(frame, TAG_AC_NAME) == [b"MACabre-AC"]
    assert _tags(frame, TAG_AC_COOKIE) == [b"\x01" * 16]


def test_pado_echoes_the_clients_service_name():
    frame = build_pado(CONFIG, CLIENT, padi(service=b"internet"), b"\x02" * 16)
    assert _tags(frame, TAG_SERVICE_NAME) == [b"internet"]


def test_padi_is_answered_with_a_pado_and_a_cookie_is_remembered():
    session = _Session()
    kind, reply = respond(CONFIG, session, padi(), random.Random(1))
    assert kind == "pado"
    assert reply[PPPoED].code == CODE_PADO
    assert session.cookies[CLIENT] == _tags(reply, TAG_AC_COOKIE)[0]


def test_padr_with_the_issued_cookie_gets_a_pads_with_a_session_id():
    session = _Session()
    _, pado = respond(CONFIG, session, padi(), random.Random(2))
    cookie = _tags(pado, TAG_AC_COOKIE)[0]
    kind, reply = respond(CONFIG, session, padr_with(cookie), random.Random(3))
    assert kind == "pads"
    assert reply[PPPoED].code == CODE_PADS
    assert reply[PPPoED].sessionid == 1
    assert reply[Ether].dst == CLIENT


def test_padr_with_a_wrong_or_missing_cookie_is_not_answered():
    session = _Session()
    respond(CONFIG, session, padi(), random.Random(4))
    assert respond(CONFIG, session, padr_with(b"\x00" * 16), random.Random(5)) is None
    assert respond(CONFIG, session, padr_with(None), random.Random(6)) is None


def test_padr_without_a_prior_padi_is_not_answered():
    assert respond(CONFIG, _Session(), padr_with(b"\x01" * 16), random.Random(7)) is None


def test_cookie_is_single_use():
    session = _Session()
    _, pado = respond(CONFIG, session, padi(), random.Random(8))
    cookie = _tags(pado, TAG_AC_COOKIE)[0]
    assert respond(CONFIG, session, padr_with(cookie), random.Random(9))[0] == "pads"
    assert respond(CONFIG, session, padr_with(cookie), random.Random(10)) is None


def test_session_ids_increase_per_client():
    session = _Session()
    ids = []
    for mac in ("02:00:00:00:00:31", "02:00:00:00:00:32"):
        _, pado = respond(CONFIG, session, padi(src=mac), random.Random(11))
        cookie = _tags(pado, TAG_AC_COOKIE)[0]
        _, pads = respond(CONFIG, session, padr_with(cookie, src=mac), random.Random(12))
        ids.append(pads[PPPoED].sessionid)
    assert ids == [1, 2]


def test_config_rejects_bad_mac_and_names():
    with pytest.raises(ValueError):
        RoguePppoeAcConfig(iface="eth9", ac_mac="not-a-mac")
    with pytest.raises(ValueError):
        RoguePppoeAcConfig(iface="eth9", ac_mac=AC_MAC, ac_name="")
    with pytest.raises(ValueError):
        RoguePppoeAcConfig(iface="eth9", ac_mac=AC_MAC, ac_name="x" * 65)


def test_dry_run_sends_nothing():
    from macabre.attacks.rogue_pppoe_access_concentrator import run_rogue_pppoe_ac as run

    sent = []
    stats = run(
        RoguePppoeAcConfig(iface="eth9", ac_mac=AC_MAC, dry_run=True),
        threading.Event(),
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert "Nothing sent" in stats.status


def test_padi_without_tags_is_still_answered():
    bare = Ether(src=CLIENT, dst="ff:ff:ff:ff:ff:ff", type=0x8863) / PPPoED(code=0x09, sessionid=0)
    kind, reply = respond(CONFIG, _Session(), bare, random.Random(13))
    assert kind == "pado"
    assert _tags(reply, TAG_AC_NAME) == [b"MACabre-AC"]
