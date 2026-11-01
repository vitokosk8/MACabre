import struct
import threading

import pytest
from scapy.all import Ether

from macabre.attacks import cdp_spoofing as cdp
from macabre.attacks.cdp_spoofing import CdpSpoofingConfig

ATTACKER = "02:00:00:00:00:30"
LINK_OUTPUT = (
    "2: eth9: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP "
    f"link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"
)


def fake_run(argv):
    return LINK_OUTPUT if argv[:4] == ["ip", "-o", "link", "show"] else ""


def tlvs_of(message: bytes):
    """Split the TLVs of a CDP message (after the 4-byte header) into (type, value) pairs."""
    out, pos = [], 4
    while pos < len(message):
        kind, length = struct.unpack("!HH", message[pos:pos + 4])
        out.append((kind, message[pos + 4:pos + length]))
        pos += length
    return out


def checksum_ok(message: bytes) -> bool:
    return cdp._checksum(message) == 0


def test_frame_goes_to_cdp_multicast_with_snap_header_and_length():
    frame = cdp.build_cdp_frame(ATTACKER, CdpSpoofingConfig(iface="eth9"))
    assert frame[Ether].dst == "01:00:0c:cc:cc:cc"
    assert frame[Ether].src == ATTACKER
    payload = bytes(frame.load)
    assert payload[:8] == bytes.fromhex("aaaa03" "00000c" "2000")
    assert frame[Ether].type == len(payload)


def test_header_has_version_ttl_and_a_valid_checksum():
    message = cdp.cdp_message("SW1", "Gi0/1", "cisco", "soft", ttl=99)
    assert message[0] == 2 and message[1] == 99
    assert checksum_ok(message)


def test_checksum_detects_a_changed_byte():
    message = bytearray(cdp.cdp_message("SW1", "Gi0/1", "cisco", "soft"))
    message[-1] ^= 0x01
    assert not checksum_ok(bytes(message))


def test_tlvs_carry_device_port_platform_software_and_capabilities():
    message = cdp.cdp_message("SW1", "Gi0/1", "cisco WS", "soft", capabilities=0x0A)
    values = dict(tlvs_of(message))
    assert values[cdp.TLV_DEVICE_ID] == b"SW1"
    assert values[cdp.TLV_PORT_ID] == b"Gi0/1"
    assert values[cdp.TLV_PLATFORM] == b"cisco WS"
    assert values[cdp.TLV_SOFTWARE] == b"soft"
    assert struct.unpack("!I", values[cdp.TLV_CAPABILITIES])[0] == 0x0A


def test_address_tlv_is_optional_and_encodes_ipv4():
    without = dict(tlvs_of(cdp.cdp_message("SW1", "Gi0/1", "p", "s")))
    assert cdp.TLV_ADDRESSES not in without
    with_addr = dict(tlvs_of(cdp.cdp_message("SW1", "Gi0/1", "p", "s", address="10.0.0.9")))
    data = with_addr[cdp.TLV_ADDRESSES]
    assert struct.unpack("!I", data[:4])[0] == 1
    assert data[4:] == bytes([0x01, 0x01, 0xCC]) + struct.pack("!H", 4) + bytes([10, 0, 0, 9])


def test_native_vlan_tlv_only_when_set():
    assert cdp.TLV_NATIVE_VLAN not in dict(tlvs_of(cdp.cdp_message("SW1", "Gi0/1", "p", "s")))
    values = dict(tlvs_of(cdp.cdp_message("SW1", "Gi0/1", "p", "s", native_vlan=20)))
    assert struct.unpack("!H", values[cdp.TLV_NATIVE_VLAN])[0] == 20


@pytest.mark.parametrize("kwargs", [
    {"device_id": " "},
    {"port_id": ""},
    {"address": "not-an-ip"},
    {"native_vlan": 4095},
    {"ttl": 256},
    {"count": -1},
    {"interval": -1.0},
])
def test_invalid_settings_are_rejected(kwargs):
    with pytest.raises(ValueError):
        CdpSpoofingConfig(iface="eth9", **kwargs)


def test_run_sends_the_requested_number_of_advertisements():
    sent = []
    config = CdpSpoofingConfig(iface="eth9", count=3, interval=0)
    stats = cdp.run_cdp_spoofing(config, threading.Event(), lambda _s: None, run=fake_run,
                                 send=lambda frame, iface, verbose: sent.append((iface, frame)))
    assert stats.frames == 3 and len(sent) == 3
    assert all(iface == "eth9" for iface, _ in sent)
    assert stats.sender_mac == ATTACKER


def test_dry_run_sends_nothing_and_reads_nothing():
    calls, sent = [], []
    stats = cdp.run_cdp_spoofing(CdpSpoofingConfig(iface="eth9", dry_run=True), threading.Event(),
                                 lambda _s: None, run=lambda argv: calls.append(argv) or "",
                                 send=lambda *a, **k: sent.append(a))
    assert calls == [] and sent == []
    assert stats.status.startswith("Dry run")
