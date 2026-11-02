"""MNDP field layout, checked against the layout of a RouterOS 7.26beta3 announcement.

The sample is built from the same types, lengths and byte order as a captured
announcement. Router names, MAC addresses and addresses are placeholders.
"""

import struct

from macabre.attacks import mndp_spoofing as mndp

SAMPLE_MAC = "02:00:00:00:00:10"


def routeros_style_announcement() -> bytes:
    def tlv(kind, value):
        return struct.pack(">HH", kind, len(value)) + value

    return (
        bytes.fromhex("00005100")
        + tlv(mndp.TLV_MAC, bytes.fromhex(SAMPLE_MAC.replace(":", "")))
        + tlv(mndp.TLV_IDENTITY, b"sample.r1.example.net")
        + tlv(mndp.TLV_VERSION, b"7.26beta3 2026-10-16 11:44:30")
        + tlv(mndp.TLV_PLATFORM, b"MikroTik")
        + tlv(mndp.TLV_UPTIME, struct.pack("<I", 628783))
        + tlv(mndp.TLV_SOFTWARE_ID, b"8DL8-ABMU")
        + tlv(mndp.TLV_BOARD, b"RB951G-2HnD")
        + tlv(mndp.TLV_INTERFACE_NAME, b"bridge_vlan700_mngmt/vlan700")
        + tlv(mndp.TLV_IPV4, bytes([172, 16, 70, 4]))
    )


def test_announcement_decodes_with_routeros_types_and_byte_order():
    fields = mndp.parse_mndp(routeros_style_announcement())

    assert fields[mndp.TLV_MAC].hex(":") == SAMPLE_MAC
    assert fields[mndp.TLV_IDENTITY] == b"sample.r1.example.net"
    assert fields[mndp.TLV_VERSION] == b"7.26beta3 2026-10-16 11:44:30"
    assert fields[mndp.TLV_PLATFORM] == b"MikroTik"
    assert struct.unpack("<I", fields[mndp.TLV_UPTIME])[0] == 628783
    assert fields[mndp.TLV_SOFTWARE_ID] == b"8DL8-ABMU"
    assert fields[mndp.TLV_BOARD] == b"RB951G-2HnD"
    assert fields[mndp.TLV_INTERFACE_NAME] == b"bridge_vlan700_mngmt/vlan700"
    assert fields[mndp.TLV_IPV4] == bytes([172, 16, 70, 4])


def test_our_announcement_uses_the_same_layout():
    payload = mndp.mndp_payload(
        SAMPLE_MAC, "MACabre-RTR", "7.16", "MikroTik", "RB750Gr3", "MACABR", "ether1",
        uptime=3600, address="10.99.0.9",
    )
    fields = mndp.parse_mndp(payload)

    assert fields[mndp.TLV_MAC] == bytes.fromhex("020000000010")
    assert fields[mndp.TLV_IDENTITY] == b"MACabre-RTR"
    assert fields[mndp.TLV_BOARD] == b"RB750Gr3"
    assert fields[mndp.TLV_SOFTWARE_ID] == b"MACABR"
    assert struct.unpack("<I", fields[mndp.TLV_UPTIME])[0] == 3600
    assert fields[mndp.TLV_IPV4] == bytes([10, 99, 0, 9])
    # The first TLV after the header starts with a big-endian type of 0x0001.
    assert payload[4:6] == b"\x00\x01"
