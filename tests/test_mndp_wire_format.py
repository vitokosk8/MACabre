from macabre.attacks.mndp_spoofing import (
    TLV_IDENTITY,
    TLV_IPV4,
    TLV_MAC,
    TLV_UPTIME,
    mndp_payload,
    parse_mndp,
)

# Synthetic values only; the addresses are from the documentation range 192.0.2.0/24.


def sample(sequence=2):
    return mndp_payload(
        "02:00:00:00:00:01", "TEST-RTR", "7.26", "MikroTik", "RB750Gr3", "SYNTH",
        "ether1", uptime=1, address="192.0.2.1", sequence=sequence,
    )


def test_header_is_little_endian_sequence_then_zeros():
    assert sample(sequence=2)[:4] == b"\x02\x00\x00\x00"


def test_first_record_is_the_mac_tlv_with_big_endian_type_and_length():
    payload = sample()
    assert payload[4:14] == b"\x00\x01\x00\x06" + bytes.fromhex("020000000001")


def test_ipv4_record_has_big_endian_type_and_length():
    assert b"\x00\x11\x00\x04" + bytes([192, 0, 2, 1]) in sample()


def test_uptime_value_is_little_endian():
    assert parse_mndp(sample())[TLV_UPTIME] == (1).to_bytes(4, "little")


def test_parser_reads_back_every_record():
    fields = parse_mndp(sample())
    assert fields[TLV_IDENTITY] == b"TEST-RTR"
    assert fields[TLV_IPV4] == bytes([192, 0, 2, 1])
    assert fields[TLV_MAC] == bytes.fromhex("020000000001")


def test_record_numbers_match_routeros_announcements():
    from macabre.attacks import mndp_spoofing as m

    assert (m.TLV_MAC, m.TLV_IDENTITY, m.TLV_VERSION, m.TLV_PLATFORM) == (0x01, 0x05, 0x07, 0x08)
    assert (m.TLV_UPTIME, m.TLV_SOFTWARE_ID, m.TLV_BOARD) == (0x0A, 0x0B, 0x0C)
    assert (m.TLV_INTERFACE_NAME, m.TLV_IPV4) == (0x10, 0x11)
