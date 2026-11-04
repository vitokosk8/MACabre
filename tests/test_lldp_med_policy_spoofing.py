import struct
import threading

import pytest
from scapy.all import Ether, Raw

from macabre.attacks.lldp_med_policy_spoofing import (
    MAX_FRAMES,
    LldpMedPolicySpoofingConfig,
    build_policy_frame,
    lldp_med_payload,
    network_policy_value,
    run_lldp_med_policy_spoofing,
)

SOURCE = "02:00:00:00:00:20"


def parse_tlvs(payload: bytes):
    tlvs = []
    offset = 0
    while offset < len(payload):
        (header,) = struct.unpack_from("!H", payload, offset)
        kind, length = header >> 9, header & 0x1FF
        tlvs.append((kind, payload[offset + 2: offset + 2 + length]))
        offset += 2 + length
    return tlvs


def policy_tlv(config):
    for kind, value in parse_tlvs(lldp_med_payload(config)):
        if kind == 127 and value[3] == 0x02:
            return value
    raise AssertionError("no network policy TLV")


def test_network_policy_packs_vlan_priority_and_dscp():
    value = network_policy_value(application=1, tagged=True, vlan_id=10, priority=5, dscp=46)
    word = int.from_bytes(value[1:], "big")
    assert value[0] == 1
    assert (word >> 22) & 1 == 1          # tagged
    assert (word >> 9) & 0xFFF == 10      # VLAN ID
    assert (word >> 6) & 0x7 == 5         # L2 priority
    assert word & 0x3F == 46              # DSCP


def test_policy_tlv_carries_the_configured_values():
    config = LldpMedPolicySpoofingConfig(iface="eth0", source_mac=SOURCE, vlan_id=20, priority=6, dscp=40)
    value = policy_tlv(config)
    assert value[:3] == b"\x00\x12\xbb"
    assert value[4] == 1                  # voice
    word = int.from_bytes(value[5:8], "big")
    assert (word >> 9) & 0xFFF == 20
    assert (word >> 6) & 0x7 == 6
    assert word & 0x3F == 40


def test_payload_has_mandatory_tlvs_first_and_end_last():
    tlvs = parse_tlvs(lldp_med_payload(LldpMedPolicySpoofingConfig(iface="eth0", source_mac=SOURCE)))
    assert [kind for kind, _ in tlvs[:3]] == [1, 2, 3]
    assert tlvs[-1] == (0, b"")


def test_frame_goes_to_the_nearest_bridge_address():
    frame = build_policy_frame(LldpMedPolicySpoofingConfig(iface="eth0", source_mac=SOURCE))
    assert frame[Ether].dst == "01:80:c2:00:00:0e"
    assert frame[Ether].type == 0x88CC
    assert frame[Ether].src == SOURCE


def test_config_rejects_bad_values():
    base = dict(iface="eth0", source_mac=SOURCE)
    with pytest.raises(ValueError):
        LldpMedPolicySpoofingConfig(**base, application="unknown")
    with pytest.raises(ValueError):
        LldpMedPolicySpoofingConfig(**base, vlan_id=0, tagged=True)
    with pytest.raises(ValueError):
        LldpMedPolicySpoofingConfig(**base, vlan_id=4095)
    with pytest.raises(ValueError):
        LldpMedPolicySpoofingConfig(**base, tagged=False, vlan_id=10)
    with pytest.raises(ValueError):
        LldpMedPolicySpoofingConfig(**base, priority=8)
    with pytest.raises(ValueError):
        LldpMedPolicySpoofingConfig(**base, dscp=64)
    with pytest.raises(ValueError):
        LldpMedPolicySpoofingConfig(**base, frames=0)
    with pytest.raises(ValueError):
        LldpMedPolicySpoofingConfig(**base, frames=MAX_FRAMES + 1)
    with pytest.raises(ValueError):
        LldpMedPolicySpoofingConfig(iface="eth0", source_mac="bad")


def test_untagged_policy_uses_vlan_zero():
    config = LldpMedPolicySpoofingConfig(iface="eth0", source_mac=SOURCE, tagged=False, vlan_id=0)
    value = policy_tlv(config)
    word = int.from_bytes(value[5:8], "big")
    assert (word >> 22) & 1 == 0
    assert (word >> 9) & 0xFFF == 0


def test_run_sends_the_frames():
    sent = []
    stats = run_lldp_med_policy_spoofing(
        LldpMedPolicySpoofingConfig(iface="eth0", source_mac=SOURCE, frames=3, interval=0),
        threading.Event(),
        lambda s: None,
        send=lambda frame, **kw: sent.append(frame),
    )
    assert stats.frames == 3
    assert len(sent) == 3
    assert all(f.haslayer(Raw) for f in sent)


def test_dry_run_sends_nothing():
    sent = []
    stats = run_lldp_med_policy_spoofing(
        LldpMedPolicySpoofingConfig(iface="eth0", source_mac=SOURCE, dry_run=True),
        threading.Event(),
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert "Nothing sent" in stats.status


def test_stop_event_set_before_run_sends_nothing():
    stop = threading.Event()
    stop.set()
    sent = []
    stats = run_lldp_med_policy_spoofing(
        LldpMedPolicySpoofingConfig(iface="eth0", source_mac=SOURCE),
        stop,
        lambda s: None,
        send=lambda *a, **kw: sent.append(a),
    )
    assert sent == []
    assert stats.frames == 0
