import struct
import threading

from scapy.all import Ether, Raw

from macabre.attacks import dtp_audit as audit
from macabre.attacks.dtp_audit import DtpAuditConfig, STATUS_ACCESS, STATUS_TRUNK
from macabre.attacks.switch_spoofing import SNAP_HEADER, build_dtp_frame, dtp_payload

ATTACKER = "02:00:00:00:00:30"
SWITCH = "00:0c:29:aa:bb:01"
LINK_OUTPUT = (
    "2: eth9: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP "
    f"link/ether {ATTACKER} brd ff:ff:ff:ff:ff:ff"
)


def fake_run(argv):
    return LINK_OUTPUT if argv[:4] == ["ip", "-o", "link", "show"] else ""


def switch_frame(status, encapsulation=0xA5, domain="corp"):
    body = bytes([1])
    body += struct.pack("!HH", 1, 4 + len(domain)) + domain.encode()
    body += struct.pack("!HH", 2, 5) + bytes([status])
    body += struct.pack("!HH", 3, 5) + bytes([encapsulation])
    body += struct.pack("!HH", 4, 10) + bytes.fromhex(SWITCH.replace(":", ""))
    payload = SNAP_HEADER + body
    return Ether(src=SWITCH, dst="01:00:0c:cc:cc:cc", type=len(payload)) / Raw(payload)


def test_a_trunk_advertisement_is_decoded_with_status_type_and_domain():
    neighbor = audit.decode(switch_frame(STATUS_TRUNK))
    assert neighbor.mac == SWITCH
    assert neighbor.status == STATUS_TRUNK
    assert neighbor.encapsulation == 0xA5
    assert neighbor.domain == "corp"
    assert neighbor.trunk


def test_an_access_advertisement_is_not_a_trunk():
    neighbor = audit.decode(switch_frame(STATUS_ACCESS))
    assert not neighbor.trunk


def test_our_own_negotiation_frame_decodes_as_a_trunk_request():
    neighbor = audit.decode(build_dtp_frame(ATTACKER))
    assert neighbor.status == STATUS_TRUNK and neighbor.mac == ATTACKER


def test_non_dtp_frames_are_ignored():
    frame = Ether(src=SWITCH, dst="ff:ff:ff:ff:ff:ff", type=0x0800) / Raw(b"\x45" + b"\x00" * 30)
    assert audit.decode(frame) is None
    assert audit.decode(Ether(src=SWITCH, dst="ff:ff:ff:ff:ff:ff", type=0x0806)) is None


def test_truncated_tlv_is_rejected():
    payload = dtp_payload(ATTACKER)
    assert audit.parse_dtp(payload[:-3]) is None


class FakeSniffer:
    handler = None

    def __init__(self, **kwargs):
        FakeSniffer.handler = kwargs["prn"]

    def start(self):
        pass

    def stop(self):
        pass


def test_probe_is_sent_once_when_enabled():
    sent = []
    stop = threading.Event()
    stop.set()
    stats = audit.run_dtp_audit(DtpAuditConfig(iface="eth9"), stop, lambda _s: None, run=fake_run,
                                send=lambda frame, iface, verbose: sent.append(frame),
                                sniffer_factory=FakeSniffer)
    assert len(sent) == 1 and stats.probe_sent
    assert stats.frames_seen == 0 and "unknown" in stats.status


def test_audit_reports_trunk_and_access_ports():
    stop = threading.Event()
    results = []
    handler_holder = {}

    class Capturing(FakeSniffer):
        def __init__(self, **kwargs):
            handler_holder["prn"] = kwargs["prn"]

    def probe(frame, iface, verbose):
        return None

    thread_stop = threading.Event()
    done = {}

    def worker():
        done["stats"] = audit.run_dtp_audit(DtpAuditConfig(iface="eth9", probe=False), thread_stop,
                                            lambda s: results.append(s), run=fake_run, send=probe,
                                            sniffer_factory=Capturing)

    thread = threading.Thread(target=worker)
    thread.start()
    while "prn" not in handler_holder:
        pass
    handler_holder["prn"](switch_frame(STATUS_ACCESS))
    handler_holder["prn"](switch_frame(STATUS_TRUNK, domain="ops"))
    thread_stop.set()
    thread.join(5)
    stats = done["stats"]
    assert stats.frames_seen == 2
    assert stats.trunk_answer
    assert "negotiates trunks" in stats.status
    assert stats.neighbors[SWITCH].domain == "ops"


def test_dry_run_sends_nothing():
    sent = []
    stats = audit.run_dtp_audit(DtpAuditConfig(iface="eth9", dry_run=True), threading.Event(),
                                lambda _s: None, run=fake_run, send=lambda *a, **k: sent.append(a),
                                sniffer_factory=FakeSniffer)
    assert sent == [] and stats.status.startswith("Dry run")


def test_a_sniffed_frame_decodes_the_same_as_a_built_one():
    # Re-parsing the bytes gives the layered form a sniffer returns (LLC, SNAP, Raw).
    sniffed = Ether(bytes(switch_frame(STATUS_TRUNK)))
    neighbor = audit.decode(sniffed)
    assert neighbor is not None
    assert neighbor.trunk and neighbor.domain == "corp"
