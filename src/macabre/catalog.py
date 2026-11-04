"""Attack families and techniques, generated from docs/attack-catalog.md.

Do not edit by hand. Run scripts/generate_catalog.py after changing the catalog.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Status(Enum):
    """How far a technique has come. Labels match docs/attack-catalog.md."""

    TO_IMPLEMENT = 'To implement'
    IMPLEMENTED = 'Implemented'
    TESTED = 'Tested'
    TESTED_IN_GUI = 'Tested in GUI'
    NOT_WORKING = 'Tested, not working yet'


@dataclass(frozen=True)
class Technique:
    name: str
    description: str
    priority: str
    status: Status


@dataclass(frozen=True)
class Family:
    name: str
    techniques: tuple[Technique, ...]


FAMILIES: tuple[Family, ...] = (
    Family(
        name='MAC Address & CAM Table',
        techniques=(
            Technique(name='MAC Address Spoofing', description='Forging MAC addresses', priority='P1', status=Status.TESTED),
            Technique(name='MAC Flooding / CAM Overflow', description='Saturating the switch learning table', priority='P1', status=Status.TESTED),
            Technique(name='MAC Flapping', description='Repeated changes of a MAC address location', priority='P1', status=Status.TESTED),
            Technique(name='MAC Cloning', description='Cloning the identity of a device', priority='P1', status=Status.TESTED),
            Technique(name='Static MAC Impersonation', description='Impersonating a statically registered MAC', priority='P2', status=Status.TESTED),
            Technique(name='Port Security Exhaustion', description='Exhausting port security learning limits', priority='P2', status=Status.IMPLEMENTED),
            Technique(name='MAC Move / Mobility Abuse', description='Abusing MAC mobility mechanisms', priority='P2', status=Status.TESTED),
            Technique(name='Unknown Unicast Flooding', description='Exploiting flooding of unknown destinations', priority='P2', status=Status.TESTED),
        ),
    ),
    Family(
        name='ARP',
        techniques=(
            Technique(name='ARP Spoofing', description='Forging ARP replies', priority='P1', status=Status.TESTED),
            Technique(name='ARP Cache Poisoning', description='Poisoning ARP caches', priority='P1', status=Status.TESTED),
            Technique(name='Gratuitous ARP Spoofing', description='Fraudulent gratuitous ARP announcements', priority='P1', status=Status.TESTED),
            Technique(name='ARP Request Flooding', description='Flooding with ARP requests', priority='P1', status=Status.TESTED),
            Technique(name='ARP Reply Flooding', description='Flooding with ARP replies', priority='P1', status=Status.TESTED),
            Technique(name='ARP Table Exhaustion', description='Exhausting the ARP table', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='Proxy ARP Abuse', description='Abusing proxy ARP responses', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='ARP-Based Gateway Impersonation', description='Impersonating the default gateway', priority='P1', status=Status.TESTED),
            Technique(name='ARP Inspection Evasion', description='Attempts to evade Dynamic ARP Inspection', priority='P3', status=Status.TO_IMPLEMENT),
        ),
    ),
    Family(
        name='VLAN & IEEE 802.1Q',
        techniques=(
            Technique(name='Switch Spoofing / DTP Spoofing', description='Improper trunk negotiation', priority='P1', status=Status.IMPLEMENTED),
            Technique(name='VLAN Hopping', description='Unauthorized access between VLANs', priority='P1', status=Status.IMPLEMENTED),
            Technique(name='Double-Tagging', description='Double 802.1Q tag insertion', priority='P1', status=Status.IMPLEMENTED),
            Technique(name='Native VLAN Abuse', description='Exploiting the native VLAN', priority='P1', status=Status.IMPLEMENTED),
            Technique(name='VLAN Tag Injection', description='Injecting tagged frames', priority='P1', status=Status.IMPLEMENTED),
            Technique(name='VLAN Translation Abuse', description='Abusing VLAN translation', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='QinQ / VLAN Stacking Abuse', description='Manipulating 802.1ad tags', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='VLAN Pruning Abuse', description='Exploiting VLAN propagation', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='Private VLAN Isolation Bypass', description='Bypassing private VLAN isolation', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='VLAN ID Exhaustion', description='Exhausting VLAN resources', priority='P3', status=Status.TO_IMPLEMENT),
        ),
    ),
    Family(
        name='Spanning Tree (STP / RSTP / MSTP / PVST+)',
        techniques=(
            Technique(name='BPDU Spoofing', description='Forging BPDUs', priority='P1', status=Status.TESTED),
            Technique(name='Root Bridge Takeover', description='Malicious root bridge election', priority='P1', status=Status.TESTED),
            Technique(name='Root Bridge Impersonation', description='Impersonating the root bridge', priority='P1', status=Status.TESTED),
            Technique(name='Topology Change Flooding', description='Flooding topology change notifications', priority='P1', status=Status.IMPLEMENTED),
            Technique(name='TCN Spoofing', description='Fraudulent topology change notifications', priority='P1', status=Status.IMPLEMENTED),
            Technique(name='BPDU Flooding', description='Flooding with BPDUs', priority='P1', status=Status.IMPLEMENTED),
            Technique(name='STP Path Cost Manipulation', description='Manipulating path costs', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='STP Priority Manipulation', description='Altering bridge priorities', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='STP Loop Induction', description='Inducing Layer 2 loops', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='BPDU Guard Trigger Abuse', description='Triggering port shutdowns through BPDU Guard', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='RSTP Proposal/Agreement Abuse', description='Manipulating RSTP convergence', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='MST Region Spoofing', description='Spoofing MST region parameters', priority='P3', status=Status.TO_IMPLEMENT),
        ),
    ),
    Family(
        name='DHCPv4 & DHCPv6',
        techniques=(
            Technique(name='DHCP Starvation', description='Exhausting the address pool', priority='P1', status=Status.TESTED),
            Technique(name='Rogue DHCP Server', description='Unauthorized DHCP server', priority='P1', status=Status.TESTED),
            Technique(name='DHCP Spoofing', description='Forging DHCP responses', priority='P1', status=Status.TESTED),
            Technique(name='DHCP Offer Flooding', description='Flooding with DHCP offers', priority='P1', status=Status.TESTED),
            Technique(name='DHCP Discover Flooding', description='Flooding with DHCP discover requests', priority='P1', status=Status.IMPLEMENTED),
            Technique(name='DHCP NAK Injection', description='Fraudulent DHCP denials', priority='P1', status=Status.TESTED),
            Technique(name='DHCP Release Spoofing', description='Fraudulent lease releases', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='DHCP Option Manipulation', description='Manipulating configuration options', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='DHCP Relay / Option 82 Abuse', description='Abusing relay agent information', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='DHCP Snooping Binding Abuse', description='Manipulating snooping bindings', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='Rogue DHCPv6 Server', description='Unauthorized DHCPv6 server', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='DHCPv6 Starvation', description='Exhausting DHCPv6 resources', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='DHCPv6 Prefix Delegation Abuse', description='Abusing prefix delegation', priority='P3', status=Status.TO_IMPLEMENT),
        ),
    ),
    Family(
        name='IPv6 Neighbor Discovery & SLAAC',
        techniques=(
            Technique(name='Neighbor Advertisement Spoofing', description='Forging NA messages', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='Neighbor Solicitation Spoofing', description='Fraudulent NS requests', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='NDP Cache Poisoning', description='Poisoning IPv6 neighbor caches', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='Rogue Router Advertisement', description='Unauthorized RA messages', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='Router Advertisement Flooding', description='Flooding with RA messages', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='Router Solicitation Flooding', description='Flooding with RS requests', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='SLAAC Prefix Spoofing', description='Advertising fraudulent prefixes', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='SLAAC Configuration Abuse', description='Manipulating stateless autoconfiguration', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='Duplicate Address Detection DoS', description='Interfering with duplicate address detection', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='NDP Neighbor Cache Exhaustion', description='Exhausting the neighbor cache', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='Redirect Spoofing', description='Forged ICMPv6 Redirect messages', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='IPv6 RA Guard Evasion', description='Attempts to evade RA Guard', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='MLD Spoofing / Flooding', description='Manipulating multicast listener membership', priority='P2', status=Status.TO_IMPLEMENT),
        ),
    ),
    Family(
        name='802.1X / EAPOL / NAC',
        techniques=(
            Technique(name='EAPOL Start Flooding', description='Flooding authentication start requests', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='EAPOL Logoff Spoofing', description='Spoofed session logoff', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='EAPOL Replay', description='Replaying captured authentication exchanges', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='802.1X Identity Spoofing', description='Spoofing client identity', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='EAP Downgrade / Weak Method Abuse', description='Exploiting weak authentication methods', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='EAP Relay / Evil Authenticator', description='Relay or rogue authenticator', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='MAB Bypass / MAC Spoofing', description='Abusing MAC-based authentication', priority='P1', status=Status.TESTED),
            Technique(name='Unauthorized Mini-Switch / Hub', description='Connecting several clients to one access port', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='Post-Authentication Session Hijacking', description='Abusing an already authorized session', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='NAC VLAN Assignment Abuse', description='Manipulating authorization VLAN assignment', priority='P3', status=Status.TO_IMPLEMENT),
        ),
    ),
    Family(
        name='Discovery & Management Protocols',
        techniques=(
            Technique(name='CDP Spoofing', description='Forged CDP advertisements', priority='P1', status=Status.TESTED),
            Technique(name='CDP Flooding', description='Flooding with CDP messages', priority='P1', status=Status.TESTED),
            Technique(name='LLDP Spoofing', description='Spoofing LLDP information', priority='P1', status=Status.TESTED),
            Technique(name='LLDP Flooding', description='Flooding with LLDP advertisements', priority='P1', status=Status.TESTED),
            Technique(name='MNDP Spoofing', description='Forged MikroTik Neighbor Discovery advertisements', priority='P1', status=Status.IMPLEMENTED),
            Technique(name='MNDP Flooding', description='Flooding with MikroTik Neighbor Discovery advertisements', priority='P1', status=Status.IMPLEMENTED),
            Technique(name='LLDP-MED Policy Spoofing', description='Forging LLDP-MED policies', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='VTP Spoofing', description='Spoofing VTP advertisements', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='VTP Revision Abuse', description='Manipulating VLAN database revisions', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='DTP Negotiation Abuse', description='Improper trunk negotiation', priority='P1', status=Status.IMPLEMENTED),
            Technique(name='UDLD Spoofing', description='Manipulating unidirectional link detection', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='Ethernet OAM Spoofing', description='Spoofing IEEE 802.3ah messages', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='CFM / 802.1ag Spoofing', description='Manipulating connectivity fault management messages', priority='P3', status=Status.TO_IMPLEMENT),
        ),
    ),
    Family(
        name='Link Aggregation & Redundancy',
        techniques=(
            Technique(name='LACP Spoofing', description='Forging LACPDUs', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='LACP Partner Impersonation', description='Impersonating a LAG partner', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='LACP Negotiation Flooding', description='Flooding LACP negotiations', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='LAG Misconfiguration Abuse', description='Exploiting incorrect link aggregations', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='PAgP Spoofing', description='Spoofing proprietary negotiation', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='MC-LAG / vPC Control Abuse', description='Manipulating multichassis redundancy', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='G.8032 ERPS Control Spoofing', description='Spoofing Ethernet ring control messages', priority='P3', status=Status.TO_IMPLEMENT),
        ),
    ),
    Family(
        name='L2 Multicast & Broadcast',
        techniques=(
            Technique(name='Broadcast Storm', description='Broadcast traffic storm', priority='P1', status=Status.TESTED),
            Technique(name='Multicast Flooding', description='Multicast flooding', priority='P1', status=Status.TESTED),
            Technique(name='IGMP Spoofing', description='Spoofing IGMP memberships', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='IGMP Query Spoofing', description='Fraudulent multicast queries', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='IGMP Leave Spoofing', description='Fraudulent group leave', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='IGMP Snooping Table Exhaustion', description='Exhausting the group table', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='Unknown Multicast Flooding', description='Exploiting unknown multicast traffic', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='L2 Loop Amplification', description='Amplifying traffic through loops', priority='P2', status=Status.TO_IMPLEMENT),
        ),
    ),
    Family(
        name='MACsec / IEEE 802.1AE',
        techniques=(
            Technique(name='MKA Peer Impersonation', description='Impersonating MKA participants', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='MKA Negotiation Disruption', description='Disrupting key agreement', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='MACsec Replay / PN Abuse', description='Testing anti-replay protection and packet numbers', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='MACsec Downgrade / Fail-Open Abuse', description='Exploiting permissive configurations', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='MACsec Key Rotation Disruption', description='Interfering with key rotation', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='MACsec SCI Spoofing', description='Spoofing secure channel identifiers', priority='P3', status=Status.TO_IMPLEMENT),
        ),
    ),
    Family(
        name='Carrier Ethernet & Data Center',
        techniques=(
            Technique(name='PPPoE Discovery Flooding', description='Flooding PPPoE discovery', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='Rogue PPPoE Access Concentrator', description='Unauthorized PPPoE access concentrator', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='PPPoE Session Spoofing', description='Spoofing PPPoE sessions', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='802.1ad QinQ Abuse', description='Manipulating provider VLANs', priority='P2', status=Status.TO_IMPLEMENT),
            Technique(name='802.1ah PBB Encapsulation Abuse', description='Manipulating backbone encapsulation', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='EVPN MAC/IP Advertisement Poisoning', description='Fraudulent MAC/IP advertisements', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='EVPN MAC Mobility Abuse', description='Mobility oscillation or spoofing', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='VXLAN VNI / VTEP Spoofing', description='Spoofing overlay elements', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='TRILL / SPB Control Abuse', description='Manipulating advanced bridging control', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='Provider Ethernet OAM Abuse', description='Manipulating provider maintenance operations', priority='P3', status=Status.TO_IMPLEMENT),
        ),
    ),
    Family(
        name='Industrial & Specialized L2',
        techniques=(
            Technique(name='PROFINET DCP Spoofing', description='Manipulating discovery and configuration', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='PROFINET DCP Identify Flooding', description='Flooding industrial discovery', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='EtherCAT Frame Injection', description='Injecting industrial frames', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='IEC 61850 GOOSE Spoofing', description='Spoofing GOOSE messages', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='IEC 61850 GOOSE Replay', description='Replaying GOOSE messages', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='HSR / PRP Redundancy Abuse', description='Manipulating industrial redundancy', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='PTP / IEEE 1588 Spoofing', description='Spoofing time synchronization', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='PTP Grandmaster Impersonation', description='Impersonating the grandmaster clock', priority='P3', status=Status.TO_IMPLEMENT),
            Technique(name='802.1AS gPTP Manipulation', description='Manipulating TSN time synchronization', priority='P3', status=Status.TO_IMPLEMENT),
        ),
    ),
)
