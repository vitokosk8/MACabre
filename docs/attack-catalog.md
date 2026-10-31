# MACabre: Layer 2 Attack Catalog

This catalog classifies Layer 2 attack techniques against Ethernet networks and related protocols. It is the design basis for MACabre's audit modules.

It covers active attacks, spoofing, interception, denial of service and discovery. It also includes techniques from higher layers that depend on access to the Ethernet segment and are useful in a Layer 2 audit.

There is no closed, universal list of attacks. Variants depend on vendor, implemented protocols, configuration and specific vulnerabilities.

## Priorities

| Priority | Meaning | Techniques |
| --- | --- | ---: |
| P1 | Core: initial functionality | 41 |
| P2 | Expansion | 45 |
| P3 | Specialized features | 40 |

Not every technique is reproducible on every device, and not every technique has a public implementation. Many modules will detect a vulnerable configuration, verify existing protections or reproduce the behavior in an isolated lab, instead of running the attack.

## Status

The Status column shows where each technique stands in MACabre:

- ✅ Implemented: has an attack module, a GUI panel and a lab test.
- ⏳ Planned: not implemented yet.

Implemented so far: 3 of 126 techniques (P1: 3 of 41).

## Techniques by category

### MAC Address & CAM Table (8)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| MAC Address Spoofing | Forging MAC addresses | P1 | ⏳ Planned |
| MAC Flooding / CAM Overflow | Saturating the switch learning table | P1 | ✅ Implemented |
| MAC Flapping | Repeated changes of a MAC address location | P1 | ✅ Implemented |
| MAC Cloning | Cloning the identity of a device | P1 | ⏳ Planned |
| Static MAC Impersonation | Impersonating a statically registered MAC | P2 | ⏳ Planned |
| Port Security Exhaustion | Exhausting port security learning limits | P2 | ⏳ Planned |
| MAC Move / Mobility Abuse | Abusing MAC mobility mechanisms | P2 | ⏳ Planned |
| Unknown Unicast Flooding | Exploiting flooding of unknown destinations | P2 | ⏳ Planned |

### ARP (9)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| ARP Spoofing | Forging ARP replies | P1 | ⏳ Planned |
| ARP Cache Poisoning | Poisoning ARP caches | P1 | ⏳ Planned |
| Gratuitous ARP Spoofing | Fraudulent gratuitous ARP announcements | P1 | ⏳ Planned |
| ARP Request Flooding | Flooding with ARP requests | P1 | ⏳ Planned |
| ARP Reply Flooding | Flooding with ARP replies | P1 | ⏳ Planned |
| ARP Table Exhaustion | Exhausting the ARP table | P2 | ⏳ Planned |
| Proxy ARP Abuse | Abusing proxy ARP responses | P2 | ⏳ Planned |
| ARP-Based Gateway Impersonation | Impersonating the default gateway | P1 | ⏳ Planned |
| ARP Inspection Evasion | Attempts to evade Dynamic ARP Inspection | P3 | ⏳ Planned |

### VLAN & IEEE 802.1Q (10)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| Switch Spoofing / DTP Spoofing | Improper trunk negotiation | P1 | ⏳ Planned |
| VLAN Hopping | Unauthorized access between VLANs | P1 | ⏳ Planned |
| Double-Tagging | Double 802.1Q tag insertion | P1 | ⏳ Planned |
| Native VLAN Abuse | Exploiting the native VLAN | P1 | ⏳ Planned |
| VLAN Tag Injection | Injecting tagged frames | P1 | ⏳ Planned |
| VLAN Translation Abuse | Abusing VLAN translation | P3 | ⏳ Planned |
| QinQ / VLAN Stacking Abuse | Manipulating 802.1ad tags | P2 | ⏳ Planned |
| VLAN Pruning Abuse | Exploiting VLAN propagation | P2 | ⏳ Planned |
| Private VLAN Isolation Bypass | Bypassing private VLAN isolation | P2 | ⏳ Planned |
| VLAN ID Exhaustion | Exhausting VLAN resources | P3 | ⏳ Planned |

### Spanning Tree (STP / RSTP / MSTP / PVST+) (12)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| BPDU Spoofing | Forging BPDUs | P1 | ⏳ Planned |
| Root Bridge Takeover | Malicious root bridge election | P1 | ⏳ Planned |
| Root Bridge Impersonation | Impersonating the root bridge | P1 | ⏳ Planned |
| Topology Change Flooding | Flooding topology change notifications | P1 | ⏳ Planned |
| TCN Spoofing | Fraudulent topology change notifications | P1 | ⏳ Planned |
| BPDU Flooding | Flooding with BPDUs | P1 | ⏳ Planned |
| STP Path Cost Manipulation | Manipulating path costs | P2 | ⏳ Planned |
| STP Priority Manipulation | Altering bridge priorities | P2 | ⏳ Planned |
| STP Loop Induction | Inducing Layer 2 loops | P2 | ⏳ Planned |
| BPDU Guard Trigger Abuse | Triggering port shutdowns through BPDU Guard | P2 | ⏳ Planned |
| RSTP Proposal/Agreement Abuse | Manipulating RSTP convergence | P3 | ⏳ Planned |
| MST Region Spoofing | Spoofing MST region parameters | P3 | ⏳ Planned |

### DHCPv4 & DHCPv6 (13)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| DHCP Starvation | Exhausting the address pool | P1 | ✅ Implemented |
| Rogue DHCP Server | Unauthorized DHCP server | P1 | ⏳ Planned |
| DHCP Spoofing | Forging DHCP responses | P1 | ⏳ Planned |
| DHCP Offer Flooding | Flooding with DHCP offers | P1 | ⏳ Planned |
| DHCP Discover Flooding | Flooding with DHCP discover requests | P1 | ⏳ Planned |
| DHCP NAK Injection | Fraudulent DHCP denials | P1 | ⏳ Planned |
| DHCP Release Spoofing | Fraudulent lease releases | P2 | ⏳ Planned |
| DHCP Option Manipulation | Manipulating configuration options | P2 | ⏳ Planned |
| DHCP Relay / Option 82 Abuse | Abusing relay agent information | P2 | ⏳ Planned |
| DHCP Snooping Binding Abuse | Manipulating snooping bindings | P3 | ⏳ Planned |
| Rogue DHCPv6 Server | Unauthorized DHCPv6 server | P1 | ⏳ Planned |
| DHCPv6 Starvation | Exhausting DHCPv6 resources | P2 | ⏳ Planned |
| DHCPv6 Prefix Delegation Abuse | Abusing prefix delegation | P3 | ⏳ Planned |

### IPv6 Neighbor Discovery & SLAAC (13)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| Neighbor Advertisement Spoofing | Forging NA messages | P1 | ⏳ Planned |
| Neighbor Solicitation Spoofing | Fraudulent NS requests | P1 | ⏳ Planned |
| NDP Cache Poisoning | Poisoning IPv6 neighbor caches | P1 | ⏳ Planned |
| Rogue Router Advertisement | Unauthorized RA messages | P1 | ⏳ Planned |
| Router Advertisement Flooding | Flooding with RA messages | P1 | ⏳ Planned |
| Router Solicitation Flooding | Flooding with RS requests | P2 | ⏳ Planned |
| SLAAC Prefix Spoofing | Advertising fraudulent prefixes | P1 | ⏳ Planned |
| SLAAC Configuration Abuse | Manipulating stateless autoconfiguration | P1 | ⏳ Planned |
| Duplicate Address Detection DoS | Interfering with duplicate address detection | P2 | ⏳ Planned |
| NDP Neighbor Cache Exhaustion | Exhausting the neighbor cache | P2 | ⏳ Planned |
| Redirect Spoofing | Forged ICMPv6 Redirect messages | P2 | ⏳ Planned |
| IPv6 RA Guard Evasion | Attempts to evade RA Guard | P3 | ⏳ Planned |
| MLD Spoofing / Flooding | Manipulating multicast listener membership | P2 | ⏳ Planned |

### 802.1X / EAPOL / NAC (10)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| EAPOL Start Flooding | Flooding authentication start requests | P2 | ⏳ Planned |
| EAPOL Logoff Spoofing | Spoofed session logoff | P2 | ⏳ Planned |
| EAPOL Replay | Replaying captured authentication exchanges | P2 | ⏳ Planned |
| 802.1X Identity Spoofing | Spoofing client identity | P2 | ⏳ Planned |
| EAP Downgrade / Weak Method Abuse | Exploiting weak authentication methods | P3 | ⏳ Planned |
| EAP Relay / Evil Authenticator | Relay or rogue authenticator | P3 | ⏳ Planned |
| MAB Bypass / MAC Spoofing | Abusing MAC-based authentication | P1 | ⏳ Planned |
| Unauthorized Mini-Switch / Hub | Connecting several clients to one access port | P2 | ⏳ Planned |
| Post-Authentication Session Hijacking | Abusing an already authorized session | P3 | ⏳ Planned |
| NAC VLAN Assignment Abuse | Manipulating authorization VLAN assignment | P3 | ⏳ Planned |

### Discovery & Management Protocols (11)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| CDP Spoofing | Forged CDP advertisements | P1 | ⏳ Planned |
| CDP Flooding | Flooding with CDP messages | P2 | ⏳ Planned |
| LLDP Spoofing | Spoofing LLDP information | P1 | ⏳ Planned |
| LLDP Flooding | Flooding with LLDP advertisements | P2 | ⏳ Planned |
| LLDP-MED Policy Spoofing | Forging LLDP-MED policies | P2 | ⏳ Planned |
| VTP Spoofing | Spoofing VTP advertisements | P2 | ⏳ Planned |
| VTP Revision Abuse | Manipulating VLAN database revisions | P2 | ⏳ Planned |
| DTP Negotiation Abuse | Improper trunk negotiation | P1 | ⏳ Planned |
| UDLD Spoofing | Manipulating unidirectional link detection | P3 | ⏳ Planned |
| Ethernet OAM Spoofing | Spoofing IEEE 802.3ah messages | P3 | ⏳ Planned |
| CFM / 802.1ag Spoofing | Manipulating connectivity fault management messages | P3 | ⏳ Planned |

### Link Aggregation & Redundancy (7)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| LACP Spoofing | Forging LACPDUs | P2 | ⏳ Planned |
| LACP Partner Impersonation | Impersonating a LAG partner | P2 | ⏳ Planned |
| LACP Negotiation Flooding | Flooding LACP negotiations | P2 | ⏳ Planned |
| LAG Misconfiguration Abuse | Exploiting incorrect link aggregations | P2 | ⏳ Planned |
| PAgP Spoofing | Spoofing proprietary negotiation | P3 | ⏳ Planned |
| MC-LAG / vPC Control Abuse | Manipulating multichassis redundancy | P3 | ⏳ Planned |
| G.8032 ERPS Control Spoofing | Spoofing Ethernet ring control messages | P3 | ⏳ Planned |

### L2 Multicast & Broadcast (8)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| Broadcast Storm | Broadcast traffic storm | P1 | ⏳ Planned |
| Multicast Flooding | Multicast flooding | P1 | ⏳ Planned |
| IGMP Spoofing | Spoofing IGMP memberships | P2 | ⏳ Planned |
| IGMP Query Spoofing | Fraudulent multicast queries | P2 | ⏳ Planned |
| IGMP Leave Spoofing | Fraudulent group leave | P2 | ⏳ Planned |
| IGMP Snooping Table Exhaustion | Exhausting the group table | P3 | ⏳ Planned |
| Unknown Multicast Flooding | Exploiting unknown multicast traffic | P2 | ⏳ Planned |
| L2 Loop Amplification | Amplifying traffic through loops | P2 | ⏳ Planned |

### MACsec / IEEE 802.1AE (6)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| MKA Peer Impersonation | Impersonating MKA participants | P3 | ⏳ Planned |
| MKA Negotiation Disruption | Disrupting key agreement | P3 | ⏳ Planned |
| MACsec Replay / PN Abuse | Testing anti-replay protection and packet numbers | P3 | ⏳ Planned |
| MACsec Downgrade / Fail-Open Abuse | Exploiting permissive configurations | P3 | ⏳ Planned |
| MACsec Key Rotation Disruption | Interfering with key rotation | P3 | ⏳ Planned |
| MACsec SCI Spoofing | Spoofing secure channel identifiers | P3 | ⏳ Planned |

### Carrier Ethernet & Data Center (10)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| PPPoE Discovery Flooding | Flooding PPPoE discovery | P2 | ⏳ Planned |
| Rogue PPPoE Access Concentrator | Unauthorized PPPoE access concentrator | P2 | ⏳ Planned |
| PPPoE Session Spoofing | Spoofing PPPoE sessions | P2 | ⏳ Planned |
| 802.1ad QinQ Abuse | Manipulating provider VLANs | P2 | ⏳ Planned |
| 802.1ah PBB Encapsulation Abuse | Manipulating backbone encapsulation | P3 | ⏳ Planned |
| EVPN MAC/IP Advertisement Poisoning | Fraudulent MAC/IP advertisements | P3 | ⏳ Planned |
| EVPN MAC Mobility Abuse | Mobility oscillation or spoofing | P3 | ⏳ Planned |
| VXLAN VNI / VTEP Spoofing | Spoofing overlay elements | P3 | ⏳ Planned |
| TRILL / SPB Control Abuse | Manipulating advanced bridging control | P3 | ⏳ Planned |
| Provider Ethernet OAM Abuse | Manipulating provider maintenance operations | P3 | ⏳ Planned |

### Industrial & Specialized L2 (9)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| PROFINET DCP Spoofing | Manipulating discovery and configuration | P3 | ⏳ Planned |
| PROFINET DCP Identify Flooding | Flooding industrial discovery | P3 | ⏳ Planned |
| EtherCAT Frame Injection | Injecting industrial frames | P3 | ⏳ Planned |
| IEC 61850 GOOSE Spoofing | Spoofing GOOSE messages | P3 | ⏳ Planned |
| IEC 61850 GOOSE Replay | Replaying GOOSE messages | P3 | ⏳ Planned |
| HSR / PRP Redundancy Abuse | Manipulating industrial redundancy | P3 | ⏳ Planned |
| PTP / IEEE 1588 Spoofing | Spoofing time synchronization | P3 | ⏳ Planned |
| PTP Grandmaster Impersonation | Impersonating the grandmaster clock | P3 | ⏳ Planned |
| 802.1AS gPTP Manipulation | Manipulating TSN time synchronization | P3 | ⏳ Planned |

## Extended scope (not yet scheduled)

These scenarios are not pure Ethernet attacks, but they belong to MACabre's extended scope:

- LLMNR, NBT-NS and mDNS poisoning: name resolution spoofing within the local segment.
- VRRP, HSRP and CARP spoofing: spoofing gateway redundancy mechanisms (L2/L3 boundary).
- DNS spoofing after a Layer 2 attack: follow-up exploitation of an intermediary position.
- IPv6-first attacks: abuse of IPv6 enabled on networks mainly managed as IPv4.
- Wake-on-LAN abuse: unauthorized use of wake-up frames.
- EtherType fuzzing: tests with unusual EtherType values and header combinations.
- Malformed Ethernet frames: robustness tests against anomalous frames.
- Jumbo frame abuse: MTU limit and processing tests.
- Pause frame (IEEE 802.3x) abuse: abuse of flow control.
- Priority Flow Control abuse: disruption through IEEE 802.1Qbb.
- 802.1p / PCP manipulation: traffic priority manipulation.
- MACsec downgrade and fail-open testing: verifying that protected links reject traffic that lacks the required protection.

Wi-Fi deserves a separate module: deauthentication, disassociation, Evil Twin, WPA attacks and 802.11 frame manipulation belong to the link layer but are not IEEE 802.3 Ethernet.

## References

- MITRE ATT&CK T1557, Adversary-in-the-Middle: https://attack.mitre.org/techniques/T1557/
- Cisco Layer 2 security documentation
- Yersinia, layer 2 attack framework: https://github.com/tomac/yersinia
- Allied Telesis, LAN Security Guide: https://www.alliedtelesis.com/sites/default/files/file/2022-02/lan_security_guide__andrew_riddell_revc3.pdf
