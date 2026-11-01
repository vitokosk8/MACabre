# MACabre: Layer 2 Attack Catalog

This catalog classifies Layer 2 attack techniques against Ethernet networks and related protocols. It is the design basis for MACabre's audit modules.

It covers active attacks, spoofing, interception, denial of service and discovery. It also includes techniques from higher layers that depend on access to the Ethernet segment and are useful in a Layer 2 audit.

There is no closed, universal list of attacks. Variants depend on vendor, implemented protocols, configuration and specific vulnerabilities.

## Priorities

| Priority | Meaning | Techniques |
| --- | --- | ---: |
| P1 | Core: initial functionality | 37 |
| P2 | Expansion | 51 |
| P3 | Specialized features | 40 |

Not every technique is reproducible on every device, and not every technique has a public implementation. Many modules will detect a vulnerable configuration, verify existing protections or reproduce the behavior in an isolated lab, instead of running the attack.

## Status

The Status column shows how far each technique has come in MACabre:

- 📋 To implement: planned, no code yet.
- 🔨 Implemented: attack module and GUI panel exist, not tested yet.
- 🧪 Tested: validated with a lab script on a test network.
- 🖥 Tested in GUI: validated by running the attack from the desktop interface.
- ❌ Tested, not working yet: tested, and the result does not match the expected behavior.

Current count: 22 tested, 0 tested in GUI, 0 not working yet, 9 implemented only, 97 to implement (128 techniques; P1: 22 of 37 tested).

## Techniques by category

### MAC Address & CAM Table (8)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| MAC Address Spoofing | Forging MAC addresses | P1 | 🧪 Tested |
| MAC Flooding / CAM Overflow | Saturating the switch learning table | P1 | 🧪 Tested |
| MAC Flapping | Repeated changes of a MAC address location | P1 | 🧪 Tested |
| MAC Cloning | Cloning the identity of a device | P1 | 🧪 Tested |
| Static MAC Impersonation | Impersonating a statically registered MAC | P2 | 📋 To implement |
| Port Security Exhaustion | Exhausting port security learning limits | P2 | 📋 To implement |
| MAC Move / Mobility Abuse | Abusing MAC mobility mechanisms | P2 | 📋 To implement |
| Unknown Unicast Flooding | Exploiting flooding of unknown destinations | P2 | 📋 To implement |

### ARP (9)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| ARP Spoofing | Forging ARP replies | P1 | 🧪 Tested |
| ARP Cache Poisoning | Poisoning ARP caches | P1 | 🧪 Tested |
| Gratuitous ARP Spoofing | Fraudulent gratuitous ARP announcements | P1 | 🧪 Tested |
| ARP Request Flooding | Flooding with ARP requests | P1 | 🧪 Tested |
| ARP Reply Flooding | Flooding with ARP replies | P1 | 🧪 Tested |
| ARP Table Exhaustion | Exhausting the ARP table | P2 | 📋 To implement |
| Proxy ARP Abuse | Abusing proxy ARP responses | P2 | 📋 To implement |
| ARP-Based Gateway Impersonation | Impersonating the default gateway | P1 | 🧪 Tested |
| ARP Inspection Evasion | Attempts to evade Dynamic ARP Inspection | P3 | 📋 To implement |

### VLAN & IEEE 802.1Q (10)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| Switch Spoofing / DTP Spoofing | Improper trunk negotiation | P1 | 🔨 Implemented |
| VLAN Hopping | Unauthorized access between VLANs | P1 | 🔨 Implemented |
| Double-Tagging | Double 802.1Q tag insertion | P1 | 🔨 Implemented |
| Native VLAN Abuse | Exploiting the native VLAN | P1 | 🔨 Implemented |
| VLAN Tag Injection | Injecting tagged frames | P1 | 🔨 Implemented |
| VLAN Translation Abuse | Abusing VLAN translation | P3 | 📋 To implement |
| QinQ / VLAN Stacking Abuse | Manipulating 802.1ad tags | P2 | 📋 To implement |
| VLAN Pruning Abuse | Exploiting VLAN propagation | P2 | 📋 To implement |
| Private VLAN Isolation Bypass | Bypassing private VLAN isolation | P2 | 📋 To implement |
| VLAN ID Exhaustion | Exhausting VLAN resources | P3 | 📋 To implement |

### Spanning Tree (STP / RSTP / MSTP / PVST+) (12)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| BPDU Spoofing | Forging BPDUs | P1 | 🧪 Tested |
| Root Bridge Takeover | Malicious root bridge election | P1 | 🧪 Tested |
| Root Bridge Impersonation | Impersonating the root bridge | P1 | 🧪 Tested |
| Topology Change Flooding | Flooding topology change notifications | P1 | 🔨 Implemented |
| TCN Spoofing | Fraudulent topology change notifications | P1 | 🔨 Implemented |
| BPDU Flooding | Flooding with BPDUs | P1 | 🔨 Implemented |
| STP Path Cost Manipulation | Manipulating path costs | P2 | 📋 To implement |
| STP Priority Manipulation | Altering bridge priorities | P2 | 📋 To implement |
| STP Loop Induction | Inducing Layer 2 loops | P2 | 📋 To implement |
| BPDU Guard Trigger Abuse | Triggering port shutdowns through BPDU Guard | P2 | 📋 To implement |
| RSTP Proposal/Agreement Abuse | Manipulating RSTP convergence | P3 | 📋 To implement |
| MST Region Spoofing | Spoofing MST region parameters | P3 | 📋 To implement |

### DHCPv4 & DHCPv6 (13)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| DHCP Starvation | Exhausting the address pool | P1 | 🧪 Tested |
| Rogue DHCP Server | Unauthorized DHCP server | P1 | 🧪 Tested |
| DHCP Spoofing | Forging DHCP responses | P1 | 🧪 Tested |
| DHCP Offer Flooding | Flooding with DHCP offers | P1 | 🧪 Tested |
| DHCP Discover Flooding | Flooding with DHCP discover requests | P1 | 🔨 Implemented |
| DHCP NAK Injection | Fraudulent DHCP denials | P1 | 🧪 Tested |
| DHCP Release Spoofing | Fraudulent lease releases | P2 | 📋 To implement |
| DHCP Option Manipulation | Manipulating configuration options | P2 | 📋 To implement |
| DHCP Relay / Option 82 Abuse | Abusing relay agent information | P2 | 📋 To implement |
| DHCP Snooping Binding Abuse | Manipulating snooping bindings | P3 | 📋 To implement |
| Rogue DHCPv6 Server | Unauthorized DHCPv6 server | P2 | 📋 To implement |
| DHCPv6 Starvation | Exhausting DHCPv6 resources | P2 | 📋 To implement |
| DHCPv6 Prefix Delegation Abuse | Abusing prefix delegation | P3 | 📋 To implement |

### IPv6 Neighbor Discovery & SLAAC (13)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| Neighbor Advertisement Spoofing | Forging NA messages | P2 | 📋 To implement |
| Neighbor Solicitation Spoofing | Fraudulent NS requests | P2 | 📋 To implement |
| NDP Cache Poisoning | Poisoning IPv6 neighbor caches | P2 | 📋 To implement |
| Rogue Router Advertisement | Unauthorized RA messages | P2 | 📋 To implement |
| Router Advertisement Flooding | Flooding with RA messages | P2 | 📋 To implement |
| Router Solicitation Flooding | Flooding with RS requests | P2 | 📋 To implement |
| SLAAC Prefix Spoofing | Advertising fraudulent prefixes | P2 | 📋 To implement |
| SLAAC Configuration Abuse | Manipulating stateless autoconfiguration | P2 | 📋 To implement |
| Duplicate Address Detection DoS | Interfering with duplicate address detection | P2 | 📋 To implement |
| NDP Neighbor Cache Exhaustion | Exhausting the neighbor cache | P2 | 📋 To implement |
| Redirect Spoofing | Forged ICMPv6 Redirect messages | P2 | 📋 To implement |
| IPv6 RA Guard Evasion | Attempts to evade RA Guard | P3 | 📋 To implement |
| MLD Spoofing / Flooding | Manipulating multicast listener membership | P2 | 📋 To implement |

### 802.1X / EAPOL / NAC (10)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| EAPOL Start Flooding | Flooding authentication start requests | P2 | 📋 To implement |
| EAPOL Logoff Spoofing | Spoofed session logoff | P2 | 📋 To implement |
| EAPOL Replay | Replaying captured authentication exchanges | P2 | 📋 To implement |
| 802.1X Identity Spoofing | Spoofing client identity | P2 | 📋 To implement |
| EAP Downgrade / Weak Method Abuse | Exploiting weak authentication methods | P3 | 📋 To implement |
| EAP Relay / Evil Authenticator | Relay or rogue authenticator | P3 | 📋 To implement |
| MAB Bypass / MAC Spoofing | Abusing MAC-based authentication | P1 | 📋 To implement |
| Unauthorized Mini-Switch / Hub | Connecting several clients to one access port | P2 | 📋 To implement |
| Post-Authentication Session Hijacking | Abusing an already authorized session | P3 | 📋 To implement |
| NAC VLAN Assignment Abuse | Manipulating authorization VLAN assignment | P3 | 📋 To implement |

### Discovery & Management Protocols (13)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| CDP Spoofing | Forged CDP advertisements | P1 | 🧪 Tested |
| CDP Flooding | Flooding with CDP messages | P1 | 🧪 Tested |
| LLDP Spoofing | Spoofing LLDP information | P1 | 🧪 Tested |
| LLDP Flooding | Flooding with LLDP advertisements | P1 | 🧪 Tested |
| MNDP Spoofing | Forged MikroTik Neighbor Discovery advertisements | P1 | 📋 To implement |
| MNDP Flooding | Flooding with MikroTik Neighbor Discovery advertisements | P1 | 📋 To implement |
| LLDP-MED Policy Spoofing | Forging LLDP-MED policies | P2 | 📋 To implement |
| VTP Spoofing | Spoofing VTP advertisements | P2 | 📋 To implement |
| VTP Revision Abuse | Manipulating VLAN database revisions | P2 | 📋 To implement |
| DTP Negotiation Abuse | Improper trunk negotiation | P1 | 📋 To implement |
| UDLD Spoofing | Manipulating unidirectional link detection | P3 | 📋 To implement |
| Ethernet OAM Spoofing | Spoofing IEEE 802.3ah messages | P3 | 📋 To implement |
| CFM / 802.1ag Spoofing | Manipulating connectivity fault management messages | P3 | 📋 To implement |

### Link Aggregation & Redundancy (7)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| LACP Spoofing | Forging LACPDUs | P2 | 📋 To implement |
| LACP Partner Impersonation | Impersonating a LAG partner | P2 | 📋 To implement |
| LACP Negotiation Flooding | Flooding LACP negotiations | P2 | 📋 To implement |
| LAG Misconfiguration Abuse | Exploiting incorrect link aggregations | P2 | 📋 To implement |
| PAgP Spoofing | Spoofing proprietary negotiation | P3 | 📋 To implement |
| MC-LAG / vPC Control Abuse | Manipulating multichassis redundancy | P3 | 📋 To implement |
| G.8032 ERPS Control Spoofing | Spoofing Ethernet ring control messages | P3 | 📋 To implement |

### L2 Multicast & Broadcast (8)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| Broadcast Storm | Broadcast traffic storm | P1 | 📋 To implement |
| Multicast Flooding | Multicast flooding | P1 | 📋 To implement |
| IGMP Spoofing | Spoofing IGMP memberships | P2 | 📋 To implement |
| IGMP Query Spoofing | Fraudulent multicast queries | P2 | 📋 To implement |
| IGMP Leave Spoofing | Fraudulent group leave | P2 | 📋 To implement |
| IGMP Snooping Table Exhaustion | Exhausting the group table | P3 | 📋 To implement |
| Unknown Multicast Flooding | Exploiting unknown multicast traffic | P2 | 📋 To implement |
| L2 Loop Amplification | Amplifying traffic through loops | P2 | 📋 To implement |

### MACsec / IEEE 802.1AE (6)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| MKA Peer Impersonation | Impersonating MKA participants | P3 | 📋 To implement |
| MKA Negotiation Disruption | Disrupting key agreement | P3 | 📋 To implement |
| MACsec Replay / PN Abuse | Testing anti-replay protection and packet numbers | P3 | 📋 To implement |
| MACsec Downgrade / Fail-Open Abuse | Exploiting permissive configurations | P3 | 📋 To implement |
| MACsec Key Rotation Disruption | Interfering with key rotation | P3 | 📋 To implement |
| MACsec SCI Spoofing | Spoofing secure channel identifiers | P3 | 📋 To implement |

### Carrier Ethernet & Data Center (10)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| PPPoE Discovery Flooding | Flooding PPPoE discovery | P2 | 📋 To implement |
| Rogue PPPoE Access Concentrator | Unauthorized PPPoE access concentrator | P2 | 📋 To implement |
| PPPoE Session Spoofing | Spoofing PPPoE sessions | P2 | 📋 To implement |
| 802.1ad QinQ Abuse | Manipulating provider VLANs | P2 | 📋 To implement |
| 802.1ah PBB Encapsulation Abuse | Manipulating backbone encapsulation | P3 | 📋 To implement |
| EVPN MAC/IP Advertisement Poisoning | Fraudulent MAC/IP advertisements | P3 | 📋 To implement |
| EVPN MAC Mobility Abuse | Mobility oscillation or spoofing | P3 | 📋 To implement |
| VXLAN VNI / VTEP Spoofing | Spoofing overlay elements | P3 | 📋 To implement |
| TRILL / SPB Control Abuse | Manipulating advanced bridging control | P3 | 📋 To implement |
| Provider Ethernet OAM Abuse | Manipulating provider maintenance operations | P3 | 📋 To implement |

### Industrial & Specialized L2 (9)

| Technique | Description | Priority | Status |
| --- | --- | --- | --- |
| PROFINET DCP Spoofing | Manipulating discovery and configuration | P3 | 📋 To implement |
| PROFINET DCP Identify Flooding | Flooding industrial discovery | P3 | 📋 To implement |
| EtherCAT Frame Injection | Injecting industrial frames | P3 | 📋 To implement |
| IEC 61850 GOOSE Spoofing | Spoofing GOOSE messages | P3 | 📋 To implement |
| IEC 61850 GOOSE Replay | Replaying GOOSE messages | P3 | 📋 To implement |
| HSR / PRP Redundancy Abuse | Manipulating industrial redundancy | P3 | 📋 To implement |
| PTP / IEEE 1588 Spoofing | Spoofing time synchronization | P3 | 📋 To implement |
| PTP Grandmaster Impersonation | Impersonating the grandmaster clock | P3 | 📋 To implement |
| 802.1AS gPTP Manipulation | Manipulating TSN time synchronization | P3 | 📋 To implement |

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
