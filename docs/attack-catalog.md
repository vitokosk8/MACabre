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

## Techniques by category

### MAC Address & CAM Table (8)

| Technique | Description | Priority |
| --- | --- | --- |
| MAC Address Spoofing | Forging MAC addresses | P1 |
| MAC Flooding / CAM Overflow | Saturating the switch learning table | P1 |
| MAC Flapping | Repeated changes of a MAC address location | P1 |
| MAC Cloning | Cloning the identity of a device | P1 |
| Static MAC Impersonation | Impersonating a statically registered MAC | P2 |
| Port Security Exhaustion | Exhausting port security learning limits | P2 |
| MAC Move / Mobility Abuse | Abusing MAC mobility mechanisms | P2 |
| Unknown Unicast Flooding | Exploiting flooding of unknown destinations | P2 |

### ARP (9)

| Technique | Description | Priority |
| --- | --- | --- |
| ARP Spoofing | Forging ARP replies | P1 |
| ARP Cache Poisoning | Poisoning ARP caches | P1 |
| Gratuitous ARP Spoofing | Fraudulent gratuitous ARP announcements | P1 |
| ARP Request Flooding | Flooding with ARP requests | P1 |
| ARP Reply Flooding | Flooding with ARP replies | P1 |
| ARP Table Exhaustion | Exhausting the ARP table | P2 |
| Proxy ARP Abuse | Abusing proxy ARP responses | P2 |
| ARP-Based Gateway Impersonation | Impersonating the default gateway | P1 |
| ARP Inspection Evasion | Attempts to evade Dynamic ARP Inspection | P3 |

### VLAN & IEEE 802.1Q (10)

| Technique | Description | Priority |
| --- | --- | --- |
| Switch Spoofing / DTP Spoofing | Improper trunk negotiation | P1 |
| VLAN Hopping | Unauthorized access between VLANs | P1 |
| Double-Tagging | Double 802.1Q tag insertion | P1 |
| Native VLAN Abuse | Exploiting the native VLAN | P1 |
| VLAN Tag Injection | Injecting tagged frames | P1 |
| VLAN Translation Abuse | Abusing VLAN translation | P3 |
| QinQ / VLAN Stacking Abuse | Manipulating 802.1ad tags | P2 |
| VLAN Pruning Abuse | Exploiting VLAN propagation | P2 |
| Private VLAN Isolation Bypass | Bypassing private VLAN isolation | P2 |
| VLAN ID Exhaustion | Exhausting VLAN resources | P3 |

### Spanning Tree (STP / RSTP / MSTP / PVST+) (12)

| Technique | Description | Priority |
| --- | --- | --- |
| BPDU Spoofing | Forging BPDUs | P1 |
| Root Bridge Takeover | Malicious root bridge election | P1 |
| Root Bridge Impersonation | Impersonating the root bridge | P1 |
| Topology Change Flooding | Flooding topology change notifications | P1 |
| TCN Spoofing | Fraudulent topology change notifications | P1 |
| BPDU Flooding | Flooding with BPDUs | P1 |
| STP Path Cost Manipulation | Manipulating path costs | P2 |
| STP Priority Manipulation | Altering bridge priorities | P2 |
| STP Loop Induction | Inducing Layer 2 loops | P2 |
| BPDU Guard Trigger Abuse | Triggering port shutdowns through BPDU Guard | P2 |
| RSTP Proposal/Agreement Abuse | Manipulating RSTP convergence | P3 |
| MST Region Spoofing | Spoofing MST region parameters | P3 |

### DHCPv4 & DHCPv6 (13)

| Technique | Description | Priority |
| --- | --- | --- |
| DHCP Starvation | Exhausting the address pool | P1 |
| Rogue DHCP Server | Unauthorized DHCP server | P1 |
| DHCP Spoofing | Forging DHCP responses | P1 |
| DHCP Offer Flooding | Flooding with DHCP offers | P1 |
| DHCP Discover Flooding | Flooding with DHCP discover requests | P1 |
| DHCP NAK Injection | Fraudulent DHCP denials | P1 |
| DHCP Release Spoofing | Fraudulent lease releases | P2 |
| DHCP Option Manipulation | Manipulating configuration options | P2 |
| DHCP Relay / Option 82 Abuse | Abusing relay agent information | P2 |
| DHCP Snooping Binding Abuse | Manipulating snooping bindings | P3 |
| Rogue DHCPv6 Server | Unauthorized DHCPv6 server | P1 |
| DHCPv6 Starvation | Exhausting DHCPv6 resources | P2 |
| DHCPv6 Prefix Delegation Abuse | Abusing prefix delegation | P3 |

### IPv6 Neighbor Discovery & SLAAC (13)

| Technique | Description | Priority |
| --- | --- | --- |
| Neighbor Advertisement Spoofing | Forging NA messages | P1 |
| Neighbor Solicitation Spoofing | Fraudulent NS requests | P1 |
| NDP Cache Poisoning | Poisoning IPv6 neighbor caches | P1 |
| Rogue Router Advertisement | Unauthorized RA messages | P1 |
| Router Advertisement Flooding | Flooding with RA messages | P1 |
| Router Solicitation Flooding | Flooding with RS requests | P2 |
| SLAAC Prefix Spoofing | Advertising fraudulent prefixes | P1 |
| SLAAC Configuration Abuse | Manipulating stateless autoconfiguration | P1 |
| Duplicate Address Detection DoS | Interfering with duplicate address detection | P2 |
| NDP Neighbor Cache Exhaustion | Exhausting the neighbor cache | P2 |
| Redirect Spoofing | Forged ICMPv6 Redirect messages | P2 |
| IPv6 RA Guard Evasion | Attempts to evade RA Guard | P3 |
| MLD Spoofing / Flooding | Manipulating multicast listener membership | P2 |

### 802.1X / EAPOL / NAC (10)

| Technique | Description | Priority |
| --- | --- | --- |
| EAPOL Start Flooding | Flooding authentication start requests | P2 |
| EAPOL Logoff Spoofing | Spoofed session logoff | P2 |
| EAPOL Replay | Replaying captured authentication exchanges | P2 |
| 802.1X Identity Spoofing | Spoofing client identity | P2 |
| EAP Downgrade / Weak Method Abuse | Exploiting weak authentication methods | P3 |
| EAP Relay / Evil Authenticator | Relay or rogue authenticator | P3 |
| MAB Bypass / MAC Spoofing | Abusing MAC-based authentication | P1 |
| Unauthorized Mini-Switch / Hub | Connecting several clients to one access port | P2 |
| Post-Authentication Session Hijacking | Abusing an already authorized session | P3 |
| NAC VLAN Assignment Abuse | Manipulating authorization VLAN assignment | P3 |

### Discovery & Management Protocols (11)

| Technique | Description | Priority |
| --- | --- | --- |
| CDP Spoofing | Forged CDP advertisements | P1 |
| CDP Flooding | Flooding with CDP messages | P2 |
| LLDP Spoofing | Spoofing LLDP information | P1 |
| LLDP Flooding | Flooding with LLDP advertisements | P2 |
| LLDP-MED Policy Spoofing | Forging LLDP-MED policies | P2 |
| VTP Spoofing | Spoofing VTP advertisements | P2 |
| VTP Revision Abuse | Manipulating VLAN database revisions | P2 |
| DTP Negotiation Abuse | Improper trunk negotiation | P1 |
| UDLD Spoofing | Manipulating unidirectional link detection | P3 |
| Ethernet OAM Spoofing | Spoofing IEEE 802.3ah messages | P3 |
| CFM / 802.1ag Spoofing | Manipulating connectivity fault management messages | P3 |

### Link Aggregation & Redundancy (7)

| Technique | Description | Priority |
| --- | --- | --- |
| LACP Spoofing | Forging LACPDUs | P2 |
| LACP Partner Impersonation | Impersonating a LAG partner | P2 |
| LACP Negotiation Flooding | Flooding LACP negotiations | P2 |
| LAG Misconfiguration Abuse | Exploiting incorrect link aggregations | P2 |
| PAgP Spoofing | Spoofing proprietary negotiation | P3 |
| MC-LAG / vPC Control Abuse | Manipulating multichassis redundancy | P3 |
| G.8032 ERPS Control Spoofing | Spoofing Ethernet ring control messages | P3 |

### L2 Multicast & Broadcast (8)

| Technique | Description | Priority |
| --- | --- | --- |
| Broadcast Storm | Broadcast traffic storm | P1 |
| Multicast Flooding | Multicast flooding | P1 |
| IGMP Spoofing | Spoofing IGMP memberships | P2 |
| IGMP Query Spoofing | Fraudulent multicast queries | P2 |
| IGMP Leave Spoofing | Fraudulent group leave | P2 |
| IGMP Snooping Table Exhaustion | Exhausting the group table | P3 |
| Unknown Multicast Flooding | Exploiting unknown multicast traffic | P2 |
| L2 Loop Amplification | Amplifying traffic through loops | P2 |

### MACsec / IEEE 802.1AE (6)

| Technique | Description | Priority |
| --- | --- | --- |
| MKA Peer Impersonation | Impersonating MKA participants | P3 |
| MKA Negotiation Disruption | Disrupting key agreement | P3 |
| MACsec Replay / PN Abuse | Testing anti-replay protection and packet numbers | P3 |
| MACsec Downgrade / Fail-Open Abuse | Exploiting permissive configurations | P3 |
| MACsec Key Rotation Disruption | Interfering with key rotation | P3 |
| MACsec SCI Spoofing | Spoofing secure channel identifiers | P3 |

### Carrier Ethernet & Data Center (10)

| Technique | Description | Priority |
| --- | --- | --- |
| PPPoE Discovery Flooding | Flooding PPPoE discovery | P2 |
| Rogue PPPoE Access Concentrator | Unauthorized PPPoE access concentrator | P2 |
| PPPoE Session Spoofing | Spoofing PPPoE sessions | P2 |
| 802.1ad QinQ Abuse | Manipulating provider VLANs | P2 |
| 802.1ah PBB Encapsulation Abuse | Manipulating backbone encapsulation | P3 |
| EVPN MAC/IP Advertisement Poisoning | Fraudulent MAC/IP advertisements | P3 |
| EVPN MAC Mobility Abuse | Mobility oscillation or spoofing | P3 |
| VXLAN VNI / VTEP Spoofing | Spoofing overlay elements | P3 |
| TRILL / SPB Control Abuse | Manipulating advanced bridging control | P3 |
| Provider Ethernet OAM Abuse | Manipulating provider maintenance operations | P3 |

### Industrial & Specialized L2 (9)

| Technique | Description | Priority |
| --- | --- | --- |
| PROFINET DCP Spoofing | Manipulating discovery and configuration | P3 |
| PROFINET DCP Identify Flooding | Flooding industrial discovery | P3 |
| EtherCAT Frame Injection | Injecting industrial frames | P3 |
| IEC 61850 GOOSE Spoofing | Spoofing GOOSE messages | P3 |
| IEC 61850 GOOSE Replay | Replaying GOOSE messages | P3 |
| HSR / PRP Redundancy Abuse | Manipulating industrial redundancy | P3 |
| PTP / IEEE 1588 Spoofing | Spoofing time synchronization | P3 |
| PTP Grandmaster Impersonation | Impersonating the grandmaster clock | P3 |
| 802.1AS gPTP Manipulation | Manipulating TSN time synchronization | P3 |

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
