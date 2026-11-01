# Attack theory

Each technique in the [attack catalog](../attack-catalog.md) has its own document, grouped by family. A document explains the idea behind the attack, not the audit steps alone:

- **What it abuses**: the trust or design flaw the attack relies on.
- **Protocols involved**: which standards and mechanisms take part.
- **Goal**: what an attacker gains.
- **How it works**: the sequence of events, in plain words.
- **What an auditor checks**: the questions an audit answers.
- **Defenses**: what stops the attack.

The audit side of the core techniques (requirements, expected behavior, evidence, execution risk) lives in the [P1 specifications](../specs/P1.md). The labs that reproduce some attacks are listed in [labs](../labs.md). The catalog shows the priority and the status of every technique.

## MAC Address & CAM Table

How switches learn the MAC addresses of hosts, and store them per port.

| Technique | Priority | Theory |
| --- | --- | --- |
| MAC Address Spoofing | P1 | [mac-address-spoofing](mac-address-cam-table/mac-address-spoofing.md) |
| MAC Flooding / CAM Overflow | P1 | [mac-flooding](mac-address-cam-table/mac-flooding.md) |
| MAC Flapping | P1 | [mac-flapping](mac-address-cam-table/mac-flapping.md) |
| MAC Cloning | P1 | [mac-cloning](mac-address-cam-table/mac-cloning.md) |
| Static MAC Impersonation | P2 | [static-mac-impersonation](mac-address-cam-table/static-mac-impersonation.md) |
| Port Security Exhaustion | P2 | [port-security-exhaustion](mac-address-cam-table/port-security-exhaustion.md) |
| MAC Move / Mobility Abuse | P2 | [mac-move-mobility-abuse](mac-address-cam-table/mac-move-mobility-abuse.md) |
| Unknown Unicast Flooding | P2 | [unknown-unicast-flooding](mac-address-cam-table/unknown-unicast-flooding.md) |

## ARP

The Address Resolution Protocol maps IPv4 addresses to MAC addresses on a segment, and trusts what it hears.

| Technique | Priority | Theory |
| --- | --- | --- |
| ARP Spoofing | P1 | [arp-spoofing](arp/arp-spoofing.md) |
| ARP Cache Poisoning | P1 | [arp-cache-poisoning](arp/arp-cache-poisoning.md) |
| Gratuitous ARP Spoofing | P1 | [gratuitous-arp-spoofing](arp/gratuitous-arp-spoofing.md) |
| ARP Request Flooding | P1 | [arp-request-flooding](arp/arp-request-flooding.md) |
| ARP Reply Flooding | P1 | [arp-reply-flooding](arp/arp-reply-flooding.md) |
| ARP Table Exhaustion | P2 | [arp-table-exhaustion](arp/arp-table-exhaustion.md) |
| Proxy ARP Abuse | P2 | [proxy-arp-abuse](arp/proxy-arp-abuse.md) |
| ARP-Based Gateway Impersonation | P1 | [arp-based-gateway-impersonation](arp/arp-based-gateway-impersonation.md) |
| ARP Inspection Evasion | P3 | [arp-inspection-evasion](arp/arp-inspection-evasion.md) |

## VLAN & IEEE 802.1Q

VLAN tags and trunks separate traffic logically on a shared switch. These attacks cross that separation.

| Technique | Priority | Theory |
| --- | --- | --- |
| Switch Spoofing / DTP Spoofing | P1 | [switch-spoofing-dtp-spoofing](vlan-802-1q/switch-spoofing-dtp-spoofing.md) |
| VLAN Hopping | P1 | [vlan-hopping](vlan-802-1q/vlan-hopping.md) |
| Double-Tagging | P1 | [double-tagging](vlan-802-1q/double-tagging.md) |
| Native VLAN Abuse | P1 | [native-vlan-abuse](vlan-802-1q/native-vlan-abuse.md) |
| VLAN Tag Injection | P1 | [vlan-tag-injection](vlan-802-1q/vlan-tag-injection.md) |
| VLAN Translation Abuse | P3 | [vlan-translation-abuse](vlan-802-1q/vlan-translation-abuse.md) |
| QinQ / VLAN Stacking Abuse | P2 | [qinq-vlan-stacking-abuse](vlan-802-1q/qinq-vlan-stacking-abuse.md) |
| VLAN Pruning Abuse | P2 | [vlan-pruning-abuse](vlan-802-1q/vlan-pruning-abuse.md) |
| Private VLAN Isolation Bypass | P2 | [private-vlan-isolation-bypass](vlan-802-1q/private-vlan-isolation-bypass.md) |
| VLAN ID Exhaustion | P3 | [vlan-id-exhaustion](vlan-802-1q/vlan-id-exhaustion.md) |

## Spanning Tree (STP / RSTP / MSTP / PVST+)

Spanning Tree removes loops from a bridged network by blocking ports. Its messages are not authenticated.

| Technique | Priority | Theory |
| --- | --- | --- |
| BPDU Spoofing | P1 | [bpdu-spoofing](spanning-tree/bpdu-spoofing.md) |
| Root Bridge Takeover | P1 | [root-bridge-takeover](spanning-tree/root-bridge-takeover.md) |
| Root Bridge Impersonation | P1 | [root-bridge-impersonation](spanning-tree/root-bridge-impersonation.md) |
| Topology Change Flooding | P1 | [topology-change-flooding](spanning-tree/topology-change-flooding.md) |
| TCN Spoofing | P1 | [tcn-spoofing](spanning-tree/tcn-spoofing.md) |
| BPDU Flooding | P1 | [bpdu-flooding](spanning-tree/bpdu-flooding.md) |
| STP Path Cost Manipulation | P2 | [stp-path-cost-manipulation](spanning-tree/stp-path-cost-manipulation.md) |
| STP Priority Manipulation | P2 | [stp-priority-manipulation](spanning-tree/stp-priority-manipulation.md) |
| STP Loop Induction | P2 | [stp-loop-induction](spanning-tree/stp-loop-induction.md) |
| BPDU Guard Trigger Abuse | P2 | [bpdu-guard-trigger-abuse](spanning-tree/bpdu-guard-trigger-abuse.md) |
| RSTP Proposal/Agreement Abuse | P3 | [rstp-proposal-agreement-abuse](spanning-tree/rstp-proposal-agreement-abuse.md) |
| MST Region Spoofing | P3 | [mst-region-spoofing](spanning-tree/mst-region-spoofing.md) |

## DHCPv4 & DHCPv6

DHCP gives hosts their addresses and configuration. Its trust model is based on who answers first.

| Technique | Priority | Theory |
| --- | --- | --- |
| DHCP Starvation | P1 | [dhcp-starvation](dhcpv4-dhcpv6/dhcp-starvation.md) |
| Rogue DHCP Server | P1 | [rogue-dhcp-server](dhcpv4-dhcpv6/rogue-dhcp-server.md) |
| DHCP Spoofing | P1 | [dhcp-spoofing](dhcpv4-dhcpv6/dhcp-spoofing.md) |
| DHCP Offer Flooding | P1 | [dhcp-offer-flooding](dhcpv4-dhcpv6/dhcp-offer-flooding.md) |
| DHCP Discover Flooding | P1 | [dhcp-discover-flooding](dhcpv4-dhcpv6/dhcp-discover-flooding.md) |
| DHCP NAK Injection | P1 | [dhcp-nak-injection](dhcpv4-dhcpv6/dhcp-nak-injection.md) |
| DHCP Release Spoofing | P2 | [dhcp-release-spoofing](dhcpv4-dhcpv6/dhcp-release-spoofing.md) |
| DHCP Option Manipulation | P2 | [dhcp-option-manipulation](dhcpv4-dhcpv6/dhcp-option-manipulation.md) |
| DHCP Relay / Option 82 Abuse | P2 | [dhcp-relay-option-82-abuse](dhcpv4-dhcpv6/dhcp-relay-option-82-abuse.md) |
| DHCP Snooping Binding Abuse | P3 | [dhcp-snooping-binding-abuse](dhcpv4-dhcpv6/dhcp-snooping-binding-abuse.md) |
| Rogue DHCPv6 Server | P1 | [rogue-dhcpv6-server](dhcpv4-dhcpv6/rogue-dhcpv6-server.md) |
| DHCPv6 Starvation | P2 | [dhcpv6-starvation](dhcpv4-dhcpv6/dhcpv6-starvation.md) |
| DHCPv6 Prefix Delegation Abuse | P3 | [dhcpv6-prefix-delegation-abuse](dhcpv4-dhcpv6/dhcpv6-prefix-delegation-abuse.md) |

## IPv6 Neighbor Discovery & SLAAC

IPv6 uses Neighbor Discovery in place of ARP, and router advertisements for addresses and routes.

| Technique | Priority | Theory |
| --- | --- | --- |
| Neighbor Advertisement Spoofing | P1 | [neighbor-advertisement-spoofing](ipv6-nd-slaac/neighbor-advertisement-spoofing.md) |
| Neighbor Solicitation Spoofing | P1 | [neighbor-solicitation-spoofing](ipv6-nd-slaac/neighbor-solicitation-spoofing.md) |
| NDP Cache Poisoning | P1 | [ndp-cache-poisoning](ipv6-nd-slaac/ndp-cache-poisoning.md) |
| Rogue Router Advertisement | P1 | [rogue-router-advertisement](ipv6-nd-slaac/rogue-router-advertisement.md) |
| Router Advertisement Flooding | P1 | [router-advertisement-flooding](ipv6-nd-slaac/router-advertisement-flooding.md) |
| Router Solicitation Flooding | P2 | [router-solicitation-flooding](ipv6-nd-slaac/router-solicitation-flooding.md) |
| SLAAC Prefix Spoofing | P1 | [slaac-prefix-spoofing](ipv6-nd-slaac/slaac-prefix-spoofing.md) |
| SLAAC Configuration Abuse | P1 | [slaac-configuration-abuse](ipv6-nd-slaac/slaac-configuration-abuse.md) |
| Duplicate Address Detection DoS | P2 | [duplicate-address-detection-dos](ipv6-nd-slaac/duplicate-address-detection-dos.md) |
| NDP Neighbor Cache Exhaustion | P2 | [ndp-neighbor-cache-exhaustion](ipv6-nd-slaac/ndp-neighbor-cache-exhaustion.md) |
| Redirect Spoofing | P2 | [redirect-spoofing](ipv6-nd-slaac/redirect-spoofing.md) |
| IPv6 RA Guard Evasion | P3 | [ipv6-ra-guard-evasion](ipv6-nd-slaac/ipv6-ra-guard-evasion.md) |
| MLD Spoofing / Flooding | P2 | [mld-spoofing-flooding](ipv6-nd-slaac/mld-spoofing-flooding.md) |

## 802.1X / EAPOL / NAC

Port-based authentication and the network access control built around it.

| Technique | Priority | Theory |
| --- | --- | --- |
| EAPOL Start Flooding | P2 | [eapol-start-flooding](802-1x-eapol-nac/eapol-start-flooding.md) |
| EAPOL Logoff Spoofing | P2 | [eapol-logoff-spoofing](802-1x-eapol-nac/eapol-logoff-spoofing.md) |
| EAPOL Replay | P2 | [eapol-replay](802-1x-eapol-nac/eapol-replay.md) |
| 802.1X Identity Spoofing | P2 | [802-1x-identity-spoofing](802-1x-eapol-nac/802-1x-identity-spoofing.md) |
| EAP Downgrade / Weak Method Abuse | P3 | [eap-downgrade-weak-method-abuse](802-1x-eapol-nac/eap-downgrade-weak-method-abuse.md) |
| EAP Relay / Evil Authenticator | P3 | [eap-relay-evil-authenticator](802-1x-eapol-nac/eap-relay-evil-authenticator.md) |
| MAB Bypass / MAC Spoofing | P1 | [mab-bypass-mac-spoofing](802-1x-eapol-nac/mab-bypass-mac-spoofing.md) |
| Unauthorized Mini-Switch / Hub | P2 | [unauthorized-mini-switch-hub](802-1x-eapol-nac/unauthorized-mini-switch-hub.md) |
| Post-Authentication Session Hijacking | P3 | [post-authentication-session-hijacking](802-1x-eapol-nac/post-authentication-session-hijacking.md) |
| NAC VLAN Assignment Abuse | P3 | [nac-vlan-assignment-abuse](802-1x-eapol-nac/nac-vlan-assignment-abuse.md) |

## Discovery & Management Protocols

Protocols that announce devices, settings and link health to their neighbors.

| Technique | Priority | Theory |
| --- | --- | --- |
| CDP Spoofing | P1 | [cdp-spoofing](discovery-management/cdp-spoofing.md) |
| CDP Flooding | P2 | [cdp-flooding](discovery-management/cdp-flooding.md) |
| LLDP Spoofing | P1 | [lldp-spoofing](discovery-management/lldp-spoofing.md) |
| LLDP Flooding | P2 | [lldp-flooding](discovery-management/lldp-flooding.md) |
| LLDP-MED Policy Spoofing | P2 | [lldp-med-policy-spoofing](discovery-management/lldp-med-policy-spoofing.md) |
| VTP Spoofing | P2 | [vtp-spoofing](discovery-management/vtp-spoofing.md) |
| VTP Revision Abuse | P2 | [vtp-revision-abuse](discovery-management/vtp-revision-abuse.md) |
| DTP Negotiation Abuse | P1 | [dtp-negotiation-abuse](discovery-management/dtp-negotiation-abuse.md) |
| UDLD Spoofing | P3 | [udld-spoofing](discovery-management/udld-spoofing.md) |
| Ethernet OAM Spoofing | P3 | [ethernet-oam-spoofing](discovery-management/ethernet-oam-spoofing.md) |
| CFM / 802.1ag Spoofing | P3 | [cfm-802-1ag-spoofing](discovery-management/cfm-802-1ag-spoofing.md) |

## Link Aggregation & Redundancy

Protocols that bundle links, or protect them against failure, by negotiating with the other end.

| Technique | Priority | Theory |
| --- | --- | --- |
| LACP Spoofing | P2 | [lacp-spoofing](link-aggregation-redundancy/lacp-spoofing.md) |
| LACP Partner Impersonation | P2 | [lacp-partner-impersonation](link-aggregation-redundancy/lacp-partner-impersonation.md) |
| LACP Negotiation Flooding | P2 | [lacp-negotiation-flooding](link-aggregation-redundancy/lacp-negotiation-flooding.md) |
| LAG Misconfiguration Abuse | P2 | [lag-misconfiguration-abuse](link-aggregation-redundancy/lag-misconfiguration-abuse.md) |
| PAgP Spoofing | P3 | [pagp-spoofing](link-aggregation-redundancy/pagp-spoofing.md) |
| MC-LAG / vPC Control Abuse | P3 | [mc-lag-vpc-control-abuse](link-aggregation-redundancy/mc-lag-vpc-control-abuse.md) |
| G.8032 ERPS Control Spoofing | P3 | [g-8032-erps-control-spoofing](link-aggregation-redundancy/g-8032-erps-control-spoofing.md) |

## L2 Multicast & Broadcast

Traffic that reaches many hosts at once, and the snooping that tries to limit it.

| Technique | Priority | Theory |
| --- | --- | --- |
| Broadcast Storm | P1 | [broadcast-storm](l2-multicast-broadcast/broadcast-storm.md) |
| Multicast Flooding | P1 | [multicast-flooding](l2-multicast-broadcast/multicast-flooding.md) |
| IGMP Spoofing | P2 | [igmp-spoofing](l2-multicast-broadcast/igmp-spoofing.md) |
| IGMP Query Spoofing | P2 | [igmp-query-spoofing](l2-multicast-broadcast/igmp-query-spoofing.md) |
| IGMP Leave Spoofing | P2 | [igmp-leave-spoofing](l2-multicast-broadcast/igmp-leave-spoofing.md) |
| IGMP Snooping Table Exhaustion | P3 | [igmp-snooping-table-exhaustion](l2-multicast-broadcast/igmp-snooping-table-exhaustion.md) |
| Unknown Multicast Flooding | P2 | [unknown-multicast-flooding](l2-multicast-broadcast/unknown-multicast-flooding.md) |
| L2 Loop Amplification | P2 | [l2-loop-amplification](l2-multicast-broadcast/l2-loop-amplification.md) |

## MACsec / IEEE 802.1AE

Encryption of Ethernet links, and the key agreement that feeds it.

| Technique | Priority | Theory |
| --- | --- | --- |
| MKA Peer Impersonation | P3 | [mka-peer-impersonation](macsec-802-1ae/mka-peer-impersonation.md) |
| MKA Negotiation Disruption | P3 | [mka-negotiation-disruption](macsec-802-1ae/mka-negotiation-disruption.md) |
| MACsec Replay / PN Abuse | P3 | [macsec-replay-pn-abuse](macsec-802-1ae/macsec-replay-pn-abuse.md) |
| MACsec Downgrade / Fail-Open Abuse | P3 | [macsec-downgrade-fail-open-abuse](macsec-802-1ae/macsec-downgrade-fail-open-abuse.md) |
| MACsec Key Rotation Disruption | P3 | [macsec-key-rotation-disruption](macsec-802-1ae/macsec-key-rotation-disruption.md) |
| MACsec SCI Spoofing | P3 | [macsec-sci-spoofing](macsec-802-1ae/macsec-sci-spoofing.md) |

## Carrier Ethernet & Data Center

Provider networks, PPPoE sessions and data center fabrics built on Ethernet.

| Technique | Priority | Theory |
| --- | --- | --- |
| PPPoE Discovery Flooding | P2 | [pppoe-discovery-flooding](carrier-ethernet-datacenter/pppoe-discovery-flooding.md) |
| Rogue PPPoE Access Concentrator | P2 | [rogue-pppoe-access-concentrator](carrier-ethernet-datacenter/rogue-pppoe-access-concentrator.md) |
| PPPoE Session Spoofing | P2 | [pppoe-session-spoofing](carrier-ethernet-datacenter/pppoe-session-spoofing.md) |
| 802.1ad QinQ Abuse | P2 | [802-1ad-qinq-abuse](carrier-ethernet-datacenter/802-1ad-qinq-abuse.md) |
| 802.1ah PBB Encapsulation Abuse | P3 | [802-1ah-pbb-encapsulation-abuse](carrier-ethernet-datacenter/802-1ah-pbb-encapsulation-abuse.md) |
| EVPN MAC/IP Advertisement Poisoning | P3 | [evpn-mac-ip-advertisement-poisoning](carrier-ethernet-datacenter/evpn-mac-ip-advertisement-poisoning.md) |
| EVPN MAC Mobility Abuse | P3 | [evpn-mac-mobility-abuse](carrier-ethernet-datacenter/evpn-mac-mobility-abuse.md) |
| VXLAN VNI / VTEP Spoofing | P3 | [vxlan-vni-vtep-spoofing](carrier-ethernet-datacenter/vxlan-vni-vtep-spoofing.md) |
| TRILL / SPB Control Abuse | P3 | [trill-spb-control-abuse](carrier-ethernet-datacenter/trill-spb-control-abuse.md) |
| Provider Ethernet OAM Abuse | P3 | [provider-ethernet-oam-abuse](carrier-ethernet-datacenter/provider-ethernet-oam-abuse.md) |

## Industrial & Specialized L2

Ethernet protocols used in industrial control, substations and precise timing.

| Technique | Priority | Theory |
| --- | --- | --- |
| PROFINET DCP Spoofing | P3 | [profinet-dcp-spoofing](industrial-specialized-l2/profinet-dcp-spoofing.md) |
| PROFINET DCP Identify Flooding | P3 | [profinet-dcp-identify-flooding](industrial-specialized-l2/profinet-dcp-identify-flooding.md) |
| EtherCAT Frame Injection | P3 | [ethercat-frame-injection](industrial-specialized-l2/ethercat-frame-injection.md) |
| IEC 61850 GOOSE Spoofing | P3 | [iec-61850-goose-spoofing](industrial-specialized-l2/iec-61850-goose-spoofing.md) |
| IEC 61850 GOOSE Replay | P3 | [iec-61850-goose-replay](industrial-specialized-l2/iec-61850-goose-replay.md) |
| HSR / PRP Redundancy Abuse | P3 | [hsr-prp-redundancy-abuse](industrial-specialized-l2/hsr-prp-redundancy-abuse.md) |
| PTP / IEEE 1588 Spoofing | P3 | [ptp-ieee-1588-spoofing](industrial-specialized-l2/ptp-ieee-1588-spoofing.md) |
| PTP Grandmaster Impersonation | P3 | [ptp-grandmaster-impersonation](industrial-specialized-l2/ptp-grandmaster-impersonation.md) |
| 802.1AS gPTP Manipulation | P3 | [802-1as-gptp-manipulation](industrial-specialized-l2/802-1as-gptp-manipulation.md) |
