# Roadmap

The full catalog of techniques, with their priorities and descriptions, is in [attack-catalog.md](attack-catalog.md). The catalog also tracks how far each technique has come.

## Phases

Priorities are the order in which techniques are developed:

| Phase | Focus | Techniques |
| --- | --- | ---: |
| **P1** | Core: initial functionality | 41 |
| **P2** | Expansion | 45 |
| **P3** | Specialized features | 40 |

Specifications are written one phase at a time under [specs/](specs/), starting with [P1](specs/P1.md). Each technique documents its protocol, technical reference, requirements, compatibility, expected behavior, evidence, impact, mitigations and execution risk. Its theory lives in [attacks/](attacks/README.md).

## Releases

Releases group the attack families by milestone. A release can contain P1, P2 and P3 techniques of its families.

| Release | Families |
| --- | --- |
| **MVP** | MAC address & CAM table, ARP, VLAN & 802.1Q, Spanning Tree, Discovery (CDP, LLDP) |
| **v0.2** | DHCPv4 & DHCPv6, IPv6 Neighbor Discovery & SLAAC |
| **v0.3** | 802.1X / EAPOL / NAC, Link Aggregation (LACP), L2 Multicast (IGMP) |
| **v0.4** | MACsec, Carrier Ethernet (PPPoE, QinQ) and Provider OAM |
| **v1.0** | Fuzzing, resilience testing and reporting; extensible framework |

Industrial protocols (PROFINET, EtherCAT, IEC 61850, PTP) and EVPN/VXLAN are specialized extensions, planned after v1.0.

## Extended scope (not yet scheduled)

Some scenarios are not pure Ethernet attacks but belong to the extended scope: LLMNR/NBT-NS/mDNS poisoning, VRRP/HSRP/CARP spoofing, IPv6-first attacks, Wake-on-LAN abuse, EtherType and malformed-frame fuzzing, jumbo frame and pause frame abuse, Priority Flow Control, 802.1p/PCP manipulation, and MACsec downgrade testing.

Wi-Fi (deauthentication, Evil Twin, WPA attacks) will be a separate module, because it is 802.11 and not IEEE 802.3 Ethernet.

## Platforms (planned)

MACabre is developed and tested on Linux today. The goal is one installable program for Linux, macOS and Windows that sends attacks on the physical network interface of the machine it runs on. The labs are a development harness and are not part of how the tool runs.

| Platform | Frames sent through | Known constraints |
| --- | --- | --- |
| Linux | AF_PACKET on the physical interface | Root or `CAP_NET_RAW` required. |
| macOS | BPF on the physical interface | Root required. Ethernet only. Frames from a virtual machine's network adapter have not been shown to reach a physical switch, so field tests use the physical interface. |
| Windows | Npcap on the physical interface | Npcap must be installed. Its license restricts redistribution, so the terms must be checked before MACabre ships with it. Administrator rights required. Changing an adapter's MAC address depends on its driver, usually through registry settings. |

Wi-Fi is excluded from the Layer 2 attacks on every platform, because access points drop frames whose MAC address is not associated.

Packaging will use PyInstaller. It comes after the attacks are complete, and the package has to be tested on all three platforms.

## Operating modes (planned)

MACabre will have four operating modes, so that disruptive tests cannot run by accident in production:

- **Passive**: observe and analyze traffic only. No frames are sent.
- **Safe Validation**: check configuration and existing protections without disrupting service.
- **Active Test**: send test frames within controlled limits.
- **Destructive Lab**: disruptive techniques. Available only when explicitly enabled, and intended for isolated lab networks.

Each attack specification already names the mode it may run in.
