<p align="center">
  <img src="assets/logo.png" width="240" alt="MACabre logo">
</p>

<h1 align="center">MACabre</h1>

<p align="center"><strong>Layer 2 network auditing suite</strong></p>

MACabre is a **layer 2** network auditing suite written in Python with [Scapy](https://scapy.net/) and a desktop graphical interface (PySide6), targeting Linux.

It is inspired by [Yersinia](https://github.com/tomac/yersinia), but written from scratch (no code from Yersinia is included) and designed as a modular framework: discovery, passive analysis, validation of existing protections, and authorized active tests.

Goals:

- Build custom (handcrafted) frames in a simple way.
- Run stress tests and protocol validation for layer 2 in labs and authorized audits.
- Complement other tools such as `iperf` and `hping3`.
- Be installable as a desktop application and, in the future, integrate into security distributions such as Kali Linux.

## Status

🚧 MVP in development.

- ✅ Desktop interface with an attack menu organized by category, protocol and attack.
- ✅ **DHCP starvation** (P1): full handshake (DISCOVER → OFFER → REQUEST). Validated in the lab: 20 of 20 addresses leased, and a legitimate client gets no offer. It also has a "discover only" option and a "generate frames only" mode.
- ✅ **MAC flooding** (P1): sends frames with random source MACs to fill the switch address table. Validated in the lab: 500 of 500 addresses learned, and 500 of 500 unknown-unicast frames received on the victim port. See [docs/specs/P1.md](docs/specs/P1.md).
- ✅ **MAC flapping** (P1): alternates frames with the same source MAC between two switch ports. Validated in the lab: the switch moved the target MAC 500 times for 500 frames, across 2 ports.
- ✅ **MAC address spoofing** (P1): sends frames with a target's source MAC, so the switch moves that address to the attacker's port. Validated in the lab: the switch port changed from `sw-t` to `sw-a`, and the attacker received 20 of 20 frames the target would have received.
- ✅ **MAC cloning** (P1): changes this interface's MAC address to an authorized device's, and restores it when stopped. Validated in the lab: with a port that admits only the authorized MAC, the attacker's own frames were dropped (0 of 20) and the cloned frames were delivered (20 of 20).
- ✅ **ARP spoofing** (P1): sends forged ARP replies that bind an IP address to this interface's MAC. Validated in the lab: the victim's ARP cache for the gateway changed from the gateway's MAC to the attacker's after 10 forged replies.
- ⏳ All other techniques in the catalog (see [Roadmap](#roadmap)).
- ⏳ Handcrafted frame builder with preview.
- ⏳ Operating modes and safety controls (see [Operating modes](#operating-modes)).
- ⏳ Packaging as an installable / executable application.

## Roadmap

The full catalog of techniques, with priorities and descriptions, is in [docs/attack-catalog.md](docs/attack-catalog.md). It currently lists 126 techniques in 13 families.

Priorities are the order in which techniques are developed within the roadmap:

| Phase | Focus | Techniques | Implemented |
| --- | --- | ---: | ---: |
| **P1** | Core: initial functionality | 41 | 6 |
| **P2** | Expansion | 45 | 0 |
| **P3** | Specialized features | 40 | 0 |

Specifications are written one phase at a time under `docs/specs/` (P1, then P2, then P3). The P1 specification is in [docs/specs/P1.md](docs/specs/P1.md). Each technique will document: protocol, technical reference, requirements, compatibility, expected behavior, evidence, impact, mitigations and execution risk level.

### Releases

Releases group the attack families by milestone. A release can contain P1, P2 and P3 techniques of its families.

| Release | Families | Status |
| --- | --- | --- |
| **MVP** | MAC address & CAM table, ARP, VLAN & 802.1Q, Spanning Tree, Discovery (CDP, LLDP) | In progress. DHCP starvation ships first as the initial attack (P1, DHCPv4 family). |
| **v0.2** | DHCPv4 & DHCPv6, IPv6 Neighbor Discovery & SLAAC | Planned |
| **v0.3** | 802.1X / EAPOL / NAC, Link Aggregation (LACP), L2 Multicast (IGMP) | Planned |
| **v0.4** | MACsec, Carrier Ethernet (PPPoE, QinQ) and Provider OAM | Planned |
| **v1.0** | Fuzzing, resilience testing and reporting; extensible framework | Planned |

Industrial protocols (PROFINET, EtherCAT, IEC 61850, PTP) and EVPN/VXLAN are specialized extensions, planned after v1.0.

### Extended scope (not yet scheduled)

Some scenarios are not pure Ethernet attacks but belong to the extended scope: LLMNR/NBT-NS/mDNS poisoning, VRRP/HSRP/CARP spoofing, IPv6-first attacks, Wake-on-LAN abuse, EtherType and malformed-frame fuzzing, jumbo frame and pause frame abuse, Priority Flow Control, 802.1p/PCP manipulation, and MACsec downgrade testing.

Wi-Fi (deauthentication, Evil Twin, WPA attacks) will be a separate module, because it is 802.11 and not IEEE 802.3 Ethernet.

## Operating modes

MACabre plans four operating modes, to avoid running disruptive tests by accident in production:

- **Passive**: observe and analyze traffic only. No frames are sent.
- **Safe Validation**: check configuration and existing protections without disrupting service.
- **Active Test**: send test frames within controlled limits.
- **Destructive Lab**: disruptive techniques. Available only when explicitly enabled, and intended for isolated lab networks.

The current MVP includes a confirmation dialog before sending frames and a "generate frames only" mode. The full mode system is part of the roadmap.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running

Sending raw frames requires root privileges:

```bash
sudo .venv/bin/macabre
```

To run the test suite (no root or display required):

```bash
pytest
```

## Lab test: DHCP starvation (Linux)

`scripts/lab/dhcp_starvation_lab.sh` builds an isolated lab with two Linux network namespaces: a `dnsmasq` DHCP server with a pool of 20 addresses, and an attacker that runs the full DHCP starvation handshake. It never touches your real network interfaces.

Requirements: Linux with root access, `iproute2`, `dnsmasq`, and the project environment.

```bash
sudo scripts/lab/dhcp_starvation_lab.sh               # 40 DISCOVER frames
sudo FRAMES=200 scripts/lab/dhcp_starvation_lab.sh    # more frames
```

The script prints what the attacker sent (DISCOVER, OFFER answered, REQUEST) and what the server did (DISCOVER, OFFER, REQUEST, ACK, distinct addresses leased). Then a legitimate client sends a DISCOVER, and the script reports whether it received an offer. It cleans up everything it created.

The lab sets `dnsmasq --no-ping` (no ARP check before each offer) and puts the attacker's interface in promiscuous mode. Both settings only speed up and simplify the lab, and are not part of the attack.

A MAC flooding lab is also available: `sudo scripts/lab/mac_flooding_lab.sh`. It uses a Linux bridge as the switch and reports the addresses it learns and the flooded frames received by the victim port.

An ARP spoofing lab is available too: `sudo scripts/lab/arp_spoofing_lab.sh`. It shows the victim's ARP cache for the gateway before and after the attack.

A MAC cloning lab is available too: `sudo scripts/lab/mac_cloning_lab.sh`. It emulates port security with one allowed MAC and checks the frames before and after cloning.

A MAC spoofing lab is available too: `sudo scripts/lab/mac_spoofing_lab.sh`. It shows the switch port of the target MAC before and after the spoofing.

A MAC flapping lab is available too: `sudo scripts/lab/mac_flapping_lab.sh`. It attaches two attacker ports to the same bridge and counts how many times the switch moves the target MAC between them.

**macOS:** the lab needs Linux network namespaces, so run it inside a Linux machine (for example, an [OrbStack](https://orbstack.dev/) Linux machine). Clone the repository inside that machine and create a new virtual environment there. Do not reuse the macOS `.venv`, because its binaries don't work on Linux.

Only run the attack on networks you own or are authorized to test. Never run it on production VLANs.

## Icons and desktop integration

- `src/macabre/resources/icons/` contains the icon set used by the window and the application (PNG sizes and `.ico`).
- `packaging/linux/macabre.desktop` is the desktop entry, and `packaging/linux/icons/hicolor/` has the icon theme files it refers to. Copy them to `~/.local/share/applications/` and `~/.local/share/icons/hicolor/` (or the system equivalents) to add MACabre to the application menu.
- To regenerate all icons from `assets/logo.png`: `python scripts/generate_icons.py` (requires Pillow).

## Intended use and legal notice

This tool generates traffic that can disrupt a network (DHCP address exhaustion, table flooding, STP topology changes, etc.).

**Use it only on networks you own or for which you have explicit written authorization.** The author is not responsible for misuse.

## Requirements

- Linux
- Python 3.10+
- [Scapy](https://scapy.net/) 2.5+
- [PySide6](https://doc.qt.io/qtforpython-6/) 6.6+
- Root privileges or `CAP_NET_RAW` to send raw frames

## License

MACabre is licensed under the [Apache License 2.0](LICENSE). You may use, copy, modify and distribute it, including commercially.

Copyright 2026 vitokosk8 Victor Bolaños Guerra.

If you distribute MACabre or a derivative work, keep the [NOTICE](NOTICE) file (or equivalent attribution) and credit the original author: **vitokosk8 Victor Bolaños Guerra, MACabre**. Apache 2.0 requires this for derivative works. Projects that are only inspired by MACabre are encouraged, but not required, to credit it.

## Acknowledgements

- [Yersinia](https://github.com/tomac/yersinia), the layer 2 attack framework that inspired this project.
- [Scapy](https://scapy.net/), for packet crafting and sending.
- [Qt for Python (PySide6)](https://doc.qt.io/qtforpython-6/), for the graphical interface.
