<p align="center">
  <img src="assets/logo.png" width="240" alt="MACabre logo">
</p>

<h1 align="center">MACabre</h1>

<p align="center"><strong>Layer 2 network auditing suite</strong></p>

A **layer 2** network auditing suite written in Python with [Scapy](https://scapy.net/) and a desktop graphical interface, targeting Linux.

Inspired by Yersinia, but written from scratch (no GPL-licensed code inherited) and aimed at:

- Building custom (handcrafted) frames in a simple way.
- Running stress tests and protocol validation for layer 2 in labs and authorized audits.
- Complementing other tools such as `iperf` and `hping3`.
- Being installable as a desktop application and, in the future, integrated into security distributions such as Kali Linux.

## Status

🚧 MVP in development.

- ✅ PySide6 interface with an attack menu organized by category, protocol and attack (Layer 2 > DHCP > Starvation).
- ✅ **DHCP starvation**: sends DHCPDISCOVER frames with random MAC addresses, answers each DHCPOFFER with a DHCPREQUEST, and so creates leases until the pool is exhausted. Validated in the lab: 20 of 20 addresses leased, and a legitimate client gets no offer. It also has a "discover only" option and a "generate frames only" mode for testing without sending anything.
- ⏳ LLDP, CDP and Spanning Tree attacks appear in the menu, disabled, until implemented.
- ⏳ Handcrafted frame builder with preview.
- ⏳ Packaging as an installable / executable application.

Note on DHCP starvation: a server can take several seconds to send an OFFER (for example, after an ARP check), so the attack keeps answering OFFERs for up to 10 seconds after the last DISCOVER.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Icons and desktop integration

- `src/macabre/resources/icons/` contains the icon set used by the window and the application (PNG sizes and `.ico`).
- `packaging/linux/macabre.desktop` is the desktop entry, and `packaging/linux/icons/hicolor/` has the icon theme files it refers to. Copy them to `~/.local/share/applications/` and `~/.local/share/icons/hicolor/` (or the system equivalents) to add macabre to the application menu.
- To regenerate all icons from `assets/logo.png`: `python scripts/generate_icons.py` (requires Pillow).

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

**macOS:** the lab needs Linux network namespaces, so run it inside a Linux machine (for example, an [OrbStack](https://orbstack.dev/) Linux machine). Clone the repository inside that machine and create a new virtual environment there. Do not reuse the macOS `.venv`, because its binaries don't work on Linux.

Only run the attack on networks you own or are authorized to test. Never run it on production VLANs.

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

Undecided.
