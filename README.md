<p align="center">
  <img src="assets/logo.png" width="240" alt="macabre logo">
</p>

<h1 align="center">macabre</h1>

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
- ✅ **DHCP starvation**: generates DHCPDISCOVER frames with random MAC addresses. Includes a "generate frames only" mode for testing without sending anything.
- ⏳ LLDP, CDP and Spanning Tree attacks appear in the menu, disabled, until implemented.
- ⏳ Handcrafted frame builder with preview.
- ⏳ Packaging as an installable / executable application.

Note on DHCP starvation: this version only sends DHCPDISCOVER messages. Exhausting the full pool also requires answering DHCPOFFER messages with DHCPREQUEST, which is planned as the next improvement.

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
