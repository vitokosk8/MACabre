<p align="center">
  <img src="assets/logo.png" width="220" alt="MACabre logo">
</p>

<h1 align="center">MACabre</h1>

<p align="center">
  <strong>A Layer 2 network auditing suite with a desktop interface.</strong><br>
  Find out what your switches and hosts trust before someone else does.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License: Apache 2.0"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/platform-Linux-lightgrey" alt="Linux">
</p>

---

MACabre sends the frames that Ethernet, ARP and DHCP take for granted, so you can check how your network reacts when something misbehaves. It is written in Python with [Scapy](https://scapy.net/) and a [PySide6](https://doc.qt.io/qtforpython-6/) interface, and it is inspired by [Yersinia](https://github.com/tomac/yersinia), written from scratch.

It is made for labs, authorized audits, and anyone who has ever wondered why a switch without port security is such a trusting friend.

## What's inside

- **Handcrafted frames.** Build and send Ethernet, ARP and DHCP frames from the desktop interface or from Python.
- **An attack menu** organized by family, with one panel per attack, a log, and a "generate frames only" mode to see what will be sent first.
- **Lab scripts.** Every attack has a script that reproduces it on a small test network, runs it and reports what the switch and the hosts did. The labs are how each attack is checked the same way every time.
- **Documentation for every attack:** the theory, the protocols involved, and an audit specification with expected behavior, evidence, mitigations and execution risk.

## Where to look

| I want to know... | Read |
| --- | --- |
| Which attacks exist, and how far each one has come | [Attack catalog](docs/attack-catalog.md) |
| What an attack abuses, and why it works | [Attack theory](docs/attacks/README.md) |
| What an audit should check, step by step | [P1 specifications](docs/specs/P1.md) |
| How to run the labs | [Labs](docs/labs.md) |
| Where the project is going | [Roadmap](docs/roadmap.md) |

## Quick start

You need Linux, Python 3.10 or newer, and root privileges (or `CAP_NET_RAW`) to send frames.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
sudo .venv/bin/macabre
```

To run the test suite, which needs neither root nor a display:

```bash
pytest
```

> **Platforms:** MACabre is tested on Linux today, and each release also publishes Windows and macOS builds. Attacks send frames on the physical interface of the machine they run on. The macOS build needs root: see [running on macOS](docs/macos.md). See the [roadmap](docs/roadmap.md).

## Use it responsibly

MACabre can disrupt a network on purpose. That is the point of an audit, and also the reason for a few rules:

- Only use it on networks you own, or on networks where you have **written authorization** to test.
- Never run an active attack on a production VLAN without a plan and a rollback.
- Start with "generate frames only" to see what will leave your interface.

The author is not responsible for misuse.

## License

MACabre is licensed under the [Apache License 2.0](LICENSE). You may use, copy, modify and distribute it, including commercially.

If you distribute MACabre or a derivative work, keep the [NOTICE](NOTICE) file (or an equivalent attribution) and credit the original author: **vitokosk8 Victor Bolaños Guerra, MACabre**. Projects that are only inspired by MACabre are welcome to credit it too.

Copyright 2026 vitokosk8 Victor Bolaños Guerra.

## Acknowledgements

- [Yersinia](https://github.com/tomac/yersinia), the layer 2 attack framework that inspired this project.
- [Scapy](https://scapy.net/), for packet crafting and sending.
- [Qt for Python (PySide6)](https://doc.qt.io/qtforpython-6/), for the graphical interface.
