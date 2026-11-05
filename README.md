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
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey" alt="Linux, macOS and Windows">
</p>

---

MACabre sends the frames that Ethernet, ARP and DHCP take for granted, so you can check how your network reacts when something misbehaves. It is written in Python with [Scapy](https://scapy.net/) and a [PySide6](https://doc.qt.io/qtforpython-6/) interface, and it is inspired by [Yersinia](https://github.com/tomac/yersinia), written from scratch.

It is made for labs, authorized audits, and anyone who has ever wondered why a switch without port security is such a trusting friend.

> **Disclaimer: authorized use only.** MACabre can disrupt a network on purpose. Use it only on networks you own or where you have **written authorization** to test. The author is not responsible for misuse. Read the [full disclaimer](#disclaimer) before you run any attack.

## What's inside

- **Handcrafted frames.** Build and send Ethernet, ARP and DHCP frames from the desktop interface or from Python.
- **An attack menu** organized by family, with one panel per attack, a log, and a "generate frames only" mode to see what will be sent first.
- **Lab scripts.** Every attack has a script that reproduces it on a small test network, runs it and reports what the switch and the hosts did. The labs are how each attack is checked the same way every time.
- **Validated in labs, not on hardware.** Each lab reproduces an attack in isolated network namespaces on Linux. Results on real vendor switches are not part of this project yet.
- **Documentation for every attack:** the theory, the protocols involved, and an audit specification with expected behavior, evidence, mitigations and execution risk.

## Where to look

| I want to know... | Read |
| --- | --- |
| Which attacks exist, and how far each one has come | [Attack catalog](docs/attack-catalog.md) |
| What an attack abuses, and why it works | [Attack theory](docs/attacks/README.md) |
| What an audit should check, step by step | [P1 specifications](docs/specs/P1.md) |
| How to run the labs | [Labs](docs/labs.md) |
| Where the project is going | [Roadmap](docs/roadmap.md) |

## Download

Prebuilt packages for each release are on the [releases page](https://github.com/vitokosk8/MACabre/releases). The latest is [0.2.0](https://github.com/vitokosk8/MACabre/releases/tag/v0.2.0): Linux x86_64 (full suite), macOS Apple silicon and Windows x64 (desktop interface). Check the platform status below before you rely on a build.

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

> **Platforms:**
> - **Linux (x86_64):** the full suite. Attacks and lab scripts run here. The labs need root, `iproute2`, `nftables`, `dnsmasq` and `lldpd`.
> - **macOS (Apple silicon):** the desktop interface opens, and the DHCP starvation and MAC flooding attacks have been run from it. Attacks that depend on Linux tools (`ip`, network namespaces) are not yet supported. The macOS build needs root: see [running on macOS](docs/macos.md).
> - **Windows (x64):** the desktop interface opens. Sending frames needs Npcap. Attacks that depend on Linux tools are not yet supported.
>
> Attacks send frames on the physical interface of the machine they run on. See the [roadmap](docs/roadmap.md) for planned work.

## Disclaimer

MACabre is a security auditing tool. It sends frames that can break connectivity, poison caches, change which switch port carries traffic, or make a switch or host behave in ways its operators did not intend. Those effects are the reason it exists, and also the reason it must be used with care.

- **Only use it on networks you own, or on networks where you have written authorization to test.** Verbal permission is not enough. Keep the written scope with your audit records.
- **Never run an active attack on a production VLAN** without a written plan, a maintenance window and a tested rollback.
- **Start with "generate frames only"** to see exactly what will leave your interface before anything is sent.
- **You are responsible for what you run.** Unauthorized use of this software against networks, systems or people may be illegal in your country. Check the law before you test.
- **No warranty.** MACabre is provided as is, under the Apache License 2.0. The author is not responsible for misuse, for damage to networks or equipment, or for lost service.

## License

MACabre is licensed under the [Apache License 2.0](LICENSE). You may use, copy, modify and distribute it, including commercially.

If you distribute MACabre or a derivative work, keep the [NOTICE](NOTICE) file (or an equivalent attribution) and credit the original author: **vitokosk8 Victor Bolaños Guerra, MACabre**. Projects that are only inspired by MACabre are welcome to credit it too.

Copyright 2026 vitokosk8 Victor Bolaños Guerra.

## Acknowledgements

- [Yersinia](https://github.com/tomac/yersinia), the layer 2 attack framework that inspired this project.
- [Scapy](https://scapy.net/), for packet crafting and sending.
- [Qt for Python (PySide6)](https://doc.qt.io/qtforpython-6/), for the graphical interface.
