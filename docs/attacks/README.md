# Attack theory

Each attack has its own document here. It explains the idea behind the attack, not the audit steps:

- **What it abuses**: the trust or design flaw the attack relies on.
- **Protocols involved**: which standards and mechanisms take part.
- **Goal**: what an attacker gains, and what an auditor is trying to find out.
- **How it works**: the sequence of frames, in plain words.
- **Defenses**: what stops it, and how to tell that it is happening.

The audit side (requirements, expected behavior, evidence, execution risk) lives in the [P1 specifications](../specs/P1.md). The lab that reproduces the attack is listed in [labs](../labs.md).

| Attack | Family | Priority | Theory |
| --- | --- | --- | --- |
| DHCP Starvation | DHCPv4 & DHCPv6 | P1 | [dhcp-starvation.md](dhcp-starvation.md) |
| MAC Flooding / CAM Overflow | MAC Address & CAM Table | P1 | [mac-flooding.md](mac-flooding.md) |
| MAC Flapping | MAC Address & CAM Table | P1 | [mac-flapping.md](mac-flapping.md) |
| MAC Address Spoofing | MAC Address & CAM Table | P1 | [mac-address-spoofing.md](mac-address-spoofing.md) |
| MAC Cloning | MAC Address & CAM Table | P1 | [mac-cloning.md](mac-cloning.md) |
| ARP Spoofing | ARP | P1 | [arp-spoofing.md](arp-spoofing.md) |
| ARP Cache Poisoning | ARP | P1 | [arp-cache-poisoning.md](arp-cache-poisoning.md) |
| Gratuitous ARP Spoofing | ARP | P1 | [gratuitous-arp-spoofing.md](gratuitous-arp-spoofing.md) |
| ARP Request Flooding | ARP | P1 | [arp-request-flooding.md](arp-request-flooding.md) |

Documents are added as each attack is implemented, so the table grows with the catalog.
