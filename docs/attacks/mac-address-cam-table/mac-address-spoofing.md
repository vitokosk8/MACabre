# MAC address spoofing

**Family**: MAC Address & CAM Table · **Priority**: P1

## What it abuses

A switch trusts the source MAC of a frame to decide where a host is. There is no check that the address really belongs to the port it came from, so any port can claim any address.

## Protocols involved

- **IEEE 802.1D**: MAC learning and forwarding.
- **IEEE 802.3**: the Ethernet frame, whose source address is set by the sender.

## Goal

Make the switch send frames addressed to a victim's MAC to the attacker's port. The attacker receives them, and the victim stops receiving them. This is interception of unicast traffic at Layer 2, without changing anything on the victim.

## How it works

1. The attacker sends frames whose source MAC is the victim's address.
2. The switch records the victim's MAC on the attacker's port.
3. Frames addressed to the victim now go to the attacker, until the real victim sends traffic again and the switch moves the entry back.

## What an auditor checks

- The switch port of the target MAC before and after the attack.
- Whether the target still receives its traffic, and who receives it instead.
- Whether the switch logs or blocks the move.

## Defenses

- **Static MAC entries** for critical hosts, which the switch will not relearn.
- **Port security** with a violation action when a port presents an address it should not.
- **MAC move logging** and alerts.

## Related

[MAC cloning](mac-cloning.md) changes the attacker's own address. Spoofing only forges the frames it sends.
