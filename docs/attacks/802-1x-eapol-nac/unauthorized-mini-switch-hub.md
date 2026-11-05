# Unauthorized Mini-Switch / Hub

**Family**: 802.1X / EAPOL / NAC · **Priority**: P2

## What it abuses

A port authenticated for one device can be connected to a hub or a small switch, which then carries several devices behind a single authorized port. The authenticator sees only the first MAC address, and the others go unchecked.

## Protocols involved

- IEEE 802.1X
- Ethernet port behavior with hubs and unmanaged switches

## Goal

Connect several devices behind one authorized port, without being checked.

## How it works

The attacker connects an unmanaged switch or hub to an authorized port. Frames from the devices behind it reach the port, and the authenticator authorized only the first host. The rest of the devices use the network through that authorization without being checked.

## What an auditor checks

- Connect an unmanaged switch behind an authenticated port and count the MACs seen.
- Check whether the port limits the number of learned addresses.
- Check whether a second MAC on the port triggers a violation.

## Defenses

- Port security with a maximum of one MAC per port.
- Authenticator policies that limit addresses per port.
- Physical checks on edge ports.

## Implementation status

- Module: `src/macabre/attacks/unauthorized_mini_switch.py` (sends one frame from each client MAC the operator lists, through the port, as a mini-switch behind it would).
- GUI panel: "Unauthorized Mini-Switch / Hub".
- Status: 🔨 Implemented. The lab validates that the LAN bridge learns one MAC on the access port for the authorized device, and three MACs on the same port when a mini-switch passes three devices. Port limits and violation actions are not validated: the Linux bridge has no port security or 802.1X.

## Lab validation

`scripts/lab/unauthorized_mini_switch_lab.sh` runs a LAN bridge whose access port faces a hub segment with the authorized device and the mini-switch. Baseline: one MAC learned on the port. Attack: three MACs learned on the same port. The lab does not measure a port limit or the switch's violation action.

## Related

The other techniques in this family are listed in the [family index](README.md).
