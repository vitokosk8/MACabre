# Private VLAN Isolation Bypass

**Family**: VLAN & IEEE 802.1Q · **Priority**: P2

## What it abuses

Private VLANs isolate hosts from each other inside one VLAN: isolated ports talk only to promiscuous ports, such as the gateway. The isolation is enforced by the switch, so a misconfiguration, or a forwarding path that skips the check, lets isolated hosts reach each other.

## Protocols involved

- IEEE 802.1Q
- Vendor private VLAN implementation (primary, isolated and community VLANs)

## Goal

Reach hosts that are isolated from the attacker, inside the same VLAN.

## How it works

The attacker's port is isolated, and it sends frames to another isolated host. If the isolation rule is not applied on the path used, the frame reaches the other host. Routing through a promiscuous port can also let traffic cross the boundary, depending on the design.

## What an auditor checks

- Test traffic between two isolated ports.
- Check the community and promiscuous port assignments.
- Verify that isolation also applies to broadcast and multicast.

## Defenses

- Isolation enforced in hardware where the platform offers it.
- Review promiscuous port assignments.
- Combine isolation with ARP inspection and port security.

## Implementation status

- Module: `src/macabre/attacks/private_vlan_bypass.py` (sends UDP probes either straight to the target's MAC or to a promiscuous relay's MAC with the target's IP).
- GUI panel: "Private VLAN Isolation Bypass".
- Status: 🔨 Implemented. The lab validates that two isolated ports do not exchange frames directly, and that a promiscuous relay that forwards carries the probes to the isolated target. Vendor private VLAN configuration and the relay's filters are not validated.

## Lab validation

`scripts/lab/private_vlan_bypass_lab.sh` runs a bridge with two isolated ports (attacker and victim) and one promiscuous port with a forwarding router. Control: the victim receives none of five direct probes. Bypass: the victim receives five of five probes sent through the relay.

## Related

The other techniques in this family are listed in the [family index](README.md).
