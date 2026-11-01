# IEC 61850 GOOSE Spoofing

**Family**: Industrial & Specialized L2 · **Priority**: P3

## What it abuses

GOOSE (Generic Object Oriented Substation Event, EtherType 0x88B8) sends status and command messages to many devices at once, using multicast. A receiver accepts a GOOSE message if its identity and values are valid, so a forged GOOSE can open or close a breaker in the substation.

## Protocols involved

- IEC 61850-8-1 (GOOSE)
- IEEE 802.1Q (priority and VLAN tags)

## Goal

Send a substation command that the receivers act on.

## How it works

The attacker sends GOOSE messages with the identifiers and values the receivers expect. A receiver that acts on the first valid message applies the command. The audit checks which devices accept GOOSE from unknown sources, and whether the messages are authenticated.

## What an auditor checks

- List the GOOSE publishers and subscribers.
- Check whether GOOSE is authenticated in the design.
- Test the effect of an unexpected GOOSE only in a lab.

## Defenses

- Authenticated GOOSE where the standard profile supports it.
- Segregation of substation VLANs.
- Monitoring of GOOSE state and sequence numbers.

## Related

The other techniques in this family are listed in the [family index](README.md).
