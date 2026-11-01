# BPDU Guard Trigger Abuse

**Family**: Spanning Tree (STP / RSTP / MSTP / PVST+) · **Priority**: P2

## What it abuses

BPDU Guard shuts an edge port when it receives a BPDU, which protects the network from rogue switches. The same behavior can be triggered on purpose, so that an attacker shuts the ports of a legitimate host, which is a denial of service.

## Protocols involved

- IEEE 802.1D
- Vendor BPDU Guard feature

## Goal

Shut down the ports of legitimate hosts by triggering the protection that BPDU Guard applies.

## How it works

The attacker sends a BPDU from the port of a legitimate host. BPDU Guard shuts the port, and the host loses connectivity until someone re-enables it. The protection works as designed, but it can be turned into a denial of service.

## What an auditor checks

- List the edge ports where BPDU Guard is enabled.
- Test whether a single BPDU shuts the port.
- Check whether the port recovers automatically, and how.

## Defenses

- Error-disable recovery with a timer.
- Monitoring of BPDU Guard events.
- Physical security on edge ports.

## Related

The other techniques in this family are listed in the [family index](README.md).
