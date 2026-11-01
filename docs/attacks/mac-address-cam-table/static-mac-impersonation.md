# Static MAC Impersonation

**Family**: MAC Address & CAM Table · **Priority**: P2

## What it abuses

Administrators can pin a MAC address to a port with a static entry. The switch then trusts that binding and never relearns it from traffic, so a device that is registered statically is treated as authoritative for its port.

## Protocols involved

- IEEE 802.1D (static filtering and forwarding entries)
- IEEE 802.1Q

## Goal

Take over traffic for a statically registered address by making a device on another port appear to be that address.

## How it works

A device with the same address as a static entry sends frames on a different port. The switch keeps the static binding, so frames for that address are still forwarded to the registered port, but the mismatch is visible in logs and in traffic that does not reach the expected host. The audit checks whether the conflict is reported at all and whether the static entry is enforced in both directions.

## What an auditor checks

- Compare the static entries with the ports where those addresses are seen.
- Check whether a conflicting frame produces a log entry or an alert.
- Confirm that statically bound ports drop frames from other addresses when port security is enabled.

## Defenses

- Port security combined with static MAC bindings.
- Alerts on frames that conflict with a static entry.
- Documented inventory of static bindings, reviewed on a schedule.

## Related

The other techniques in this family are listed in the [family index](README.md).
