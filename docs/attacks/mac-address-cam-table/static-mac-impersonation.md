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

A device with the same address as a static entry sends frames on a different port. Whether the switch then keeps the binding on the registered port is implementation-specific, and the two outcomes have different impact:

- **Binding kept**: frames for that address still go to the registered port. The conflict is visible only in logs or in traffic that does not reach the expected host.
- **Binding moved**: the switch relearns the address on the attacker's port, even though the entry is still marked static, and frames for that address are delivered to the attacker.

The Linux bridge used by the lab moves the binding. Real switches differ, so the audit checks which outcome applies. It also checks whether the conflict is reported at all.

## What an auditor checks

- Compare the static entries with the ports where those addresses are seen.
- Check whether a conflicting frame produces a log entry or an alert.
- Confirm that statically bound ports drop frames from other addresses when port security is enabled.

## Defenses

- Port security combined with static MAC bindings.
- Alerts on frames that conflict with a static entry.
- Documented inventory of static bindings, reviewed on a schedule.

## Lab validation

`scripts/lab/static_mac_impersonation_lab.sh` builds a bridge with three ports: the registered victim, the attacker and a monitor. The victim's MAC is a static entry on the victim's port. The lab runs four phases:

1. Baseline: nothing is sent, and the monitor sees no frames from the registered address.
2. Control: the attacker sends frames with its own MAC. The monitor receives them, and the switch learns the attacker's MAC on the attacker's port.
3. Impersonation: the attacker sends frames with the registered MAC. The monitor receives all of them, and the static entry moves to the attacker's port.
4. Redirect: the monitor sends unicast frames to the registered MAC. The attacker receives them, and the victim receives none.

On this Linux bridge the static flag does not protect the binding. The result is a redirect of unicast traffic for the registered address. This is a finding about the Linux bridge only. Whether a managed switch keeps the binding, and whether its port security drops the frames, needs a real switch, which the lab does not test.

## Related

The other techniques in this family are listed in the [family index](README.md).
