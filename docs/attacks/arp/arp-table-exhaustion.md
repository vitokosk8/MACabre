# ARP Table Exhaustion

**Family**: ARP · **Priority**: P2

## What it abuses

The ARP table of a router or host is finite. Filling it with entries for addresses that do not exist makes the device evict useful entries, or refuse new ones, so resolution of real hosts starts to fail.

## Protocols involved

- ARP (RFC 826)
- Neighbor table implementation (for example the Linux gc_thresh limits)

## Goal

Fill a device's ARP table so that legitimate entries are evicted or new hosts cannot be resolved.

## How it works

The attacker sends replies or requests that create entries for many distinct addresses. The device stores them until its limit is reached, then starts evicting, sometimes including entries for legitimate hosts. New hosts may be unreachable until their entries are learned again.

## What an auditor checks

- Compare the table size with the number of hosts on the segment.
- Check the eviction policy and the garbage collection thresholds.
- Verify that legitimate entries survive a burst of fake ones.

## Defenses

- Table sizes sized for the segment.
- Limits on entries created per port.
- Dynamic ARP Inspection and DHCP snooping, so that only trusted bindings create entries.

## Related

The other techniques in this family are listed in the [family index](README.md).
