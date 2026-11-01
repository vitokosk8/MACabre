# G.8032 ERPS Control Spoofing

**Family**: Link Aggregation & Redundancy · **Priority**: P3

## What it abuses

G.8032 (Ethernet Ring Protection Switching) protects a ring topology. Ring nodes exchange R-APS messages to block a link and to switch traffic when a failure occurs. R-APS messages are not authenticated, so a forged message can trigger a protection switch or block a healthy link.

## Protocols involved

- ITU-T G.8032 (ERPS)
- R-APS messages

## Goal

Trigger a protection switch, or block a healthy link, in the ring.

## How it works

The attacker sends R-APS messages that signal a failure or a block. The ring nodes change the blocked link and move traffic, which can cut the ring or create a loop if the messages are repeated. The audit checks whether the ring accepts messages from ports that are not part of it.

## What an auditor checks

- List the ring ports and check that no access port can reach them.
- Test whether an R-APS message from outside is accepted.
- Check the protection state after a forged signal.

## Defenses

- Ring membership limited to trusted ports.
- Monitoring of protection state changes.
- Physical separation of the ring from user ports.

## Related

The other techniques in this family are listed in the [family index](README.md).
