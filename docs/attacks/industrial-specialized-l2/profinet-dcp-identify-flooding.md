# PROFINET DCP Identify Flooding

**Family**: Industrial & Specialized L2 · **Priority**: P3

## What it abuses

DCP Identify requests ask every device on the segment to reply with its identity. A high rate of Identify requests makes each device spend time on replies, which is a discovery flood in the PROFINET network.

## Protocols involved

- PROFINET DCP (EtherType 0x8892)

## Goal

Load devices with identification requests, which can disturb their timing.

## How it works

The attacker sends Identify requests at a high rate, and each device answers. The devices' processing and the replies' traffic grow. In a control network, this can disturb the cyclic traffic that has timing requirements.

## What an auditor checks

- Measure the devices' response times under an Identify stream.
- Check whether the cyclic traffic keeps its timing.
- Check whether the switch rate-limits DCP.

## Defenses

- Rate limits for DCP on industrial switches.
- Separation of cyclic and acyclic traffic.
- Monitoring of discovery traffic.

## Related

The other techniques in this family are listed in the [family index](README.md).
