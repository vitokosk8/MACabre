# IEC 61850 GOOSE Replay

**Family**: Industrial & Specialized L2 · **Priority**: P3

## What it abuses

GOOSE messages carry a state number (stNum) and a sequence number (sqNum). A receiver uses them to detect new state changes and to reject old messages. A replayed GOOSE message that is accepted again repeats an old command.

## Protocols involved

- IEC 61850-8-1 (GOOSE state and sequence numbers)

## Goal

Repeat an old substation command, by replaying captured messages.

## How it works

The attacker records GOOSE messages and sends them again later. A receiver that does not check the numbers acts on the old state. The audit checks the receivers' logic for stale and repeated messages.

## What an auditor checks

- Record GOOSE traffic and replay it in a lab.
- Check how receivers handle a repeated stNum or sqNum.
- Check the time-to-live of each GOOSE message.

## Defenses

- Receivers that check stNum and sqNum strictly.
- Authenticated GOOSE where supported.
- Monitoring of sequence number anomalies.

## Related

The other techniques in this family are listed in the [family index](README.md).
