# EtherCAT Frame Injection

**Family**: Industrial & Specialized L2 · **Priority**: P3

## What it abuses

EtherCAT (EtherType 0x88A4) carries process data through a chain of slave devices, which each read and write part of the frame as it passes. A frame that is injected into the chain, or a frame that is altered in transit, changes the outputs of the slaves.

## Protocols involved

- EtherCAT (IEC 61158, EtherType 0x88A4)

## Goal

Change the outputs of slave devices, by injecting process data frames.

## How it works

The attacker sends EtherCAT frames with the expected working counter and the expected commands. A slave that does not check the source applies the data to its outputs. The effect can be wrong motion or a wrong state in the process, which makes this attack a safety concern.

## What an auditor checks

- Check which devices are allowed on the EtherCAT segment.
- Test frame injection only in a lab with the process disconnected.
- Check whether the slaves verify the master.

## Defenses

- Segregation of EtherCAT segments.
- Safety functions that do not depend on a single network path.
- Monitoring of unexpected frames.

## Related

The other techniques in this family are listed in the [family index](README.md).
