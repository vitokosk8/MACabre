# MKA Peer Impersonation

**Family**: MACsec / IEEE 802.1AE · **Priority**: P3

## What it abuses

MACsec Key Agreement (MKA) lets two MACsec peers agree on keys over EAPOL. The peers identify each other with a connectivity association key (CAK) and a connectivity association name (CKN). A device that holds a copied CAK or CKN can join the agreement as a peer.

## Protocols involved

- IEEE 802.1X-2010 (MKA, Clause 9)
- IEEE 802.1AE (MACsec)
- EAPOL

## Goal

Join a MACsec key agreement as a peer, and obtain the keys of the connectivity association.

## How it works

The attacker sends MKA messages with a known CKN and a valid-looking key exchange. If the key material is a shared secret that the attacker holds, the peer accepts the attacker as a member of the connectivity association and may send it the secure channel key.

## What an auditor checks

- Check whether MKA uses pre-shared keys or certificates.
- Check which devices hold the CAK.
- Test whether a peer with a copied CKN is accepted.

## Defenses

- Certificate-based MKA where supported.
- Unique CAKs per link, rotated regularly.
- Monitoring of MKA peers.

## Related

The other techniques in this family are listed in the [family index](README.md).
