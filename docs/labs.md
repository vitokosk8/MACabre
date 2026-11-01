# Labs

The labs are MACabre's development test harness. Every attack has a lab script under `scripts/lab/` that builds a small test network on one Linux machine, runs the attack inside it, and reports what the switch and the hosts did. The labs exist so that each attack can be checked the same way, every time.

The labs are not how MACabre runs. The tool sends frames on the physical interface you choose, and the lab harness is only a way to test without a real switch. Nothing in a lab touches your real network interfaces, and the script removes everything it created when it ends.

## Requirements

- Linux with root access (`sudo`).
- `iproute2` (`ip`, `bridge`) and `ping`. The cloning lab also needs `nft` (nftables), and the DHCP lab needs `dnsmasq`.
- The project environment in `.venv`, or another interpreter set with `PYTHON=/path/to/python`.

## The labs

| Attack | Script | What it shows |
| --- | --- | --- |
| [DHCP starvation](attacks/dhcpv4-dhcpv6/dhcp-starvation.md) | `dhcp_starvation_lab.sh` | Leases granted to the attacker, and whether a legitimate client still gets an address |
| [MAC flooding](attacks/mac-address-cam-table/mac-flooding.md) | `mac_flooding_lab.sh` | Addresses the switch learns, and flooded frames received by a victim port |
| [MAC flapping](attacks/mac-address-cam-table/mac-flapping.md) | `mac_flapping_lab.sh` | How many times the switch moves one MAC between two ports |
| [MAC address spoofing](attacks/mac-address-cam-table/mac-address-spoofing.md) | `mac_spoofing_lab.sh` | The switch port of the target MAC before and after, and who receives its frames |
| [MAC cloning](attacks/mac-address-cam-table/mac-cloning.md) | `mac_cloning_lab.sh` | Frames dropped by a port that admits one MAC, then delivered after cloning |
| [ARP spoofing](attacks/arp/arp-spoofing.md) | `arp_spoofing_lab.sh` | The victim's ARP cache for the gateway, before and after |
| [ARP cache poisoning](attacks/arp/arp-cache-poisoning.md) | `arp_poisoning_lab.sh` | Both ARP caches, of the victim and of the gateway, before and after |
| [Gratuitous ARP spoofing](attacks/arp/gratuitous-arp-spoofing.md) | `gratuitous_arp_lab.sh` | Two victims' ARP caches changed by one broadcast announcement |
| [ARP request flooding](attacks/arp/arp-request-flooding.md) | `arp_request_flooding_lab.sh` | Flooded requests received by the victim, and the gateway's neighbor table growth |
| [ARP reply flooding](attacks/arp/arp-reply-flooding.md) | `arp_reply_flooding_lab.sh` | Replies received by the victim, and whether its neighbor table changes |
| [ARP-based gateway impersonation](attacks/arp/arp-based-gateway-impersonation.md) | `arp_gateway_impersonation_lab.sh` | Both victims' cached MAC for the gateway, before and after, and the attacker's forwarding setting |
| [Switch spoofing (DTP)](attacks/vlan-802-1q/switch-spoofing-dtp-spoofing.md) | `switch_spoofing_lab.sh` | DTP frames seen on the monitor port, and whether they are well formed. The trunk decision needs a real switch |
| [VLAN hopping](attacks/vlan-802-1q/vlan-hopping.md) | `vlan_hopping_lab.sh` | Tagged probes for VLAN 20 reaching the monitor, before and after the port carries that VLAN (the trunk outcome is simulated) |
| [Double-tagging](attacks/vlan-802-1q/double-tagging.md) | `double_tagging_lab.sh` | Frames with both tags reaching the monitor, before and after the port passes tagged frames (the switch's tag removal is not tested) |
| [Native VLAN abuse](attacks/vlan-802-1q/native-vlan-abuse.md) | `native_vlan_lab.sh` | Untagged probes reaching the monitor. The mismatch between trunk ends needs two real switches |
| [BPDU spoofing](attacks/spanning-tree/bpdu-spoofing.md) | `bpdu_spoofing_lab.sh` | Which switch port is the root port, before, during and after injected BPDUs, and when the switch returns to the legitimate root (uses the Linux kernel's Spanning Tree) |
| [Root bridge takeover](attacks/spanning-tree/root-bridge-takeover.md) | `root_bridge_takeover_lab.sh` | Which switch port is the root port while the attacker keeps its root claim refreshed, and when the switch returns to the legitimate root (uses the Linux kernel's Spanning Tree) |
| [Root bridge impersonation](attacks/spanning-tree/root-bridge-impersonation.md) | `root_bridge_impersonation_lab.sh` | Which switch port leads to the root while an impostor sends the real root's ID, and when the switch returns to the real root (uses the Linux kernel's Spanning Tree) |
| [Topology change flooding](attacks/spanning-tree/topology-change-flooding.md) | `topology_change_flooding_lab.sh` | Whether the monitor's MAC is flushed from the switch's table with and without the TC flag, against a control run. This kernel does not flush on the flag, so the effect needs a real switch |
| [VLAN tag injection](attacks/vlan-802-1q/vlan-tag-injection.md) | `vlan_tag_injection_lab.sh` | Injected-tag frames reaching the monitor, and whether their VLAN ID and priority are unchanged (the switch's decision is simulated) |

Run any of them with `sudo`, from the project root:

```bash
sudo scripts/lab/mac_flooding_lab.sh
sudo FRAMES=2000 scripts/lab/mac_flooding_lab.sh
```

Most labs accept a size parameter (`FRAMES`, `SPOOF_FRAMES`, `REPLY_SECONDS`, `ANNOUNCEMENTS`) to change how much traffic they send.

## Limits of the labs

- The switch is a Linux bridge, which is software. It has no CAM table size limit, no port security and no vendor behavior. The labs test the logic of each attack and the way a learning switch reacts to it, not the behavior of a specific device.
- Port security in the cloning lab is emulated with an nftables rule on the bridge.
- The DHCP lab uses `dnsmasq --no-ping`, which skips the ARP check before each offer, so the lab runs faster. That setting belongs to the lab, not to the attack.

To test on real hardware, use a dedicated Ethernet adapter connected to a switch you control. Wi-Fi access points drop frames whose MAC address is not associated, so Wi-Fi is not suitable for these tests.
