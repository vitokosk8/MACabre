First public build of MACabre, a Python Layer 2 audit suite with a desktop interface.

**Status by platform**

- **Linux (x86_64)**: the full suite. Attacks and laboratory scripts run here. The labs need root, `iproute2`, `nftables`, `dnsmasq` and `lldpd`.
- **macOS (Apple silicon)**: the desktop interface opens, and the DHCP starvation and MAC flooding attacks have been run from it. Attacks that depend on Linux tools (`ip`, network namespaces) are not yet supported; they are being ported.
- **Windows (x64)**: the desktop interface opens. Sending frames needs Npcap installed, and attacks that depend on Linux tools are not yet supported.

**Not yet validated**: MNDP field layout (against a RouterOS capture), DTP status mapping (against a real switch), and the MAB result on a real port.

**Signing**: these builds are not signed or notarized. On macOS, open the app with right-click → Open, or run `xattr -dr com.apple.quarantine MACabre.app`. On Windows, SmartScreen may show a warning; choose "More info" → "Run anyway".

Use only on networks you own or are explicitly authorized to test.
