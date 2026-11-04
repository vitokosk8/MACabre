# Running MACabre on macOS

MACabre sends frames on the network interface of the Mac it runs on. Sending frames and changing the interface's MAC address both need root privileges.

## Run the app with root

The app needs root for the attacks that send frames. Launch it from Terminal with `sudo`, so the process has the privileges it needs:

```
sudo /Applications/MACabre.app/Contents/MacOS/MACabre
```

Opening the app from Finder runs it without root, and the attacks that send frames will fail.

## How MACabre reads and changes the MAC address on macOS

MACabre reads the current MAC address of an interface with `ifconfig <interface>`, and sets a new one with `ifconfig <interface> ether <mac>`. These commands need root to change the address.

## Limits

- The macOS build is tested less than the Linux build. Report any difference on your Mac.
- Whether a switch accepts frames from a Mac's interface depends on that switch. The lab tests run on Linux only; see [labs](labs.md).
