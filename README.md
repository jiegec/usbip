# usbip

A Rust library to run a USB/IP server to simulate USB devices.

It also enables sharing devices from an OS supporting libusb(libusb claims that it supports Linux, macOS, Windows, OpenBSD/NetBSD, Haiku and Solaris) to another OS supporting USB/IP(Linux, Windows). Sharing an CCID SmartCard from macOS to Linux is tested.

[![Coverage Status](https://coveralls.io/repos/github/jiegec/usbip/badge.svg?branch=master)](https://coveralls.io/github/jiegec/usbip?branch=master)

## How to use

See examples directory. Three examples are provided:

1. hid_keyboard: Simulate a hid keyboard that types something every second.
2. cdc_acm_serial: Simulate a serial that gets a character every second.
3. host: Act like original usb/ip sharing server, sharing one device from one machine to another. Also supports sharing from macOS to Linux!

To run example, run:

```bash
$ env RUST_LOG=info cargo run --example hid_keyboard
```

Then, in a USB/IP client environment:

```bash
$ usbip list -r $remote_ip
$ usbip attach -r $remote_ip -b $bus_id
```

Then, you can inspect the simulated USB device behavior in both sides.

## API

See code comments. Not finalized yet, so get prepared for api breaking changes.
