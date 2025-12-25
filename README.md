# usbip

[![Coverage Status](https://coveralls.io/repos/github/jiegec/usbip/badge.svg?branch=master)](https://coveralls.io/github/jiegec/usbip?branch=master)
[![crates.io](https://img.shields.io/crates/v/usbip.svg)](https://crates.io/crates/usbip)

A Rust library to run a USB/IP server to simulate USB devices and share real USB devices over a network.

## What is USB/IP?

USB/IP is a network protocol that allows USB devices to be shared between computers over a network. It enables:

- **Device simulation**: Create virtual USB devices that can be accessed remotely
- **Device sharing**: Share physical USB devices from one machine to another
- **Cross-platform**: Works across different operating systems (Linux, etc.)

## Installation

### Prerequisites

Install Rust from the [official documentation](https://www.rust-lang.org/tools/install).

### Building from source

```bash
git clone https://github.com/jiegec/usbip.git
cd usbip
cargo build --release
```

## How to use

### Examples

The `examples/` directory contains three example programs:

1. **hid_keyboard**: Simulate a HID keyboard that types something every second
2. **cdc_acm_serial**: Simulate a CDC ACM serial device that receives a character every second
3. **host**: Act as a USB/IP server, sharing physical devices from the host machine to remote clients

#### Running an example

```bash
cargo run --example hid_keyboard
```

#### Connecting from a USB/IP client

On the client machine (e.g. Linux with USB/IP support):

```bash
# List available devices
usbip list -r $remote_ip

# Attach to a device
usbip attach -r $remote_ip -b $bus_id
```

## License

MIT License - see [LICENSE](LICENSE) file for details.
