#!/usr/bin/env bash
# Run the QEMU host-passthrough test (issue #66).
#
# QEMU provides two emulated USB devices to the guest: a SuperSpeed one (usb-uas,
# USB 3.1 on the emulated xHCI) and a high-speed one (usb-storage). Inside the
# guest, examples/host.rs exports them over USB/IP -- once through the nusb backend
# and once through libusb (rusb) -- and the guest attaches them back via vhci-hcd,
# checking that the virtual copy enumerates at the same speed and with the same
# bMaxPacketSize0 as the real device.
#
# Usage: run-qemu-passthrough-test.sh [--build] [--dump-log]
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

WORK=$(mktemp -d)
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# Backing storage for the two emulated mass storage devices.
truncate -s 16M "$WORK/uas.img" "$WORK/msd.img" || exit 1

export EXAMPLE=host
export INIT_SCRIPT="$SCRIPT_DIR/init-host-passthrough.sh"
export LOG_FILE="${LOG_FILE:-$REPO_ROOT/.qemu-passthrough.log}"
# SuperSpeed device on an xHCI controller, high-speed device on an EHCI controller.
export QEMU_EXTRA_ARGS="${QEMU_EXTRA_ARGS:--device qemu-xhci,id=xhci \
    -drive if=none,id=uasdisk,file=$WORK/uas.img,format=raw \
    -device usb-uas,id=uas,bus=xhci.0 \
    -device scsi-hd,drive=uasdisk,bus=uas.0 \
    -device usb-ehci,id=ehci \
    -drive if=none,id=msddisk,file=$WORK/msd.img,format=raw \
    -device usb-storage,id=msd,bus=ehci.0,drive=msddisk}"

"$SCRIPT_DIR/run-qemu-test.sh" "$@"
rc=$?
cleanup
trap - EXIT
exit $rc
