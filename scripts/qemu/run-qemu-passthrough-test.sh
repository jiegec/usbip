#!/usr/bin/env bash
# Run the QEMU host-passthrough test (issue #66).
#
# QEMU provides emulated USB devices to the guest: a SuperSpeed UAS device
# (usb-uas) and a SuperSpeed bulk-only device (usb-bot) on the emulated xHCI
# controller, plus a high-speed usb-storage device on EHCI. Inside the guest,
# examples/host.rs exports them over USB/IP -- once through the nusb backend and
# once through libusb (rusb) -- and the guest attaches them back via vhci-hcd,
# checking that the virtual copies enumerate at the right speed and ep0 max packet
# size, and that bulk IN/OUT works on both bulk-only devices.
#
# Usage: run-qemu-passthrough-test.sh [--build] [--dump-log]
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

WORK=$(mktemp -d)
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# Backing storage for the emulated mass storage devices.
truncate -s 16M "$WORK/uas.img" "$WORK/bot.img" "$WORK/msd.img" || exit 1

export EXAMPLE=host
export INIT_SCRIPT="$SCRIPT_DIR/init-host-passthrough.sh"
export LOG_FILE="${LOG_FILE:-$REPO_ROOT/.qemu-passthrough.log}"
# SuperSpeed devices on an xHCI controller, high-speed device on an EHCI
# controller. The UAS device is only enumerated: vhci-hcd does not support
# streams, which the Linux UAS driver requires at SuperSpeed. The SuperSpeed
# bulk-only device (usb-bot) is used for the data-path test instead, because
# usb-storage binds to it over USB 3.
export QEMU_EXTRA_ARGS="${QEMU_EXTRA_ARGS:--device qemu-xhci,id=xhci \
    -drive if=none,id=uasdisk,file=$WORK/uas.img,format=raw \
    -device usb-uas,id=uas,bus=xhci.0 \
    -device scsi-hd,drive=uasdisk,bus=uas.0 \
    -drive if=none,id=botdisk,file=$WORK/bot.img,format=raw \
    -device usb-bot,id=bot,bus=xhci.0 \
    -device scsi-hd,drive=botdisk,bus=bot.0 \
    -device usb-ehci,id=ehci \
    -drive if=none,id=msddisk,file=$WORK/msd.img,format=raw \
    -device usb-storage,id=msd,bus=ehci.0,drive=msddisk}"

"$SCRIPT_DIR/run-qemu-test.sh" "$@"
rc=$?
cleanup
trap - EXIT
exit $rc
