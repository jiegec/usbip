#!/bin/busybox sh
# QEMU end-to-end usbip test init script.
#
# Runs *inside* the QEMU guest. It:
#   1. mounts proc/sys/devtmpfs
#   2. loads vhci-hcd + cdc_acm kernel modules
#   3. starts the compiled usbip demo server (our library under test)
#   4. uses the usbip client to attach the simulated HID keyboard + CDC ACM serial
#   5. verifies the serial device emits 'a' and the keyboard emits KEY_1
#   6. prints "TEST_RESULT: PASS" or "TEST_RESULT: FAIL" and powers off
#
# The workflow greps the serial console output for TEST_RESULT.
set -x

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts 2>/dev/null || true
mount -t tmpfs tmpfs /tmp 2>/dev/null || true

# Bring up loopback so the usbip client can reach the local server on 127.0.0.1
ifconfig lo 127.0.0.1 netmask 255.0.0.0 up 2>/dev/null || echo "WARN: could not bring up lo"

echo "=== init: mounting done ==="

K=$(uname -r)
echo "=== kernel: $K ==="

echo "=== loading modules ==="
for mod in usbip-core vhci-hcd cdc-acm; do
    ko=$(find /lib/modules \( -name "$mod.ko" -o -name "$mod.ko.*" \) 2>/dev/null | head -1)
    echo "- loading $ko"
    insmod "$ko" || echo "WARN: failed to load $ko"
done
sleep 1

echo "=== starting usbip demo server ==="
RUST_LOG=info /demo_server > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 2
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "!!! demo server died, log:"
    cat /tmp/server.log
fi

echo "=== usbip list ==="
usbip list -r 127.0.0.1

# Extract busids (e.g. 1-1, 1-2) from "usbip list -r" output
BUSIDS=$(usbip list -r 127.0.0.1 2>/dev/null \
    | sed -n 's/^[[:space:]]*\([0-9][0-9-]*\):.*/\1/p')
echo "=== bus ids: [$BUSIDS] ==="

PASS=1

if [ -z "$BUSIDS" ]; then
    echo "TEST_RESULT: FAIL (no exportable devices)"
    dmesg | tail -40
    poweroff -f
    sleep 1
    exit 1
fi

for BUSID in $BUSIDS; do
    echo "=== attaching $BUSID ==="
    # Note: the usbip tool may report a spurious "record connection" error after a
    # successful attach; the kernel still enumerates the device, so we don't abort here.
    usbip attach -r 127.0.0.1 -b "$BUSID"
    echo "=== attach exit: $? ==="
    sleep 2
done

echo "=== waiting for devices ==="
for i in $(seq 1 30); do
    ACM=$(ls /dev/ttyACM* 2>/dev/null | head -1)
    EV=$(awk '
        /^S:.*vhci_hcd/ { f=1 }
        f && /^H:/ { if (match($0, /event[0-9]+/)) { print substr($0, RSTART, RLENGTH); exit } }
    ' /proc/bus/input/devices)
    echo "iter $i: ACM=[$ACM] event=[$EV]"
    if [ -n "$ACM" ] && [ -n "$EV" ]; then
        break
    fi
    sleep 1
done

echo "=== /proc/bus/input/devices ==="
cat /proc/bus/input/devices 2>/dev/null
echo
echo "=== /dev listing ==="
ls -la /dev/ttyACM* /dev/input/ 2>/dev/null

# ---- Serial test: read one raw byte from /dev/ttyACM0, expect 'a' (0x61) ----
if [ -n "$ACM" ]; then
    echo "=== serial test: reading $ACM (raw) ==="
    stty -F "$ACM" raw -echo 2>/dev/null || true
    DATA=$(timeout 8 dd if="$ACM" bs=1 count=1 2>/dev/null | od -An -tx1 -v | tr -d ' \n')
    echo "serial byte: [$DATA]"
    case "$DATA" in
        61) echo "SERIAL_TEST: PASS (got 'a' = 0x61)" ;;
        *)  echo "SERIAL_TEST: FAIL ([$DATA])"; PASS=0 ;;
    esac
else
    echo "SERIAL_TEST: FAIL (no /dev/ttyACM device)"; PASS=0
fi

# ---- Keyboard test: read the vhci HID event device, look for KEY_1 (code=2) ----
if [ -n "$EV" ]; then
    echo "=== keyboard test: reading /dev/input/$EV (timeout 6s) ==="
    timeout 6 cat "/dev/input/$EV" > /tmp/kbd.bin 2>/dev/null
    HEX=$(od -An -tx1 -v /tmp/kbd.bin | tr -d ' \n')
    echo "kbd bytes: $HEX"
    # EV_KEY(type=1) KEY_1(code=2) value=1(down) -> LE bytes "0100 0200 01000000"
    case "$HEX" in
        *0100020001000000*) echo "KEYBOARD_TEST: PASS (KEY_1 down event seen)" ;;
        *)                  echo "KEYBOARD_TEST: FAIL"; PASS=0 ;;
    esac
else
    echo "KEYBOARD_TEST: FAIL (no vhci input event device)"; PASS=0
fi

echo "=== server.log (tail) ==="
tail -40 /tmp/server.log 2>/dev/null

if [ "$PASS" = "1" ]; then
    echo "TEST_RESULT: PASS"
else
    echo "TEST_RESULT: FAIL"
fi

echo "=== dmesg tail ==="
dmesg | tail -20

sync
sleep 1
poweroff -f
sleep 1
exit 0
