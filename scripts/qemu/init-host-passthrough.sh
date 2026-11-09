#!/bin/busybox sh
# QEMU host-passthrough test init script (issue #66).
#
# QEMU provides three USB devices: a SuperSpeed UAS device (usb-uas) and a
# SuperSpeed bulk-only device (usb-bot) on the emulated xHCI controller, and a
# high-speed usb-storage device on an emulated EHCI controller. This guest runs the
# host-passthrough server example (examples/host.rs) against those *real* devices --
# once with the nusb backend and once with the rusb backend -- and attaches what it
# exports back through vhci-hcd.
#
# The client copy has to enumerate at the same speed as the real device and with the
# same bMaxPacketSize0 (9 = 512 bytes at SuperSpeed, 64 at high speed), and bulk
# IN/OUT has to move data in both directions. Reporting a cast speed enum value, a
# hardcoded ep0 max packet size, or dropping endpoint companion descriptors breaks
# this test.
#
# Prints "TEST_RESULT: PASS" or "TEST_RESULT: FAIL"; the runner greps for it.
set -x

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts 2>/dev/null || true
mount -t tmpfs tmpfs /tmp 2>/dev/null || true

# The usbip client talks to the server over loopback.
ifconfig lo 127.0.0.1 netmask 255.0.0.0 up 2>/dev/null || echo "WARN: could not bring up lo"

echo "=== kernel: $(uname -r) ==="

echo "=== loading modules ==="
# The host controller drivers are modules on Debian/Ubuntu kernels, so the QEMU
# USB devices only appear once they are loaded (order: HCD before its PCI glue).
load_module() {
    _mod=$1
    ko=$(find /lib/modules \( -name "$_mod.ko" -o -name "$_mod.ko.*" \) -print -quit 2>/dev/null)
    if [ -z "$ko" ]; then
        echo "- $_mod: not present (built-in?)"
        return 0
    fi
    echo "- loading $ko"
    insmod "$ko" || echo "WARN: failed to load $ko"
}

for mod in usb-common usbcore ehci-hcd ehci-pci \
           xhci-hcd xhci-pci-renesas xhci-pci usbip-core vhci-hcd; do
    load_module "$mod"
done
sleep 1

attr() { cat "$1" 2>/dev/null; }

# is_vhci <sysfs device dir>: true for devices behind vhci-hcd
is_vhci() {
    case "$(readlink -f "$1")" in
        *vhci_hcd*) return 0 ;;
    esac
    return 1
}

# find_dev <vid> <pid> <vhci|real> [speed]: print the sysfs dir of a matching
# device. The speed filter is needed because QEMU uses the same VID:PID for the
# high-speed usb-storage and the SuperSpeed usb-bot devices.
find_dev() {
    for d in /sys/bus/usb/devices/*; do
        [ -e "$d/idVendor" ] || continue
        [ "$(attr "$d/idVendor")" = "$1" ] || continue
        [ "$(attr "$d/idProduct")" = "$2" ] || continue
        if [ -n "${4:-}" ] && [ "$(attr "$d/speed")" != "$4" ]; then
            continue
        fi
        if [ "$3" = "vhci" ]; then
            is_vhci "$d" || continue
        else
            is_vhci "$d" && continue
        fi
        echo "$d"
        return 0
    done
    return 1
}

echo "=== waiting for the QEMU USB devices ==="
for _ in $(seq 1 20); do
    find_dev 46f4 0003 real > /dev/null &&
        find_dev 46f4 0001 real 480 > /dev/null &&
        find_dev 46f4 0001 real 5000 > /dev/null && break
    sleep 1
done
if ! find_dev 46f4 0003 real > /dev/null ||
    ! find_dev 46f4 0001 real 480 > /dev/null ||
    ! find_dev 46f4 0001 real 5000 > /dev/null; then
    echo "WARN: not all QEMU USB devices showed up; dmesg:"
    dmesg | tail -30
fi

echo "=== USB devices provided by QEMU ==="
for d in /sys/bus/usb/devices/*; do
    [ -e "$d/idVendor" ] || continue
    is_vhci "$d" && continue
    echo "$d vid=$(attr "$d/idVendor") pid=$(attr "$d/idProduct")" \
        "speed=$(attr "$d/speed") bMaxPacketSize0=$(attr "$d/bMaxPacketSize0")" \
        "bcdUSB=$(attr "$d/version")"
done

detach_all() {
    for p in $(usbip port 2>/dev/null | sed -n 's/^Port 0*\([0-9][0-9]*\):.*/\1/p'); do
        echo "=== detaching port $p ==="
        usbip detach -p "$p"
    done
}

PASS=1

# check_dev <vid> <pid> <expected real speed> <expected real bMaxPacketSize0>
# The attached (virtual) copy must mirror the real device's speed, ep0 size and
# bcdUSB; the real device values are also checked so the test cannot silently
# pass on a setup QEMU did not provide as expected.
check_dev() {
    vid=$1 pid=$2 want_speed=$3 want_maxp=$4
    label="$vid:$pid@$want_speed"

    if ! real=$(find_dev "$vid" "$pid" real "$want_speed"); then
        echo "ATTACH_TEST: FAIL ($label not found on the QEMU controller)"
        return 1
    fi
    real_speed=$(attr "$real/speed")
    real_maxp=$(attr "$real/bMaxPacketSize0")
    real_version=$(attr "$real/version")
    if [ "$real_speed" != "$want_speed" ] || [ "$real_maxp" != "$want_maxp" ]; then
        echo "ATTACH_TEST: FAIL ($label real device speed=$real_speed/$want_speed" \
            "bMaxPacketSize0=$real_maxp/$want_maxp: unexpected QEMU setup)"
        return 1
    fi

    for _ in $(seq 1 30); do
        attached=$(find_dev "$vid" "$pid" vhci "$want_speed")
        [ -n "$attached" ] && break
        sleep 1
    done
    if [ -z "$attached" ]; then
        echo "ATTACH_TEST: FAIL ($label never showed up behind vhci-hcd)"
        echo "--- dmesg ---"
        dmesg | tail -40
        return 1
    fi

    speed=$(attr "$attached/speed")
    maxp=$(attr "$attached/bMaxPacketSize0")
    version=$(attr "$attached/version")
    echo "attached $label at $attached: speed=$speed bMaxPacketSize0=$maxp bcdUSB=$version"
    if [ "$speed" = "$real_speed" ] && [ "$maxp" = "$real_maxp" ] && [ "$version" = "$real_version" ]; then
        echo "ATTACH_TEST: PASS ($label speed=$speed bMaxPacketSize0=$maxp bcdUSB=$version)"
        return 0
    fi
    echo "ATTACH_TEST: FAIL ($label speed=$speed/$real_speed" \
        "bMaxPacketSize0=$maxp/$real_maxp bcdUSB=$version/$real_version)"
    return 1
}

# check_dmesg <backend>: no enumeration failures in this round
check_dmesg() {
    dmesg > /tmp/dmesg-$1.log 2>&1
    bad=$(grep -iE 'unable to enumerate|device descriptor read|bad maxpacket|No SuperSpeed endpoint companion|invalid SuperSpeed endpoint companion|No LPM exit latency' /tmp/dmesg-$1.log)
    if [ -n "$bad" ]; then
        echo "DMESG_TEST: FAIL ($1)"
        echo "$bad"
        echo "--- dmesg ---"
        tail -60 /tmp/dmesg-$1.log
        return 1
    fi
    echo "DMESG_TEST: PASS ($1 no enumeration errors)"
    return 0
}

# Load the mass-storage class drivers only after the server has claimed the real
# QEMU devices. If they were loaded at boot they would bind to the devices being
# exported (and block nusb's claim), so load them once the attached virtual copies
# exist: they then bind to those copies and expose /dev/sd* inside the guest.
STORAGE_LOADED=0
load_storage_drivers() {
    [ "$STORAGE_LOADED" = "1" ] && return 0
    for mod in usb-storage uas; do
        load_module "$mod"
    done
    STORAGE_LOADED=1
}

# find_block <attached sysfs dir>: print the sd* sysfs path below that device
find_block() {
    for d in "$1"/*/host*/target*/*/block/sd*; do
        if [ -e "$d" ]; then
            echo "$d"
            return 0
        fi
    done
    return 1
}

# bulk_data_test <vid> <pid> <speed> <backend>: write a block through the attached
# device.
#
# This forces non-empty bulk IN/OUT transfers (SCSI INQUIRY/WRITE/READ) through the
# server. It used to panic in the nusb backend because Buffer::len is 0 until the
# data is appended (see src/host.rs); the read-back checks the data made the round
# trip.
bulk_data_test() {
    vid=$1 pid=$2 speed=$3 backend=$4
    label="$vid:$pid@$speed"
    if ! attached=$(find_dev "$vid" "$pid" vhci "$speed"); then
        echo "BULK_TEST: FAIL ($label not attached)"
        return 1
    fi

    blk=""
    for _ in $(seq 1 20); do
        blk=$(find_block "$attached")
        if [ -n "$blk" ] && [ -e "/dev/$(basename "$blk")" ]; then
            break
        fi
        sleep 1
    done
    if [ -z "$blk" ] || [ ! -e "/dev/$(basename "$blk")" ]; then
        echo "BULK_TEST: FAIL ($label no block device)"
        dmesg | tail -20
        return 1
    fi
    dev="/dev/$(basename "$blk")"

    dd if=/dev/zero of=/tmp/bulkblock bs=512 count=1 2>/dev/null
    printf 'USBIP-BULK-OUT' | dd of=/tmp/bulkblock bs=1 conv=notrunc 2>/dev/null
    if ! timeout 20 dd if=/tmp/bulkblock of="$dev" bs=512 count=1 conv=fsync 2>/tmp/dd-$backend.log; then
        echo "BULK_TEST: FAIL ($label write to $dev failed)"
        cat /tmp/dd-$backend.log
        return 1
    fi
    sync

    if grep -q "panicked" /tmp/server-$backend.log; then
        echo "BULK_TEST: FAIL ($label server panicked)"
        tail -20 /tmp/server-$backend.log
        return 1
    fi

    # O_DIRECT bypasses the guest page cache, so this read also goes over USB.
    if ! timeout 20 dd if="$dev" of=/tmp/readback bs=512 count=1 iflag=direct 2>/tmp/dd-read-$backend.log; then
        echo "BULK_TEST: FAIL ($label read from $dev failed)"
        cat /tmp/dd-read-$backend.log
        return 1
    fi
    if ! head -c 14 /tmp/readback | grep -q 'USBIP-BULK-OUT'; then
        echo "BULK_TEST: FAIL ($label read-back mismatch on $dev)"
        hexdump -C /tmp/readback | head -2
        return 1
    fi

    echo "BULK_TEST: PASS ($label wrote and read back $dev via $backend)"
    return 0
}

# VID:PID of the devices QEMU provides; only these are exported
SERVER_FILTERS="46f4:0003 46f4:0001"
EXPECTED_DEVICES=3

# round <backend>: export the QEMU devices with the given backend and attach them
round() {
    backend=$1
    echo "=== round: $backend backend ==="
    detach_all
    dmesg -c > /dev/null 2>&1

    RUST_LOG=info /demo_server "--$backend" $SERVER_FILTERS > /tmp/server-$backend.log 2>&1 &
    server_pid=$!
    ok=1

    busids=""
    for _ in $(seq 1 20); do
        if ! kill -0 $server_pid 2>/dev/null; then
            echo "!!! demo server died, log:"
            cat /tmp/server-$backend.log
            ok=0
            break
        fi
        usbip list -r 127.0.0.1 > /tmp/list-$backend.txt 2>&1
        busids=$(sed -n 's/^[[:space:]]*\([0-9][0-9-]*\):.*/\1/p' /tmp/list-$backend.txt)
        [ "$(echo $busids | wc -w)" -ge $EXPECTED_DEVICES ] && break
        sleep 1
    done

    if [ "$ok" = "1" ]; then
        echo "=== exported bus ids: [$busids] ($backend) ==="
        if [ "$(echo $busids | wc -w)" -lt $EXPECTED_DEVICES ]; then
            echo "LIST_TEST: FAIL ($backend exported $(echo $busids | wc -w) device(s), want $EXPECTED_DEVICES)"
            cat /tmp/server-$backend.log
            ok=0
        else
            echo "LIST_TEST: PASS ($backend exported all devices)"

            for b in $busids; do
                echo "=== attaching $b ($backend) ==="
                usbip attach -r 127.0.0.1 -b "$b"
                echo "=== attach exit: $? ==="
            done
            sleep 2

            # usb-uas (SuperSpeed): ep0 max packet size 512 is encoded as exponent 9
            check_dev 46f4 0003 5000 9 || ok=0
            # usb-storage (high speed): ep0 max packet size 64
            check_dev 46f4 0001 480 64 || ok=0
            # usb-bot (SuperSpeed, bulk-only): ep0 max packet size 9
            check_dev 46f4 0001 5000 9 || ok=0

            # Bind the storage drivers to the attached copies and push a block
            # through both bulk-only devices. UAS is left alone: vhci-hcd does not
            # support the streams the Linux UAS driver requires at SuperSpeed.
            load_storage_drivers
            bulk_data_test 46f4 0001 480 "$backend" || ok=0
            bulk_data_test 46f4 0001 5000 "$backend" || ok=0

            check_dmesg "$backend" || ok=0
        fi
    fi

    echo "=== server.log (tail, $backend) ==="
    tail -20 /tmp/server-$backend.log 2>/dev/null

    detach_all
    kill $server_pid 2>/dev/null
    wait $server_pid 2>/dev/null
    sleep 2
    [ "$ok" = "1" ]
}

round nusb || PASS=0
round rusb || PASS=0

echo "=== dmesg: vhci / usb / errors ==="
dmesg | grep -iE 'vhci_hcd|usb [0-9]-|error|descriptor|speed' | tail -40

if [ "$PASS" = "1" ]; then
    echo "TEST_RESULT: PASS"
else
    echo "TEST_RESULT: FAIL"
fi

sync
sleep 1
poweroff -f
sleep 1
exit 0
