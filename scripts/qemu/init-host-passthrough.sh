#!/bin/busybox sh
# QEMU host-passthrough test init script (issue #66).
#
# QEMU provides a SuperSpeed device (usb-uas on the emulated xHCI) and a high-speed
# one (usb-storage on an emulated EHCI controller). This guest runs the host-passthrough server example
# (examples/host.rs) against those *real* devices -- once with the nusb backend and
# once with the rusb backend -- and attaches what it exports back through vhci-hcd.
#
# The client copy has to enumerate at the same speed as the real device and with the
# same bMaxPacketSize0 (9 = 512 bytes at SuperSpeed, 64 at high speed). Reporting a
# cast speed enum value or a hardcoded ep0 max packet size breaks enumeration, which
# is what this test guards against.
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
for mod in usb-common usbcore ehci-hcd ehci-pci \
           xhci-hcd xhci-pci-renesas xhci-pci usbip-core vhci-hcd; do
    ko=$(find /lib/modules \( -name "$mod.ko" -o -name "$mod.ko.*" \) -print -quit 2>/dev/null)
    if [ -z "$ko" ]; then
        echo "- $mod: not present (built-in?)"
        continue
    fi
    echo "- loading $ko"
    insmod "$ko" || echo "WARN: failed to load $ko"
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

# find_dev <vid> <pid> <vhci|real>: print the sysfs dir of a matching device
find_dev() {
    for d in /sys/bus/usb/devices/*; do
        [ -e "$d/idVendor" ] || continue
        [ "$(attr "$d/idVendor")" = "$1" ] || continue
        [ "$(attr "$d/idProduct")" = "$2" ] || continue
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
    find_dev 46f4 0003 real > /dev/null && find_dev 46f4 0001 real > /dev/null && break
    sleep 1
done
if ! find_dev 46f4 0003 real > /dev/null || ! find_dev 46f4 0001 real > /dev/null; then
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
    label="$vid:$pid"

    if ! real=$(find_dev "$vid" "$pid" real); then
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
        attached=$(find_dev "$vid" "$pid" vhci)
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
    bad=$(grep -iE 'unable to enumerate|device descriptor read|bad maxpacket' /tmp/dmesg-$1.log)
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

# VID:PID of the devices QEMU provides; only these are exported
SERVER_FILTERS="46f4:0003 46f4:0001"
EXPECTED_DEVICES=2

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
            echo "LIST_TEST: PASS ($backend exported both devices)"

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
