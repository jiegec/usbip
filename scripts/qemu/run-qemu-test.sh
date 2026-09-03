#!/usr/bin/env bash
# Run the QEMU-based usbip end-to-end test.
#
# This builds the `demo` example, assembles an initramfs from the running
# kernel + modules + busybox + usbip tool, boots it in QEMU, and verifies that
# the simulated serial port and keyboard actually work inside a real Linux.
#
# Usage: run-qemu-test.sh [--build] [--dump-log]
#   --build      build the demo example first (default: assume prebuilt)
#   --dump-log   print the full serial console log on stdout (for debugging)
#
# Exit: 0 if the test passed, non-zero otherwise.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

BUILD=0
DUMP=0
for arg in "$@"; do
    case "$arg" in
        --build) BUILD=1 ;;
        --dump-log) DUMP=1 ;;
    esac
done

if [ "$BUILD" = "1" ]; then
    echo "=== building demo example ==="
    cargo build --example demo --release --all-features || exit 1
fi

DEMO_BIN="$REPO_ROOT/target/release/examples/demo"
[ -e "$DEMO_BIN" ] || { echo "ERROR: $DEMO_BIN not found; run with --build"; exit 1; }

KERNEL=$(uname -r)
VMLINUZ=/boot/vmlinuz-$KERNEL
[ -e "$VMLINUZ" ] || { echo "ERROR: no vmlinuz for kernel $KERNEL at $VMLINUZ"; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Persist the serial console log for CI artefact upload / debugging.
SERIAL_LOG="${REPO_ROOT}/.qemu-serial.log"
rm -f "$SERIAL_LOG"

echo "=== building initramfs ==="
DEMO_BIN="$DEMO_BIN" KERNEL="$KERNEL" "$SCRIPT_DIR/build-initramfs.sh" "$WORK/initramfs.cpio.gz" || exit 1

# /boot/vmlinuz-* is usually root-only; copy to a readable temp path for QEMU.
VMLINUZ_SAFE="$WORK/vmlinuz"
cp "$VMLINUZ" "$VMLINUZ_SAFE"

QEMU_SUDO=()
QEMU_ACCEL=()
if [ "${FORCE_TCG:-0}" != "1" ] && [ -e /dev/kvm ]; then
    # Prefer hardware acceleration. On GitHub runners /dev/kvm typically needs
    # root, for which passwordless sudo is available.
    if [ -w /dev/kvm ]; then
        QEMU_ACCEL=(-enable-kvm -cpu host)
        echo "=== using KVM acceleration ==="
    elif command -v sudo >/dev/null 2>&1; then
        QEMU_SUDO=(sudo)
        QEMU_ACCEL=(-enable-kvm -cpu host)
        echo "=== using KVM acceleration (via sudo) ==="
    else
        QEMU_ACCEL=(-cpu max)
        echo "=== /dev/kvm not writable and no sudo, falling back to TCG ==="
    fi
else
    QEMU_ACCEL=(-cpu max)
    echo "=== /dev/kvm not available, falling back to TCG (slow) ==="
fi

QEMU_CMD=("${QEMU_SUDO[@]}" qemu-system-x86_64 -m 512 -smp 2 "${QEMU_ACCEL[@]}" \
    -kernel "$VMLINUZ_SAFE" \
    -initrd "$WORK/initramfs.cpio.gz" \
    -append "console=ttyS0 panic=-1" \
    -display none \
    -serial "file:$SERIAL_LOG" \
    -monitor none \
    -no-reboot
)

echo "=== launching QEMU ==="
KVM_FAIL=0
if [[ " ${QEMU_CMD[*]} " == *" -enable-kvm "* ]]; then
    timeout 300 "${QEMU_CMD[@]}" 2>"$WORK/qemu.err" || { KVM_FAIL=$?; }
    # If KVM failed (e.g. permission), retry with TCG once.
    if [ "$KVM_FAIL" != "0" ]; then
        echo "=== KVM run returned $KVM_FAIL, retrying with TCG ==="
        rm -f "$SERIAL_LOG"
        timeout 600 "${QEMU_SUDO[@]}" qemu-system-x86_64 -m 512 -smp 2 -cpu max \
            -kernel "$VMLINUZ_SAFE" \
            -initrd "$WORK/initramfs.cpio.gz" \
            -append "console=ttyS0 panic=-1" \
            -display none -serial "file:$SERIAL_LOG" -monitor none -no-reboot \
            2>"$WORK/qemu.err" || true
    fi
else
    timeout 600 "${QEMU_CMD[@]}" 2>"$WORK/qemu.err" || true
fi

# Ensure the serial log is readable by the (non-root) caller for artifact upload.
[ -e "$SERIAL_LOG" ] && [ -n "${QEMU_SUDO[*]}" ] && sudo chmod 644 "$SERIAL_LOG" 2>/dev/null || true

echo "=== serial log (tail) ==="
tail -80 "$SERIAL_LOG" || true

if [ "$DUMP" = "1" ]; then
    echo "=== full serial log ==="
    cat "$SERIAL_LOG" 2>/dev/null || true
    echo "=== qemu stderr ==="
    cat "$WORK/qemu.err" 2>/dev/null || true
fi

if grep -q "TEST_RESULT: PASS" "$SERIAL_LOG"; then
    echo "SUCCESS: QEMU usbip test passed"
    echo "VERIFY_SERIAL=$(grep -c 'SERIAL_TEST: PASS' "$SERIAL_LOG")"
    echo "VERIFY_KEYBOARD=$(grep -c 'KEYBOARD_TEST: PASS' "$SERIAL_LOG")"
    exit 0
else
    echo "FAILURE: TEST_RESULT: PASS not found in serial log"
    exit 1
fi
