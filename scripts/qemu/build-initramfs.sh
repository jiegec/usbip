#!/usr/bin/env bash
# Build a minimal initramfs for the QEMU usbip end-to-end test.
#
# The initramfs bundles everything the guest needs to:
#   1. boot (via the host kernel, /boot/vmlinuz-$(uname -r))
#   2. load the vhci-hcd + cdc_acm kernel modules
#   3. run the compiled usbip demo server (our library under test)
#   4. run the usbip userspace client and attach the simulated devices
#
# Usage: build-initramfs.sh <output.cpio.gz>
#
# Overridable via env:
#   KERNEL      kernel version whose modules/kernel to use (default: uname -r)
#   BUSYBOX     path to a *static* busybox binary (default: `which busybox`)
#   USBIP       path to the usbip userspace binary (default: auto-detect)
#   DEMO_BIN    path to the compiled demo example (default: target/release/examples/demo)
set -euo pipefail
trap 'echo "ERROR: build-initramfs.sh failed at line $LINENO: $BASH_COMMAND" >&2' ERR

# Find a real (ELF) usbip binary. On Ubuntu the linux-tools-common package puts a
# tiny shell *script* at /usr/bin/usbip that execs a versioned binary; the usbip
# package installs the real binary at /usr/sbin/usbip. Prefer a real ELF.
find_usbip_bin() {
    local c
    for c in /usr/sbin/usbip /usr/lib/linux-tools/*/usbip /usr/bin/usbip; do
        [ -f "$c" ] || continue
        if head -c4 "$c" 2>/dev/null | grep -q ELF; then
            echo "$c"
            return 0
        fi
    done
    command -v usbip 2>/dev/null || echo /usr/sbin/usbip
}

OUT="${1:?usage: build-initramfs.sh <output.cpio.gz>}"
KERNEL="${KERNEL:-$(uname -r)}"
BUSYBOX="${BUSYBOX:-$(command -v busybox)}"
USBIP="${USBIP:-$(find_usbip_bin)}"
DEMO_BIN="${DEMO_BIN:-target/release/examples/demo}"

[ -e "$BUSYBOX" ] || { echo "ERROR: busybox not found at $BUSYBOX"; exit 1; }
[ -e "$USBIP" ] || { echo "ERROR: usbip not found at $USBIP"; exit 1; }
[ -e "$DEMO_BIN" ] || { echo "ERROR: demo binary not found at $DEMO_BIN"; exit 1; }

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

echo "kernel=$KERNEL busybox=$BUSYBOX usbip=$USBIP demo=$DEMO_BIN"

# --- binaries ---
mkdir -p "$ROOT/bin" "$ROOT/sbin" "$ROOT/usr/sbin" "$ROOT/usr/share/misc"
cp "$BUSYBOX" "$ROOT/bin/busybox"

# busybox applet symlinks (see init.sh for the applets we use)
for a in sh insmod modprobe ls cat dmesg grep sleep dd hexdump od mount mknod \
         poweroff reboot echo printf test head tail cp rm more seq timeout mkdir \
         sync umount true false mdev find ifconfig stty; do
    ln -sf busybox "$ROOT/bin/$a"
done
ln -sf busybox "$ROOT/sbin/modprobe"
ln -sf busybox "$ROOT/sbin/insmod"
ln -sf busybox "$ROOT/sbin/mdev"

# usbip: copy the client tool to several standard locations and to its real
# path. It may be a real binary or a symlink/script.
_usbip_real="$(readlink -f "$USBIP")"
for _dst in "$ROOT/usr/sbin/usbip" "$ROOT/usr/bin/usbip" "$ROOT$_usbip_real"; do
    mkdir -p "$(dirname "$_dst")"
    cp -L "$_usbip_real" "$_dst"
done
cp "$DEMO_BIN" "$ROOT/demo_server"

# --- kernel modules (decompress if needed, preserve layout) ---
for mod in usbip-core vhci-hcd cdc-acm; do
    ko=$(find "/lib/modules/$KERNEL" \( -name "$mod.ko" -o -name "$mod.ko.*" \) -print -quit 2>/dev/null)
    if [ -z "$ko" ]; then
        echo "ERROR: kernel module $mod.ko not found for kernel $KERNEL"
        exit 1
    fi
    case "$ko" in
        *.ko.zst) out="${ko%.zst}"; mkdir -p "$ROOT$(dirname "$out")"; zstd -d -c "$ko" > "$ROOT$out" ;;
        *.ko.xz)  out="${ko%.xz}";  mkdir -p "$ROOT$(dirname "$out")"; xz -d -c "$ko"  > "$ROOT$out" ;;
        *.ko.gz)  out="${ko%.gz}";  mkdir -p "$ROOT$(dirname "$out")"; gzip -d -c "$ko" > "$ROOT$out" ;;
        *)        mkdir -p "$ROOT$(dirname "$ko")"; cp -L "$ko" "$ROOT$ko" ;;
    esac
done

# --- usb.ids database required by the usbip tool ---
UI="$(find /usr/share -name usb.ids -print -quit 2>/dev/null)"
[ -n "$UI" ] && cp "$UI" "$ROOT/usr/share/misc/usb.ids" || echo "WARN: usb.ids not found"

# --- libraries needed by usbip + demo server ---
# Copy the dynamic loader and a comprehensive set of libc/system libraries
# explicitly so the guest always has a working glibc, even if `ldd` cannot
# resolve a given binary (e.g. a statically-linked or symlinked usbip tool).
mkdir -p "$ROOT/lib64" "$ROOT/lib/x86_64-linux-gnu"
for f in /lib64/ld-linux-x86-64.so.2; do
    [ -e "$f" ] && cp -L "$f" "$ROOT$f"
done
for lib in libc.so.6 libm.so.6 libgcc_s.so.1 libpthread.so.0 libdl.so.2 librt.so.1 \
           libudev.so.1 libcap.so.2 libcap-ng.so.0 libwrap.so.0 libusb-1.0.so.0; do
    src=""
    for d in /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu /lib64 /lib; do
        [ -e "$d/$lib" ] && { src="$d/$lib"; break; }
    done
    if [ -n "$src" ]; then
        mkdir -p "$ROOT$(dirname "$src")"
        cp -L "$src" "$ROOT$src"
    fi
done

# Additionally copy any libraries ldd can resolve. Process substitution avoids a
# `set -e`/pipefail abort if `ldd` itself returns non-zero.
copy_libs() {
    local bin="$1"
    local lib
    while IFS= read -r lib; do
        [ -e "$lib" ] || continue
        mkdir -p "$ROOT$(dirname "$lib")"
        cp -L "$lib" "$ROOT$lib"
    done < <(ldd "$bin" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*' | sort -u)
}
copy_libs "$USBIP"
copy_libs "$DEMO_BIN"

# --- device dirs (devtmpfs populates /dev at runtime) ---
mkdir -p "$ROOT/dev" "$ROOT/proc" "$ROOT/sys" "$ROOT/tmp"
mknod -m 666 "$ROOT/dev/console" c 5 1 2>/dev/null || true

# --- init script ---
cp "$(dirname "$0")/init.sh" "$ROOT/init"
chmod +x "$ROOT/init"

# --- cpio archive ---
( cd "$ROOT" && find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "$OUT" )
echo "wrote $OUT"
