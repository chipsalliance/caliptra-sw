#!/bin/bash
# Licensed under the Apache-2.0 license

# Generate and apply a deterministic, board-unique MAC address for network interfaces.
# This prevents MAC address collisions on the local network between multiple FPGA boards
# while ensuring the MAC address remains stable across reboots of the same board.

set -e

IFACE="${1:-end0}"

get_hardware_seed() {
    # SD Card CID (128-bit unique hardware card identification register on the boot SD card)
    if [ -f /sys/block/mmcblk0/device/cid ]; then
        local cid
        cid=$(tr -d '\n\r\0' < /sys/block/mmcblk0/device/cid 2>/dev/null | xargs)
        if [ -n "$cid" ]; then
            echo "$cid"
            return 0
        fi
    fi

    # Fallback seed if SD card CID is unavailable (e.g. QEMU or container)
    echo "caliptra-fpga-default-seed"
}

SEED=$(get_hardware_seed)
HASH=$(echo -n "$SEED" | sha256sum | awk '{print $1}')

# Construct locally administered unicast MAC address (02:xx:xx:xx:xx:xx)
MAC="02:${HASH:0:2}:${HASH:2:2}:${HASH:4:2}:${HASH:6:2}:${HASH:8:2}"

if [ "$1" = "--print" ]; then
    echo "$MAC"
    exit 0
fi

if ip link show "$IFACE" >/dev/null 2>&1; then
    CURRENT_MAC=$(ip link show "$IFACE" | grep -oE 'link/ether [0-9a-fA-F:]+' | awk '{print $2}')
    if [ "$CURRENT_MAC" != "$MAC" ]; then
        echo "Setting MAC address for $IFACE to $MAC (seed: $SEED)"
        ip link set dev "$IFACE" down 2>/dev/null || true
        ip link set dev "$IFACE" address "$MAC"
        ip link set dev "$IFACE" up 2>/dev/null || true
    fi
fi
