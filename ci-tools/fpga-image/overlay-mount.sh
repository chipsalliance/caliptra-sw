#!/bin/sh
# Licensed under the Apache-2.0 license

# Setup basic PATH
export PATH=/sbin:/bin:/usr/sbin:/usr/bin

# Path for the log file (in RAM)
LOG_FILE="/run/overlay-mount.log"

# Check if we should skip overlay (Developer Mode)
if [ -f /etc/no_overlayfs ]; then
    echo "Developer mode detected. Skipping overlay."
    mount -o rw,remount /
    exec /lib/systemd/systemd
fi

# Ensure basic directories exist
mkdir -p /proc /sys /dev /run /mnt/root_base /mnt/root_overlay /mnt/new_root

# Mount essential virtual filesystems
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /run

echo "Starting Overlay Mount Script..." > "${LOG_FILE}"

# Setup the overlay
echo "Mounting lower layer..." >> "${LOG_FILE}"
mount --bind / /mnt/root_base

echo "Creating writable upper layer (tmpfs)..." >> "${LOG_FILE}"
mount -t tmpfs tmpfs /mnt/root_overlay
mkdir -p /mnt/root_overlay/upper /mnt/root_overlay/work

echo "Assembling overlayfs..." >> "${LOG_FILE}"
mount -t overlay overlay \
  -o lowerdir=/mnt/root_base,upperdir=/mnt/root_overlay/upper,workdir=/mnt/root_overlay/work \
  /mnt/new_root

# Move virtual filesystems to the new merged root
echo "Moving virtual filesystems..." >> "${LOG_FILE}"
mount --move /dev /mnt/new_root/dev
mount --move /proc /mnt/new_root/proc
mount --move /sys /mnt/new_root/sys
mount --move /run /mnt/new_root/run

# Prepare to switch root
echo "Switching to overlay root and starting systemd..." >> "${LOG_FILE}"
cd /mnt/new_root
mkdir -p old_root
pivot_root . old_root

# Hand off to real init (systemd)
# We are now inside the new root, so paths are relative to it
exec /lib/systemd/systemd
