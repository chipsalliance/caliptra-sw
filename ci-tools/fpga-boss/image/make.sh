#!/bin/bash

# Licensed under the Apache-2.0 license
#
# WIP scripts for building a rPi SD image for hosting fpga-boss and bridging
# network connectivity.

set -e

if [ -z "$1" ]; then
    echo "Usage: make.sh 2023-05-03-raspios-bullseye-arm64-lite.img.xz"
    exit 1
fi

xz -dkc "$1" > fpgaboss.img
LOOPBACK_DEV="$(losetup --show -Pf fpgaboss.img)"
function cleanup1 {
	echo cleanup1
	losetup -d ${LOOPBACK_DEV}
}
trap cleanup1 EXIT

losetup -c ${LOOPBACK_DEV}

sudo mkdir -p mnt/p1
mount ${LOOPBACK_DEV}p1 mnt/p1
function cleanup2 {
	echo cleanup2
	umount mnt/p1
	cleanup1
}
trap cleanup2 EXIT
sudo bash -c 'echo enable_uart=1 >> mnt/p1/config.txt'
sudo umount mnt/p1
trap cleanup1 EXIT

sudo mkdir -p mnt/p2
mount ${LOOPBACK_DEV}p2 mnt/p2
function cleanup2 {
	echo cleanup2
	umount mnt/p2
	cleanup1
}
trap cleanup2 EXIT

chroot mnt/p2 apt-get update 
chroot mnt/p2 apt-get upgrade -y
chroot mnt/p2 apt-get install -y libftdi1-dev symlinks jq ipv6calc radvd
chroot mnt/p2 bash -c 'cd /usr/lib/aarch64-linux-gnu && symlinks -c -r .'
cp radvd.conf.template mnt/p2/etc/
cp 71-fpga-proxy.conf mnt/p2/lib/dhcpcd/dhcpcd-hooks/
