#!/bin/bash
# Licensed under the Apache-2.0 license

# This script generates an SD card disk image that will boot on
# a VCK190 FPGA dev board, and be ready to accept GHA runner
# jitconfig passed in over UART by fpga-boss.

set -eux

mkdir -p out
SYSTEM_IMAGE="5a0f3d04034923c5f04371a656b7e948dcd9894b3ca4ad2fe8a1d52139124e6c"
if ! (echo "${SYSTEM_IMAGE} out/image.img.xz" | sha256sum -c); then
  curl -o out/image.img.xz -L "https://people.canonical.com/~platform/images/xilinx/versal-ubuntu-22.04/iot-limerick-versal-classic-server-2204-x02-20230315-48.img.xz"
  if ! (echo "${SYSTEM_IMAGE} out/image.img.xz" | sha256sum -c); then
    echo "Downloaded image file did not match expected sha256sum".
    exit 1
  fi
fi

(rm out/image.img || true)
(xz -d out/image.img.xz || true)

LOOPBACK_DEV="$(losetup --show -Pf out/image.img)"
function cleanup1 {
  losetup -d ${LOOPBACK_DEV}
}
trap cleanup1 EXIT

(rm -r out/bootfs || true)
mkdir -p out/bootfs

mount "${LOOPBACK_DEV}p1" out/bootfs

function cleanup2 {
  umount out/bootfs
  cleanup1
}
trap cleanup2 EXIT

# Load FPGA bit stream
# TODO: Get bitstream from GH actions
(rm out/boot1900.zip || true)
(rm out/boot1900.bin || true)
curl -L "https://github.com/clundin25/caliptra-sw/releases/download/release_v20241005_0/boot1900.zip" -o out/boot1900.zip
unzip out/boot1900.zip -d out/
cp out/boot1900.bin out/bootfs/boot1900.bin

umount out/bootfs
trap cleanup1 EXIT

(rm -r out/rootfs || true)
mkdir -p out/rootfs
mount "${LOOPBACK_DEV}p2" out/rootfs

function cleanup3 {
  umount out/rootfs
  cleanup1
}
trap cleanup3 EXIT

touch out/rootfs/etc/cloud/cloud-init.disabled
mkdir -p out/rootfs/etc/sudoers.d/
echo "runner ALL=(ALL) NOPASSWD:ALL" > out/rootfs/etc/sudoers.d/runner
chroot out/rootfs useradd runner --shell /bin/bash --create-home
chroot out/rootfs bash -c 'echo kernel.softlockup_panic = 1 >> /etc/sysctl.conf'
chroot out/rootfs bash -c 'echo kernel.softlockup_panic = 1 >> /etc/sysctl.conf'
chroot out/rootfs bash -c 'echo kernel.softlockup_all_cpu_backtrace = 1 >> /etc/sysctl.conf'
chroot out/rootfs bash -c 'echo kernel.panic_print = 127 >> /etc/sysctl.conf'
chroot out/rootfs bash -c 'echo kernel.sysrq = 1 >> /etc/sysctl.conf'

echo "Retrieving latest GHA runner version"
RUNNER_VERSION="$(curl https://api.github.com/repos/actions/runner/releases/latest | jq -r '.tag_name[1:]')"
echo Using runner version ${RUNNER_VERSION}
(cd out/rootfs/home/runner && curl -O -L "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz")
chroot out/rootfs bash -c "su runner -c \"cd /home/runner && tar xvzf actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz && rm -f actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz\""

su $SUDO_USER -c "
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=\"aarch64-linux-gnu-gcc\" \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS=\"-C link-arg=--sysroot=$PWD/out/rootfs\" \
~/.cargo/bin/cargo install cargo-nextest@0.9.64 \
--locked \
--no-default-features \
--features=default-no-update \
--target=aarch64-unknown-linux-gnu \
--root /tmp/cargo-nextest"

cp /tmp/cargo-nextest/bin/cargo-nextest out/rootfs/usr/bin/

cp startup-script.sh out/rootfs/usr/bin/
chroot out/rootfs chmod 755 /usr/bin/startup-script.sh
cp startup-script.service out/rootfs/etc/systemd/system/
chroot out/rootfs systemctl enable startup-script.service

# We want to boot into the startup-script, not cloud-init.
chroot out/rootfs systemctl disable cloud-init.service

umount out/rootfs
losetup -d ${LOOPBACK_DEV}
trap - EXIT
