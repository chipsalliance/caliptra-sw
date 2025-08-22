#!/bin/bash
# Licensed under the Apache-2.0 license

# This script generates an SD card disk image that will boot on
# a zcu104 Zynq FPGA dev board, and be ready to accept GHA runner
# jitconfig passed in over UART by fpga-boss.

set -ex

mkdir -p out
BUILD_DEV_IMAGE=true

mv ${KERNEL_ARCHIVE} out/system-boot.tar.gz
mv ${KERNEL_MODULE_ARCHIVE}  out/io-module.ko

# Build the rootfs
if [[ -z "${SKIP_DEBOOTSTRAP}" ]]; then
  (rm -rf out/rootfs || true)
  mkdir -p out/rootfs
  PACKAGES="git,curl,ca-certificates,locales,libicu72,sudo,vmtouch,fping,rdnssd,dbus,systemd-timesyncd,libboost-regex1.74.0,openocd,gdb-multiarch,macchanger"
  if [[ -n "$BUILD_DEV_IMAGE" ]]; then
    PACKAGES="$PACKAGES,ssh,rsync,tmux"
  fi
  debootstrap --include "$PACKAGES" --arch arm64 --foreign bookworm out/rootfs
  chroot out/rootfs /debootstrap/debootstrap --second-stage
  chroot out/rootfs useradd runner --shell /bin/bash --create-home

  # Jobs need to act as root to install an FPGA bitstream. We don't care
  # if they mess up the rootfs because it's going to be re-flashed after the job
  # terminates anyways.
  echo "runner ALL=(ALL) NOPASSWD:ALL" > out/rootfs/etc/sudoers.d/runner

  chroot out/rootfs mkdir /mnt/root_base
  chroot out/rootfs mkdir /mnt/root_overlay
  chroot out/rootfs mkdir /mnt/new_root

  chroot out/rootfs bash -c 'echo caliptra-fpga > /etc/hostname'
  chroot out/rootfs bash -c 'echo auto end0 > /etc/network/interfaces'
  chroot out/rootfs bash -c 'echo allow-hotplug end0 >> /etc/network/interfaces'
  chroot out/rootfs bash -c 'echo iface end0 inet dhcp >> /etc/network/interfaces'
  chroot out/rootfs bash -c 'echo iface end0 inet6 auto >> /etc/network/interfaces'
  chroot out/rootfs bash -c 'echo nameserver 8.8.8.8 > /etc/resolv.conf'
  chroot out/rootfs bash -c 'echo nameserver 2001:4860:4860::6464 > /etc/resolv.conf'
  chroot out/rootfs bash -c 'echo nameserver 2001:4860:4860::64 >> /etc/resolv.conf'
  chroot out/rootfs bash -c 'echo kernel.softlockup_panic = 1 >> /etc/sysctl.conf'
  chroot out/rootfs bash -c 'echo kernel.softlockup_all_cpu_backtrace = 1 >> /etc/sysctl.conf'
  chroot out/rootfs bash -c 'echo kernel.panic_print = 127 >> /etc/sysctl.conf'
  chroot out/rootfs bash -c 'echo kernel.sysrq = 1 >> /etc/sysctl.conf'
  chroot out/rootfs bash -c 'echo "[Time]" > /etc/systemd/timesyncd.conf'
  chroot out/rootfs bash -c 'echo "NTP=time.google.com" >> /etc/systemd/timesyncd.conf'

  if [[ -n "$BUILD_DEV_IMAGE" ]]; then
      echo "Adding developer keys to image"
      chroot out/rootfs bash -c "echo \"PubkeyAuthentication yes\" >> /etc/ssh/sshd_config" 
      chroot out/rootfs bash -c "echo \"PasswordAuthentication no\" >> /etc/ssh/sshd_config" 
      chroot out/rootfs bash -c "su runner -c \"mkdir /home/runner/.ssh\""

      # Add clundin
      chroot out/rootfs bash -c "su runner -c \"echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDDKTJ6unwymfvdFSTNAXo+wjaX1l2SFPgeSgK/xzC7ex3oGR2ihCg/8luQt1e6FKnbqV83O2v0AT/aRw9p9sEjY7HGNDz+0nQ6lezi4XAuqJMOMshzVlqv4hZJLb8Ab2PMma0se15h1LhnfSUpttv7cDgdLXHqh2kizMQ39l62Lu4j2ITJKFhqW1v7Ez74uo2o++We6EHU2PRZhyKV9tKbYXojOyow+abUXKMfXy01iCSunaQq6KRB6Jl5TskMVmGSz0rUnjyxLCCPEA2h7D0lgQviLuJQtIl/jFYu8QFNqaVwHDHiEUpNfcfQGx6S7hpSs7CdPD29YQSka9TovICyD3dCKGn+tpfRQDmZSTR8Qnqv4mNtxKPcitpMFNVL9V6Echqy83rlo5CgO1tEsL/6g0WEm6nrFBMs/szUfv1qs4/4wL0PsNit1ArxfqYXVaDzGisvA+Y4yRl2IsMPaI7TzB6uDSR0j31jZXSGR8vqPG9rF+aGobF21OfWGHI8Ddc= clundin@clundin-macbookpro.roam.internal >> ~/.ssh/authorized_keys\""

      # Add zhalvorsen
      chroot out/rootfs bash -c "su runner -c \"echo ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBLCee6PZ63j9MXxo2LIB6K7I5WmIKJAWdww922p9klsKVhLkMpNPXkLtYaf44GDLSmNO1j2stkXw174agt722rAa6fNInSCY8HPpAlyAJ7xELEGDOb5FfQVJU5ruGYJ7LQ== zhalvorsen@zhalvorsen.c.googlers.com >> ~/.ssh/authorized_keys\""

      # Add ttrippel
      chroot out/rootfs bash -c "su runner -c \"echo ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAC3/lGx3rPr9Nns3aAS8faxKHOj/jgqLNFpjfXehz2kGhNC2EGRibXBHHP738KEG+rjA8HOsG8oHFmTFcOBJf+UqgDNmIfx7M5Db3cEgvhMcZSWck3Nb6ouIBwVchFgAupohpKmGroNuLB5QDuOE3cA8U7zN3y1L8uhUrDAxNPmS2Dvag== ttrippel@ttrippel.svl.corp.google.com >> ~/.ssh/authorized_keys\""

      # Add jhand
      chroot out/rootfs bash -c "su runner -c \"echo ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNAmcxogmvhKGQy/kd5R+uB382XiSb1p/hlqx/lJv3IcxT3JDVk2cRuVxipirplizT6g5+a5FWH6fGrOizQ/Rd0= publickey >> ~/.ssh/authorized_keys\""
  fi

  # Comment this line out if you don't trust folks with physical access to the
  # uart
  # chroot out/rootfs bash -c 'echo root:password | chpasswd'
  #

  echo Retrieving latest GHA runner version
  RUNNER_VERSION="$(curl https://api.github.com/repos/actions/runner/releases/latest | jq -r '.tag_name[1:]')"
  echo Using runner version ${RUNNER_VERSION}
  trap - EXIT
  (cd out/rootfs/home/runner && curl -O -L "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz")
  chroot out/rootfs bash -c "su runner -c \"cd /home/runner && tar xvzf actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz && rm -f actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz\""
fi

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

chroot out/rootfs bash -c 'echo ::1 caliptra-fpga >> /etc/hosts'
cp startup-script.sh out/rootfs/usr/bin/
chroot out/rootfs systemctl set-default multi-user.target
chroot out/rootfs chmod 755 /usr/bin/startup-script.sh
cp startup-script.service out/rootfs/etc/systemd/system/
chroot out/rootfs systemctl enable startup-script.service

cp out/io-module.ko out/rootfs/home/runner/io-module.ko

# Build a squashed filesystem from the rootfs
rm out/rootfs.sqsh || true
sudo mksquashfs out/rootfs out/rootfs.sqsh -comp zstd
bootfs_blocks="$((80000 * 4))"
rootfs_bytes="$(stat --printf="%s" out/rootfs.sqsh)"
rootfs_blocks="$((($rootfs_bytes + 512) / 512))"
persistfs_blocks=14680064

# Allocate the disk image
fallocate -l $(((2048 + 8 + $bootfs_blocks + $rootfs_blocks + $persistfs_blocks) * 512)) out/image.img

# Partition the disk image
cat <<EOF | sfdisk out/image.img
label: dos
label-id: 0x4effe30a
device: image.img
unit: sectors
sector-size: 512

p1 : start=2048, size=${bootfs_blocks}, type=c, bootable
p2 : start=$((2048 + $bootfs_blocks)), size=8, type=83
p3 : start=$((2048 + 8 + $bootfs_blocks)), size=${rootfs_blocks}, type=83
p4 : start=$((2048 + 8 + $bootfs_blocks + $rootfs_blocks)), size=${persistfs_blocks}, type=83
EOF
truncate -s $(((2048 + 8 + $bootfs_blocks + $rootfs_blocks) * 512)) out/image.img


LOOPBACK_DEV="$(losetup --show -Pf out/image.img)"
function cleanup1 {
  losetup -d ${LOOPBACK_DEV}
}
trap cleanup1 EXIT

# Format bootfs partition (kernel + bootloader stages)
mkfs -t vfat "${LOOPBACK_DEV}p1"

# Mount bootfs partition (from image) for modification
mkdir -p out/bootfs
mount "${LOOPBACK_DEV}p1" out/bootfs

function cleanup2 {
  umount out/bootfs
  cleanup1
}
trap cleanup2 EXIT

# Write bootfs contents
tar xvzf out/system-boot.tar.gz -C out/bootfs --no-same-owner

# Replace the u-boot boot script with our own
umount out/bootfs
trap cleanup1 EXIT

# Write the rootfs squashed filesystem to the image partition
dd if=out/rootfs.sqsh of="${LOOPBACK_DEV}p3"

# Write a sentinel value to the configuration partition
echo CONFIG_PARTITION > "${LOOPBACK_DEV}p2"
