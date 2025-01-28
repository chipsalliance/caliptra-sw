#!/bin/bash
# Licensed under the Apache-2.0 license

# This script generates a Versal BOOT.BIN using Petalinux.
# When using an ubuntu image this replaces boot1901.bin in the boot partition.

if [[ -z $1 ]]; then
    echo "create_boot_bin.sh [/path/to/caliptra_fpga_project_bd_wrapper.xsa]"
    exit
fi

echo Deleting old project
rm -rf petalinux_project
echo Creating project
petalinux-create project --template versal --name petalinux_project
cd petalinux_project
echo Adding xsa
petalinux-config --get-hw-description=$1 --silentconfig

echo Changing to 
sed -i 's/CONFIG_SUBSYSTEM_ROOTFS_INITRD=y/CONFIG_SUBSYSTEM_ROOTFS_INITRD=n/g' project-spec/configs/config
sed -i 's/# CONFIG_SUBSYSTEM_ROOTFS_EXT4 is not set/CONFIG_SUBSYSTEM_ROOTFS_EXT4=y/g' project-spec/configs/config

echo Building FW components, only device-tree depends on XSA
petalinux-build -c device-tree
petalinux-build -c u-boot
petalinux-build -c arm-trusted-firmware
petalinux-build -c plm
petalinux-build -c psmfw

echo Modify device tree for 2024.2
dtc -I dtb -O dts -o images/linux/system.dts images/linux/system.dtb
sed -i 's/primecell/sbsa-uart/g' images/linux/system.dts
dtc -I dts -O dtb -o images/linux/system.dtb images/linux/system.dts

echo Pakaging boot files
petalinux-package boot --format BIN --plm --psmfw --u-boot --dtb --force
cd ../