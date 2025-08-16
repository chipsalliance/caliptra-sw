#!/bin/bash
# Licensed under the Apache-2.0 license

# This script generates a Versal BOOT.BIN using Petalinux.
# When using an ubuntu image BOOT.BIN replaces boot1901.bin in the boot partition.

if [[ -z $1 ]]; then
    echo "create_boot_bin.sh [/path/to/caliptra_fpga_project_bd_wrapper.xsa]"
    exit
fi

xsa_location=$(realpath $1)

set -e
trap '{
  if [ $? -ne 0 ]
  then
    echo FAILED TO CREATE BOOT.BIN
    exit 1
  else
    echo SUCCESS
  fi  
}' EXIT

echo "BUILD_SS: ${BUILD_SS}"

if [[ -z "${BUILD_SS}" ]]; then
  echo "Copying io_module source code"
  cp io_module/io_module.c petalinux_project/project-spec/meta-user/recipes-modules/io-module/files/io-module.c
else
  echo "Copying mcu io_module source code"
  cp io_module/mcu_io_module.c petalinux_project/project-spec/meta-user/recipes-modules/io-module/files/io-module.c
fi

cd petalinux_project

echo Adding xsa
petalinux-config --get-hw-description $xsa_location --silentconfig

echo Building FW components
petalinux-build

echo Modify device tree for 2024.2
dtc -I dtb -O dts -o images/linux/system.dts images/linux/system.dtb
# Enable versal-gpio
sed -i '/versal-gpio/{n;s/disabled/okay/}' images/linux/system.dts
dtc -I dts -O dtb -o images/linux/system.dtb images/linux/system.dts

echo Packaging boot files
petalinux-package --boot --format BIN --plm --psmfw --u-boot --dtb --force

echo "Building io-module"
petalinux-build -c io-module

cd ../
