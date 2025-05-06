#!/bin/bash
# Licensed under the Apache-2.0 license

# This script updates a Versal BOOT.BIN with a new xsa.
# When using an ubuntu image BOOT.BIN replaces boot1901.bin in the boot partition.

if [[ -z $1 ]]; then
    echo "update_boot_bin.sh [/path/to/caliptra_fpga_project_bd_wrapper.xsa]"
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

cd petalinux_project
echo Updating xsa
petalinux-config --get-hw-description $xsa_location --silentconfig

echo Packaging boot files
petalinux-package --boot --format BIN --plm --psmfw --u-boot --dtb --force
cd ../
