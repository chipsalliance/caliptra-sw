#!/usr/bin/env bash
#
# Licensed under the Apache-2.0 license.
#

set -e

CALIPTRA_ROOT=$(realpath "$(dirname "$( readlink -f -- "$0"; )")"/../../)

function usage() {
    echo "usage: $0"
}

function build_and_install_kernel_modules() {

    # io_module.ko
    if ! lsmod | grep -wq "io_module"
    then
        cd "$CALIPTRA_ROOT/hw/fpga/io_module" || exit 2
        make

        if [[ -f "$CALIPTRA_ROOT/hw/fpga/io_module/io_module.ko" ]]; then
            insmod "$CALIPTRA_ROOT/hw/fpga/io_module/io_module.ko"
            chmod 666 /dev/uio0
        else
            echo "[-] error inserting io module. module not found"
            exit 2
        fi
    fi
}

# entrypoint
if [[ $EUID -ne 0 ]]; then
    echo "[-] you must run this script as root"
    usage "$(basename "$0")"
    exit 1
fi

# main execution
echo "[*] Building and installing kernel modules"
build_and_install_kernel_modules
