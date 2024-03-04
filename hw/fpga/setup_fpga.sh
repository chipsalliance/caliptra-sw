#!/usr/bin/env bash
#
# Licensed under the Apache-2.0 license.
#

set -e

CALIPTRA_ROOT=$(realpath "$(dirname "$( readlink -f -- "$0"; )")"/../../)

function usage() {
    echo "usage: $0 [binfile]"
}

function disable_cpu_idle() {
    for i in $(seq 0 3); do
        cpu_sysfs=/sys/devices/system/cpu/cpu"$i"/cpuidle/state1/disable
        echo 1 >"$cpu_sysfs"
        echo "    |- cpu[$i]"

        # verify options were set
        while IFS= read -r line; do
            if [[ "$line" -ne "1" ]]; then
                echo "[-] error setting cpu[$i] into idle state"
                exit 1
            fi
        done <"$cpu_sysfs"
    done
}

function reduce_fan_speed() {
    if [[ ! -d /sys/class/gpio/gpio321 ]]
    then
        echo 321 >/sys/class/gpio/export
        echo out >/sys/class/gpio/gpio321/direction
    fi
}

function build_and_install_kernel_modules() {
    # rom_backdoor.ko
    if ! lsmod | grep -wq "rom_backdoor"
    then
        cd "$CALIPTRA_ROOT/hw/fpga/rom_backdoor" || exit 2
        make

        if [[ -f "$CALIPTRA_ROOT/hw/fpga/rom_backdoor/rom_backdoor.ko" ]]; then
            insmod "$CALIPTRA_ROOT/hw/fpga/rom_backdoor/rom_backdoor.ko"
        else
            echo "[-] error inserting rom backdoor. module not found"
            exit 2
        fi
    fi

    # io_module.ko
    if ! lsmod | grep -wq "io_module"
    then
        cd "$CALIPTRA_ROOT/hw/fpga/io_module" || exit 2
        make

        if [[ -f "$CALIPTRA_ROOT/hw/fpga/io_module/io_module.ko" ]]; then
            insmod "$CALIPTRA_ROOT/hw/fpga/io_module/io_module.ko"
            chmod 666 /dev/uio4
        else
            echo "[-] error inserting io module. module not found"
            exit 2
        fi
    fi
}

function set_fpga_pll_freq() {
    echo 20000000 >/sys/bus/platform/drivers/xilinx_fclk/fclk0/set_rate
}

function install_fpga_image() {
    if [[ $# -ne 1 ]]; then
        echo "[-] no fpga image provided"
        exit 3
    fi

    fpga_image="$1"
    if [[ -z "$fpga_image" ]]; then
        echo "[-] image $fpga_image does not exist. exiting."
        exit 3
    fi

    fpgautil -b "$fpga_image" -f Full -n Full
}

# entrypoint
if [[ $EUID -ne 0 ]]; then
    echo "[-] you must run this script as root"
    usage "$(basename "$0")"
    exit 1
fi

# check parameters
if [[ $# -ne 1 ]]; then
    usage "$(basename "$0")"
    exit 1
fi

param_fpga_image="$1"

# main execution
echo "[*] Disabling CPU idle for cpu 0-3"
disable_cpu_idle

echo "[*] Reducing fan speeds"
reduce_fan_speed

echo "[*] Installing fpga image $param_fpga_image"
install_fpga_image "$param_fpga_image"

echo "[*] Building and installing kernel modules"
build_and_install_kernel_modules

echo "[*] Setting fpga frequency"
set_fpga_pll_freq
