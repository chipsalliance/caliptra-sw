#!/usr/bin/env bash

CALIPTRA_ROOT=$(pwd)

function disable_cpu_idle() {
    for i in $(seq 1 3); do
        cpu_sysfs=/sys/devices/system/cpu/cpu"$i"/cpuidle/state1/disable
        echo 1  > "$cpu_sysfs"
        echo "    |- cpu[$i]"

        # verify options were set
        while IFS= read -r line; do
            if [[ "$line" -ne "1" ]];then
                echo "[-] error setting cpu[$i] into idle state"
            fi
        done < "$cpu_sysfs"
    done
}

function reduce_fan_speed() {
    echo 321    > /sys/class/gpio/export
    echo out    > /sys/class/gpio/gpio321/direction
}

function build_and_install_kernel_modules() {
    # rom_backdoor.ko
    cd "$CALIPTRA_ROOT"/hw-latest/fpga/rom_backdoor || exit 2
    make

    if [[ -f "$CALIPTRA_ROOT/hw-latest/fpga/rom_backdoor/rom_backdoor.ko" ]];then
        insmod "$CALIPTRA_ROOT/hw-latest/fpga/rom_backdoor/rom_backdoor.ko"  
    fi

    # io_module
    cd "$CALIPTRA_ROOT"/hw-latest/fpga/io_module || exit 2
    make

    if [[ -f "$CALIPTRA_ROOT/hw-latest/fpga/rom_backdoor/rom_backdoor.ko" ]];then
        insmod "$CALIPTRA_ROOT/hw-latest/fpga/rom_backdoor/rom_backdoor.ko"
        chmod 666 /dev/uio4
    fi
}

function set_fpga_pll_freq() {
    echo 20000000   > /sys/bus/platform/drivers/xilinx_fclk/fclk0/set_rate
}

function install_fpga_image() {
    if [[ $# -ne 1 ]];then
        exit 3
    fi
    
    fpga_image="$1"
    if [[ -z "$fpga_image" ]];then
        echo "[-] image $fpga_image does not exist. exiting."
        exit 3
    fi

    fpgautil -b "$fpga_image" -f Full -n Full
}

# entryppoint
if [[ $EUID -ne 0 ]];then
    echo "[-] you must run this script as root"
    exit 1
fi

# check parameters
if [[ $# -ne 1 ]];then
    echo "[-] not enough aruments"
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
