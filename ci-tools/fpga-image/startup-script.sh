#!/bin/bash

# Licensed under the Apache-2.0 license
#
# Startup script that is executed against the zcu104 UART. fpga-boss will
# connect to this UART (via on-board FTDI chip) and send commands.

# Stop spewing kernel noise to the UART
echo 3 > /proc/sys/kernel/printk

# The VCK-190 image currently always has the same MAC. Do this for now until 
# a better option is found.
ip link set dev end0 down
macchanger -r end0 || true
ip link set dev end0 up

# Load the IO module if it exists
if [[ -f "/home/runner/io-module.ko" ]]; then
    echo "Installing io-module.ko..."
    insmod /home/runner/io-module.ko
fi

# Developer mode (mutable filesystem)
if [[ -f "/etc/no_overlayfs" ]]; then
    echo "Developer mode: Skipping CI startup logic."
    systemctl start resize-rootfs
    login -f root
else
    # CI mode (overlaid writable filesystem)
    echo "CI mode: Starting command loop..."

    function runner_jitconfig() {
      echo "Executing GHA runner"
      su runner -c "/home/runner/run.sh --jitconfig \"${cmd_array[1]}\""
      echo "GHA runner complete"
    }

    # Emit a sentinel that tells fpga-boss (listening via UART)
    # that we are ready for input.
    echo "36668aa492b1c83cdd3ade8466a0153d --- Command input"
    echo Available commands:
    echo "  runner-jitconfig <base64>"
    echo "  login"
    read -e -p "> " cmd

    cmd_array=($cmd)
    if [[ "${cmd}" == "login" ]]; then
        login -f root
    elif [[ "${cmd_array[0]}" == "runner-jitconfig" ]]; then
        runner_jitconfig
    else
        echo "Unknown command ${cmd}"
    fi

    # Emit a sentinel that tells fpga-boss (listening via UART)
    # that we are done and can be reset.
    echo "3297327285280f1ffb8b57222e0a5033 --- ACTION IS COMPLETE"

    # Run a root shell for debugging
    login -f root
    shutdown -h now
fi
