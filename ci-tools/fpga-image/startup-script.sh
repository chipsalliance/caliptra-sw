#!/bin/bash

# Licensed under the Apache-2.0 license
#
# Startup script that is executed against the zcu104 UART. fpga-boss will
# connect to this UART (via on-board FTDI chip) and send commands.

# Stop spewing kernel noise to the UART
echo 3 > /proc/sys/kernel/printk

# Overlay exists so we can proceed.
if grep -q "overlay" /proc/mounts; then
    mount -o rw,remount /

    # TODO(clundin): Get this at job runtime instead.
    insmod /home/runner/io-module.ko

    # The VCK-190 image currently always has the same MAC. Do this for now until 
    # a better option is found.
    ip link set dev end0 down
    macchanger -r end0 || true
    ip link set dev end0 up

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

    # Run a root shell that can be used to debug any problems while the artifacts
    # are still in the filesystem.
    login -f root
    shutdown -h now
else
   # We need to mount the squashfs in an overlayfs. To spare myself more pain
   # wrestling with petalinux I will mount the overlay here (why not). Eventually
   # I want to do this the proper way but this will do for now.
  
   LOWER_DIR="/mnt/root_base"
   MERGED_DIR="/mnt/new_root"
   UPPER_MNT="/mnt/root_overlay"

   UPPER_DIR="${UPPER_MNT}/upper"
   WORK_DIR="${UPPER_MNT}/work"

   mount --bind / "${LOWER_DIR}"
   mount -t tmpfs tmpfs "${UPPER_MNT}"
   mkdir -p "${UPPER_DIR}" "${WORK_DIR}"
   mount -t overlay overlay \
     -o lowerdir="${LOWER_DIR}",upperdir="${UPPER_DIR}",workdir="${WORK_DIR}" \
     "${MERGED_DIR}"

   mount --make-rprivate /
   for m in dev proc sys run; do
     mount --move "/${m}" "${MERGED_DIR}/${m}"
   done

   mkdir -p "${MERGED_DIR}/old_root"
   cd "${MERGED_DIR}"
   pivot_root . old_root

   # Recursively call startup-script
   /usr/bin/startup-script.sh
fi
