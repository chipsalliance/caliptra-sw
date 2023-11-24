#!/bin/bash

# Licensed under the Apache-2.0 license
#
# Startup script that is executed against the zcu104 UART. fpga-boss will
# connect to this UART (via on-board FTDI chip) and send commands.

# Stop spewing kernel noise to the UART
echo 3 > /proc/sys/kernel/printk

function runner_jitconfig() {
  echo "Executing GHA runner"
  su runner -c "./run.sh --jitconfig \"${cmd_array[1]}\""
  echo "GHA runner complete"
}

# Emit a sentinel that tells fpga-boss (listening via UART)
# that we are ready for input.
echo "36668aa492b1c83cdd3ade8466a0153d --- Command input"
echo Available commands:
echo "  runner-jitconfig <base64>"
echo "  login"
echo -n "> "

read cmd
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
