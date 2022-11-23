#!/bin/bash

#
# Licensed under the Apache-2.0 license.
#
# File Name:
#     caliptra-test-runner.sh
#
# Abstract:
#
#     Caliptra Test runner script
#

# Terminate the script on error
set -e

ROM_FILE="$1.rom"

# Convert the ELF file to binary
rust-objcopy -O binary $1 $ROM_FILE

# Execute the ROM file
caliptra-emu --rom $ROM_FILE
