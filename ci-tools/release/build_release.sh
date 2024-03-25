#!/bin/bash
# Licensed under the Apache-2.0 license

set -euo pipefail

# Check arg count
if [ $# -ne 1 ]
  then
    echo "Usage: $(basename $0) <release_name>"
	exit -1
fi

WORKSPACE_DIR="release/workspace"
release_scripts_path=$(dirname "$0")
# Generate Release Folder
rm -rf release
mkdir -p $WORKSPACE_DIR

# Generate ROM and Image Bundle Binary
cargo run --manifest-path=builder/Cargo.toml --bin image -- --rom-no-log $WORKSPACE_DIR/caliptra-rom.bin --fw $WORKSPACE_DIR/image-bundle.bin
# Copy ROM ELF
cp -a target/riscv32imc-unknown-none-elf/firmware/caliptra-rom $WORKSPACE_DIR/caliptra-rom.elf
# Copy FMC ELF
cp -a target/riscv32imc-unknown-none-elf/firmware/caliptra-fmc $WORKSPACE_DIR/caliptra-fmc.elf
# Copy Runtime FW ELF
cp -a target/riscv32imc-unknown-none-elf/firmware/caliptra-runtime $WORKSPACE_DIR/caliptra-runtime.elf

# Generate rom-with-log
cargo run --manifest-path=builder/Cargo.toml --bin image -- --rom-with-log $WORKSPACE_DIR/caliptra-rom-with-log.bin

# Copy ROM-with-log ELF
cp -a target/riscv32imc-unknown-none-elf/firmware/caliptra-rom $WORKSPACE_DIR/caliptra-rom-with-log.elf

# Generate fake ROM and Image Bundle Binary
cargo run --manifest-path=builder/Cargo.toml --bin image -- --fake-rom $WORKSPACE_DIR/fake-caliptra-rom.bin --fake-fw $WORKSPACE_DIR/fake-image-bundle.bin
# Copy fake ROM ELF
cp -a target/riscv32imc-unknown-none-elf/firmware/caliptra-rom $WORKSPACE_DIR/fake-caliptra-rom.elf
# Copy fake FMC ELF
cp -a target/riscv32imc-unknown-none-elf/firmware/caliptra-fmc $WORKSPACE_DIR/fake-caliptra-fmc.elf
# Copy fake Runtime FW ELF
cp -a target/riscv32imc-unknown-none-elf/firmware/caliptra-runtime $WORKSPACE_DIR/fake-caliptra-runtime.elf

# Copy RTL
cp -rf hw/1.0/rtl $WORKSPACE_DIR/caliptra-rtl
# Copy libcaliptra
cp -rf libcaliptra $WORKSPACE_DIR/libcaliptra
# Copy FPGA Model
cp -rf hw/fpga $WORKSPACE_DIR/fpga

# Calculate RTL hash
# Generate file list (excluding files integrators will modify)
$release_scripts_path/tools/generate_rtl_file_list.sh $WORKSPACE_DIR/caliptra-rtl $WORKSPACE_DIR/rtl_hash_file_list.txt
# Calculate hash
if ! rtl_hash=$($release_scripts_path/tools/rtl_hash.sh $WORKSPACE_DIR/caliptra-rtl/src $WORKSPACE_DIR/rtl_hash_file_list.txt); then
    echo "Failed to generate RTL hash"
    # Dump output from the failure
    echo "$rtl_hash"
    exit -1
fi
echo "RTL hash is $rtl_hash"
# Include hash tool with release
cp $release_scripts_path/tools/rtl_hash.sh $WORKSPACE_DIR/

# Generate Notes
echo -e "Caliptra HW Release Note " > $WORKSPACE_DIR/release_notes.txt
echo -e "Nightly $1" >> $WORKSPACE_DIR/release_notes.txt
echo -e "Caliptra-RTL Rev: $(git rev-parse HEAD:hw/1.0/rtl)" >> $WORKSPACE_DIR/release_notes.txt
echo -e "Caliptra-SW Rev: $(git rev-parse HEAD)" >> $WORKSPACE_DIR/release_notes.txt
echo -e "RTL hash (see rtl_hash.sh): $rtl_hash" >> $WORKSPACE_DIR/release_notes.txt
echo -e "Content:" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tRTL: caliptra-rtl/" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tROM Bin: caliptra-rom.bin" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tROM ELF: caliptra-rom.elf" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tImage Bundle Bin: image-bundle.bin" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tFMC ELF: caliptra-fmc.elf" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tRTFW ELF: caliptra-runtime.elf" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tFake ROM Bin: fake-caliptra-rom.bin" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tFake ROM ELF: fake-caliptra-rom.elf" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tFake Image Bundle Bin: fake-image-bundle.bin" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tFake FMC ELF: fake-caliptra-fmc.elf" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tFake RTFW ELF: fake-caliptra-runtime.elf" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tLIBCaliptra: libcaliptra/" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tFPGA Model: fpga/" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tRTL hash tool: rtl_hash.sh" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tRTL hash file list: rtl_hash_file_list.txt" >> $WORKSPACE_DIR/release_notes.txt

# Generate Zip
cd ./release/workspace
zip -r ../release.zip ./*
