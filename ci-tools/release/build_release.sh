#!/bin/bash
# Licensed under the Apache-2.0 license

set -euo pipefail

WORKSPACE_DIR="release/workspace"
# Generate Release Folder
rm -rf release
mkdir -p $WORKSPACE_DIR

# Generate ROM and Image Bundle Binary
cargo run --manifest-path=builder/Cargo.toml --bin image -- --rom $WORKSPACE_DIR/caliptra-rom.bin --fw $WORKSPACE_DIR/image-bundle.bin
# Generate ROM Hex
objcopy -I binary -O verilog $WORKSPACE_DIR/caliptra-rom.bin $WORKSPACE_DIR/caliptra-rom.hex
# Copy ROM ELF
cp -a target/riscv32imc-unknown-none-elf/firmware/caliptra-rom $WORKSPACE_DIR/caliptra-rom.elf
# Copy FMC ELF
cp -a target/riscv32imc-unknown-none-elf/firmware/caliptra-fmc $WORKSPACE_DIR/caliptra-fmc.elf
# Copy Runtime FW ELF
cp -a target/riscv32imc-unknown-none-elf/firmware/caliptra-runtime $WORKSPACE_DIR/caliptra-runtime.elf
# Copy RTL
cp -rf hw-latest/caliptra-rtl $WORKSPACE_DIR/caliptra-rtl
# Copy libcaliptra
cp -rf libcaliptra $WORKSPACE_DIR/libcaliptra

# Generate Notes
echo -e "Caliptra HW Release Note " > $WORKSPACE_DIR/release_notes.txt
echo -e "Nightly $1" >> $WORKSPACE_DIR/release_notes.txt
echo -e "Caliptra-RTL Rev: $(git rev-parse HEAD:hw-latest/caliptra-rtl)" >> $WORKSPACE_DIR/release_notes.txt
echo -e "Caliptra-SW Rev: $(git rev-parse HEAD)" >> $WORKSPACE_DIR/release_notes.txt
echo -e "Content:" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tRTL: caliptra-rtl/" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tROM Bin: caliptra-rom.bin" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tROM Hex: caliptra-rom.hex" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tROM ELF: caliptra-rom.elf" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tImage Bundle Bin: image-bundle.bin" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tFMC ELF: caliptra-fmc.elf" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tRTFW ELF: caliptra-runtime.elf" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tLIBCaliptra: libcaliptra/" >> $WORKSPACE_DIR/release_notes.txt

# Generate Zip
cd ./release/workspace
zip -r ../release.zip ./*
