#!/bin/bash
# Licensed under the Apache-2.0 license

set -euo pipefail

WORKSPACE_DIR="release/workspace"
# Generate Release Folder
rm -rf release
mkdir -p $WORKSPACE_DIR

# Generate ROM and Image Bundle Binary
cargo run --manifest-path=builder/Cargo.toml --bin image -- --rom-with-log $WORKSPACE_DIR/caliptra-rom.bin --fw $WORKSPACE_DIR/image-bundle.bin
# Generate ROM Hex
objcopy -I binary -O verilog $WORKSPACE_DIR/caliptra-rom.bin $WORKSPACE_DIR/caliptra-rom.hex
# Copy ROM ELF
cp -a target/riscv32imc-unknown-none-elf/firmware/caliptra-rom $WORKSPACE_DIR/caliptra-rom.elf
# Copy FMC ELF
cp -a target/riscv32imc-unknown-none-elf/firmware/caliptra-fmc $WORKSPACE_DIR/caliptra-fmc.elf
# Copy Runtime FW ELF
cp -a target/riscv32imc-unknown-none-elf/firmware/caliptra-runtime $WORKSPACE_DIR/caliptra-runtime.elf

# Generate fake ROM and Image Bundle Binary
cargo run --manifest-path=builder/Cargo.toml --bin image -- --fake-rom $WORKSPACE_DIR/fake-caliptra-rom.bin --fake-fw $WORKSPACE_DIR/fake-image-bundle.bin
# Generate fake ROM Hex
objcopy -I binary -O verilog $WORKSPACE_DIR/fake-caliptra-rom.bin $WORKSPACE_DIR/fake-caliptra-rom.hex
# Copy fake ROM ELF
cp -a target/riscv32imc-unknown-none-elf/firmware/caliptra-rom $WORKSPACE_DIR/fake-caliptra-rom.elf
# Copy fake FMC ELF
cp -a target/riscv32imc-unknown-none-elf/firmware/caliptra-fmc $WORKSPACE_DIR/fake-caliptra-fmc.elf
# Copy fake Runtime FW ELF
cp -a target/riscv32imc-unknown-none-elf/firmware/caliptra-runtime $WORKSPACE_DIR/fake-caliptra-runtime.elf

# Copy RTL
cp -rf hw-latest/caliptra-rtl $WORKSPACE_DIR/caliptra-rtl
# Copy libcaliptra
cp -rf libcaliptra $WORKSPACE_DIR/libcaliptra
# Copy FPGA Model
cp -rf hw-latest/fpga $WORKSPACE_DIR/fpga

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
echo -e "\tFake ROM Bin: fake-caliptra-rom.bin" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tFake ROM Hex: fake-caliptra-rom.hex" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tFake ROM ELF: fake-caliptra-rom.elf" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tFake Image Bundle Bin: fake-image-bundle.bin" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tFake FMC ELF: fake-caliptra-fmc.elf" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tFake RTFW ELF: fake-caliptra-runtime.elf" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tLIBCaliptra: libcaliptra/" >> $WORKSPACE_DIR/release_notes.txt
echo -e "\tFPGA Model: fpga/" >> $WORKSPACE_DIR/release_notes.txt

# Generate Zip
cd ./release/workspace
zip -r ../release.zip ./*
