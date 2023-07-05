#!/bin/bash
# Licensed under the Apache-2.0 license

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"/../..

mkdir release
mkdir release/workspace
cargo run --manifest-path=builder/Cargo.toml --bin image -- --rom caliptra_rom.bin --fw image_bundle.bin
objcopy -I binary -O verilog caliptra_rom.bin release/workspace/caliptra_rom.hex
cp -a target/riscv32imc-unknown-none-elf/firmware/* release/workspace/
cp image_bundle.bin release/workspace/

cd ./release/workspace
zip -r ../release.zip ./*
