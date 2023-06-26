# Licensed under the Apache-2.0 license

cd "$(dirname "${BASH_SOURCE[0]}")"

mkdir release_${{ steps.date.outputs.date }}
cargo run --manifest-path=../builder/Cargo.toml --bin image -- --rom caliptra_rom.bin --fw image_bundle.bin
objcopy -I binary -O verilog caliptra_rom.bin caliptra_rom.hex
cp -a ../target/riscv32imc-unknown-none-elf/firmware/* release_${{ steps.date.outputs.date }}/
cp caliptra_rom.hex release_${{ steps.date.outputs.date }}/
zip -r release_${{ steps.date.outputs.date }}.zip release_${{ steps.date.outputs.date }}
