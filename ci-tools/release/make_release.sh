# Licensed under the Apache-2.0 license

release_date=$1

mkdir release_$1
cargo run --manifest-path=builder/Cargo.toml --bin image -- --rom caliptra_rom.bin --fw image_bundle.bin
objcopy -I binary -O verilog caliptra_rom.bin caliptra_rom.hex
cp -a target/riscv32imc-unknown-none-elf/firmware/* release_$1/
cp caliptra_rom.hex release_$1/
zip -r release_$1.zip release_$1