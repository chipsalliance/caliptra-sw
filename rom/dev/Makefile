##
#
# Licensed under the Apache-2.0 license.
#
# File Name:
#
#    Makefile
#
# Abstract:
#
#    File contains helper routines for building debugging Caliptra ROM.
#
##

RUSTFLAGS=RUSTFLAGS=-Ctarget-feature=+relax
TARGET_DIR=../../target/riscv32imc-unknown-none-elf/firmware
CURRENT_DIR = $(shell pwd)
GIT_REV = $(shell git rev-parse HEAD)

default: build

build:
	$(RUSTFLAGS) cargo build \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \

build-emu:
	$(RUSTFLAGS) cargo build \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features emu \
		
build-test-fmc:
	$(RUSTFLAGS) cargo build \
		--profile firmware \
		--manifest-path tools/test-fmc/Cargo.toml \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features emu \

build-test-rt:
	$(RUSTFLAGS) cargo build \
		--profile firmware \
		--manifest-path tools/test-rt/Cargo.toml \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features emu \

gen-certs:
	$(shell bash $(CURRENT_DIR)/tools/scripts/gen_test_certs.sh $(TARGET_DIR))
	$(shell cp $(CURRENT_DIR)/tools/keys.toml $(TARGET_DIR))

build-fw-image: gen-certs build-test-fmc build-test-rt
	cargo run \
		--manifest-path ../../image/app/Cargo.toml \
		-- \
		create \
		--key-config $(TARGET_DIR)/keys.toml \
		--ecc-pk-idx 3 \
		--fmc $(TARGET_DIR)/caliptra-rom-test-fmc \
		--fmc-svn 0 \
		--fmc-min-svn 0 \
		--fmc-rev $(GIT_REV) \
		--rt $(TARGET_DIR)/caliptra-rom-test-rt \
		--rt-svn 0 \
		--rt-min-svn 0 \
		--rt-rev $(GIT_REV) \
		--out $(TARGET_DIR)/caliptra-rom-test-fw \
		
bloat: build
	$(RUSTFLAGS) cargo bloat \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		-n 1000 \

objdump:
	$(RUSTFLAGS) cargo objdump \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
 		-- \
		-d \
		--no-print-imm-hex \
		--disassembler-options=no-aliases \

objcopy:
	riscv64-unknown-elf-objcopy \
		--gap-fill 0x00 \
		--pad-to 0x8000 \
  		-j .text \
  		-j .rodata \
  		-O binary \
  		$(TARGET_DIR)/caliptra-rom \
  		$(TARGET_DIR)/caliptra-rom.bin \

run: build-emu build-fw-image objcopy
	cargo run \
		--manifest-path ../../sw-emulator/Cargo.toml \
		--release \
		--bin caliptra-emu \
		-- \
		--idevid-key-id-algo sha1 \
		--rom $(TARGET_DIR)/caliptra-rom.bin \
		--firmware $(TARGET_DIR)/caliptra-rom-test-fw \
		--device-lifecycle unprovisioned \

run-update: build-emu build-fw-image objcopy
		cargo run \
		--manifest-path ../../sw-emulator/Cargo.toml \
		--release \
		--bin caliptra-emu \
		-- \
		--req-idevid-csr \
		--idevid-key-id-algo sha1 \
		--rom $(TARGET_DIR)/caliptra-rom.bin \
		--firmware $(TARGET_DIR)/caliptra-rom-test-fw \
		--update-firmware $(TARGET_DIR)/caliptra-rom-test-fw \
		--device-lifecycle unprovisioned \


size:
	$(RUSTFLAGS) cargo size \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		
nm:
	$(RUSTFLAGS) cargo nm \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		-- \
		-v \

hexdump: objcopy
	xxd $(TARGET_DIR)/caliptra-rom.bin \
	
clean:
	cargo clean

