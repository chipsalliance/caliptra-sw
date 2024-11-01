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

TARGET_DIR=../../target/riscv32imc-unknown-none-elf/firmware
CURRENT_DIR = $(shell pwd)
GIT_REV = $(shell git rev-parse HEAD)
EXTRA_CARGO_CONFIG = target.'cfg(all())'.rustflags = [\"-Dwarnings\"]

default: build

build:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu no-cfi"

build-emu:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu no-cfi"

build-test-fmc:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--manifest-path tools/test-fmc/Cargo.toml \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features emu

build-test-rt:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--manifest-path tools/test-rt/Cargo.toml \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features emu

gen-certs:
	$(shell bash $(CURRENT_DIR)/tools/scripts/gen_test_certs.sh $(TARGET_DIR))
	$(shell cp $(CURRENT_DIR)/tools/keys.toml $(TARGET_DIR))

build-fw-image: gen-certs build-test-fmc build-test-rt
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run \
		--manifest-path ../../image/app/Cargo.toml \
		-- \
		create \
		--key-config $(TARGET_DIR)/keys.toml \
		--ecc-pk-idx 3 \
		--lms-pk-idx 3 \
		--fmc $(TARGET_DIR)/caliptra-rom-test-fmc \
		--fmc-version 0 \
		--fmc-svn 0 \
		--fmc-rev $(GIT_REV) \
		--rt $(TARGET_DIR)/caliptra-rom-test-rt \
		--rt-version 0 \
		--rt-svn 0 \
		--rt-rev $(GIT_REV) \
		--out $(TARGET_DIR)/caliptra-rom-test-fw \

bloat: build
	 cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		bloat \
		--bin caliptra-rom \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu no-cfi" \
		-n 1000 \

objdump:
	 cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		objdump \
		--bin caliptra-rom \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu no-cfi" \
		-- \
		-d \
		--no-print-imm-hex \
		--disassembler-options=no-aliases \

build-rom:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run -p caliptra-builder -- \
		--rom-with-log $(TARGET_DIR)/caliptra-rom.bin \
		--fw /dev/null

run: build-emu build-fw-image build-rom
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run \
		-p caliptra-emu \
		-- \
		--req-idevid-csr \
		--idevid-key-id-algo sha1 \
		--rom $(TARGET_DIR)/caliptra-rom.bin \
		--recovery-image-fw $(TARGET_DIR)/caliptra-rom-test-fw \
		--device-lifecycle unprovisioned \

run-active: build-emu build-fw-image build-rom
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run \
		-p caliptra-emu \
		-- \
		--req-idevid-csr \
		--idevid-key-id-algo sha1 \
		--rom $(TARGET_DIR)/caliptra-rom.bin \
		--recovery-image-fw $(TARGET_DIR)/caliptra-rom-test-fw \
		--device-lifecycle unprovisioned \
		--active-mode \

run-update: build-emu build-fw-image build-rom
		cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run \
		-p caliptra-emu \
		-- \
		--req-idevid-csr \
		--idevid-key-id-algo sha1 \
		--rom $(TARGET_DIR)/caliptra-rom.bin \
		--recovery-image-fw $(TARGET_DIR)/caliptra-rom-test-fw \
		--update-recovery-image-fw $(TARGET_DIR)/caliptra-rom-test-fw \
		--device-lifecycle unprovisioned \


size:
	 cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		size \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--bin caliptra-rom \
		--features no-cfi \

nm:
	 cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		nm \
		--bin caliptra-rom \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features no-cfi \
		-- \
		-v \

hexdump: build-rom
	xxd $(TARGET_DIR)/caliptra-rom.bin \

clean:
	cargo clean

