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
# MLDSA (default): 1, LMS: 3.
PQC_KEY_TYPE ?= 1
# Device lifecycle state: unprovisioned, manufacturing, production
DEVICE_LIFECYCLE ?= production

default: build

build:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu"

build-emu:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu"

build-fmc:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--manifest-path ../../fmc/Cargo.toml \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features emu,riscv \
		--bin caliptra-fmc

build-test-fmc:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--manifest-path tools/test-fmc/Cargo.toml \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features emu

build-rt:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--manifest-path ../../runtime/Cargo.toml \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features emu,riscv \
		--bin caliptra-runtime

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

build-fw-test-image: gen-certs build-test-fmc build-test-rt
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run \
		--manifest-path ../../image/app/Cargo.toml \
		-- \
		create \
		--pqc-key-type $(PQC_KEY_TYPE) \
		--key-config $(TARGET_DIR)/keys.toml \
		--ecc-pk-idx 1 \
		--pqc-pk-idx 0 \
		--fmc $(TARGET_DIR)/caliptra-rom-test-fmc \
		--fmc-version 0 \
		--fmc-rev $(GIT_REV) \
		--rt $(TARGET_DIR)/caliptra-rom-test-rt \
		--rt-version 0 \
		--rt-rev $(GIT_REV) \
		--fw-svn 0 \
		--out $(TARGET_DIR)/caliptra-rom-test-fw \
		--print-hashes

build-fw-image: gen-certs build-fmc build-rt
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run \
		--manifest-path ../../image/app/Cargo.toml \
		-- \
		create \
		--pqc-key-type $(PQC_KEY_TYPE) \
		--key-config $(TARGET_DIR)/keys.toml \
		--ecc-pk-idx 1 \
		--pqc-pk-idx 0 \
		--fmc $(TARGET_DIR)/caliptra-fmc \
		--fmc-version 0 \
		--fmc-rev $(GIT_REV) \
		--rt $(TARGET_DIR)/caliptra-runtime \
		--rt-version 0 \
		--rt-rev $(GIT_REV) \
		--fw-svn 0 \
		--out $(TARGET_DIR)/caliptra-fw \
		--print-hashes

bloat: build
	 cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		bloat \
		--bin caliptra-rom \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu" \
		-n 1000 \

objdump:
	 cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		objdump \
		--bin caliptra-rom \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu" \
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

run: build-emu build-fw-test-image build-rom
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run \
		-p caliptra-emu \
		-- \
		--req-idevid-csr \
		--idevid-key-id-algo sha1 \
		--rom $(TARGET_DIR)/caliptra-rom.bin \
		--recovery-image-fw $(TARGET_DIR)/caliptra-rom-test-fw \
		--device-lifecycle $(DEVICE_LIFECYCLE) \
		--pqc-key-type $(PQC_KEY_TYPE) \
		$(if $(filter production manufacturing,$(DEVICE_LIFECYCLE)),--mfg-pk-hash \
			$$(dd if=$(TARGET_DIR)/caliptra-rom-test-fw bs=1 skip=12 count=1736 status=none | sha384sum | cut -d' ' -f1),)
# See image/types/src/lib.rs ImageManifest for offsets and lengths of vendor_pub_key_info

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
		--device-lifecycle $(DEVICE_LIFECYCLE) \
		--subsystem-mode \
		--pqc-key-type $(PQC_KEY_TYPE) \
		$(if $(filter production manufacturing,$(DEVICE_LIFECYCLE)),--mfg-pk-hash \
			$$(dd if=$(TARGET_DIR)/caliptra-rom-test-fw bs=1 skip=12 count=1736 status=none | sha384sum | cut -d' ' -f1),)
# See image/types/src/lib.rs ImageManifest for offsets and lenghts of vendor_pub_key_info


run-update: build-emu build-fw-test-image build-rom
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

nm:
	 cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		nm \
		--bin caliptra-rom \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		-- \
		-v \

hexdump: build-rom
	xxd $(TARGET_DIR)/caliptra-rom.bin \

clean:
	cargo clean
