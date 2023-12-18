LIBCALIPTRA_DIR = ../../libcaliptra
HW_MODEL_C_DIR = ../../hw-model/c-binding
TARGET_DIR = ../../target
BUILDER_DIR = ../../builder

DPE_VERSION = $(shell cargo tree -p dpe | head -1 | sed -e 's/.*#//' -e 's/.$$//' )

ROM_FILE = /tmp/caliptra_rom.bin
FW_FILE  = /tmp/image_bundle.bin

LIBCALIPTRA = $(LIBCALIPTRA_DIR)/libcaliptra.a
LIB_HW_MODEL = $(TARGET_DIR)/debug/libcaliptra_hw_model_c_binding.a

EXTRA_CARGO_CONFIG = target.'cfg(all())'.rustflags = [\"-Dwarnings\"]

.PHONY: $(LIBCALIPTRA) $(LIB_HW_MODEL) $(ROM_FILE) $(FW_FILE)

$(LIBCALIPTRA):
	# For some reason, libcaliptra doesn't get rebuilt when the code changes.
	# That will need to be fixed in the libcaliptra Makefile.
	make -C $(LIBCALIPTRA_DIR) clean
	make -C $(LIBCALIPTRA_DIR)

$(LIB_HW_MODEL):
	cargo build --config="$(EXTRA_CARGO_CONFIG)" --manifest-path $(HW_MODEL_C_DIR)/Cargo.toml

$(FW_FILE) $(ROM_FILE):
	cargo --config="$(EXTRA_CARGO_CONFIG)" run --manifest-path=$(BUILDER_DIR)/Cargo.toml --bin image -- --fw $(FW_FILE) --rom-no-log=$(ROM_FILE)

# update the go.mod file to the current DPE commit
run: $(LIBCALIPTRA) $(LIB_HW_MODEL) $(FW_FILE) $(ROM_FILE)
	cp go.mod go.mod.backup; cp go.sum go.sum.backup
	go get github.com/chipsalliance/caliptra-dpe/verification@$(DPE_VERSION)
	go mod tidy
	ROM_PATH=$(ROM_FILE) FW_PATH=$(FW_FILE) go test -v
	mv go.mod.backup go.mod; mv go.sum.backup go.sum
