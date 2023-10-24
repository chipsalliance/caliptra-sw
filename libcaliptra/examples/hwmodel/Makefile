TARGET = hwmodel

CROSS_COMPILE ?=

.DEFAULT_GOAL = $(TARGET)

LIBCALIPTRA_ROOT = ../../
LIBCALIPTRA_INC  = 

OUTPUT_DIR = ../../../target/debug

# ROM AND FW DIR
ROM_FW_DIR = $(OUTPUT_DIR)

ROM_FILE = $(ROM_FW_DIR)/caliptra_rom.bin
FW_FILE  = $(ROM_FW_DIR)/image_bundle.bin

BUILDER_PATH = ../../../builder

# ROM AND FW FILES
#
# These paths are encoded into the binary so the generic
# main sources don't need a command line.
DEFINES  = -DROM_PATH=\"$(ROM_FILE)\"
DEFINES += -DFW_PATH=\"$(FW_FILE)\"

# HW MODEL
HWMODEL_DIR = $(OUTPUT_DIR)
HWMODEL_HEADER_DIR = ../../../hw-model/c-binding/out
HWMODEL_INCLUDE = -I$(HWMODEL_HEADER_DIR)
HWMODEL_LIB = -Wl,-L$(HWMODEL_DIR) -lcaliptra_hw_model_c_binding
HWMODEL_FLAGS = -lpthread -lstdc++ -ldl -lrt -lm
HWMODEL_HEADER = $(HWMODEL_HEADER_DIR)/caliptra_model.h
HWMODEL_BINDING_LIB_OBJ = $(HWMODEL_DIR)/libcaliptra_hw_model_c_binding.a

# DEPENDENCIES
DEPS += $(HWMODEL_BINDING_LIB_OBJ) $(HWMODEL_HEADER) $(ROM_FILE) $(FW_FILE)

# INCLUDES
INCLUDES += $(HWMODEL_INCLUDE)

SOURCE += interface.c

CFLAGS += $(HWMODEL_INCLUDE) $(HWMODEL_LIB) $(HWMODEL_FLAGS) -Wall

$(ROM_FILE) $(FW_FILE):
	@echo [IMAGE] caliptra_rom.bin image_bundle.bin
	$(Q)make -C ../../../rom/dev
	$(Q)cd ../../../runtime && ./build.sh
	$(Q)cargo --config="$(EXTRA_CARGO_CONFIG)" run --manifest-path=$(BUILDER_PATH)/Cargo.toml --bin image -- --rom-with-log $(ROM_FW_DIR)/caliptra_rom.bin --fw $(ROM_FW_DIR)/image_bundle.bin

$(HWMODEL_BINDING_LIB_OBJ):
	@echo "[CARGO] c-binding"
	$(Q)cd ../../../hw-model/c-binding
	$(Q)cargo build

EXTRA_CARGO_CONFIG = target.'cfg(all())'.rustflags = [\"-Dwarnings\"]

$(TARGET): $(ROM_FILE) $(FW_FILE)

$(HWMODEL_HEADER):
	@echo "[CARGO] hw-model"
	$(Q)cd ../../../hw-model
	$(Q)cargo --config="$(EXTRA_CARGO_CONFIG)" build

run: $(TARGET)
	@echo [RUN] $(TARGET)
	$(Q)./$(TARGET)

include ../generic/main.mk
