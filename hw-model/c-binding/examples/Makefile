# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 Western Digital Corporation or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

EXTRA_CARGO_CONFIG = target.'cfg(all())'.rustflags = [\"-Dwarnings\"]
OUT = out
TARGET = $(OUT)/smoke_test
RTL_SOC_IFC_INCLUDE_PATH = ../../../hw/1.0/rtl/src/soc_ifc/rtl
BUILDER_PATH = ../../../builder
CALIPTRA_MODEL_PATH = ../out
CFLAGS += -I$(RTL_SOC_IFC_INCLUDE_PATH) -I$(CALIPTRA_MODEL_PATH)

SOURCE += api/caliptra_api.c
SOURCE += smoke_test.c

OBJS := $(patsubst %.c,%.o, $(filter %.c,$(SOURCE)))

all: $(TARGET)
$(OUT)/caliptra_model.h:
	cargo --config="$(EXTRA_CARGO_CONFIG)" build
	mkdir -p $(OUT)/debug
	cp ../../../target/debug/libcaliptra_hw_model_c_binding.a $(OUT)/debug/

$(OUT)/%.o: $(SOURCE)
	$(MKDIR)
	$(CC) ${CFLAGS} -g -c $< -o $@

$(TARGET): $(OUT)/caliptra_model.h $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(CFLAGS) -Wl,-L$(OUT)/debug -lcaliptra_hw_model_c_binding -lpthread -lstdc++ -ldl -lrt -lm

clean:
	$(RM) -rf $(OUT)

run: $(TARGET)
	cargo --config="$(EXTRA_CARGO_CONFIG)" run --manifest-path=$(BUILDER_PATH)/Cargo.toml --bin image -- --rom-with-log $(OUT)/caliptra_rom.bin --fw $(OUT)/image_bundle.bin
	$(TARGET) -r $(OUT)/caliptra_rom.bin -f $(OUT)/image_bundle.bin

