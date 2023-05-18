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


OUT = out
TARGET = $(OUT)/smoke_test
RTL_SOC_IFC_INCLUDE_PATH = ../../../hw-latest/caliptra-rtl/src/soc_ifc/rtl
BUILDER_PATH = ../../../builder
CALIPTRA_MODEL_PATH = ../src
CFLAGS += -I$(RTL_SOC_IFC_INCLUDE_PATH) -I$(CALIPTRA_MODEL_PATH) -Lout/debug

SOURCE += api/caliptra_api.c
SOURCE += smoke_test.c

OBJS := $(patsubst %.c,%.o, $(filter %.c,$(SOURCE)))
all: $(TARGET)
$(OUT)/%.o: $(SOURCE)
	$(MKDIR)
	$(CC) ${CFLAGS} -c $< -o $@

$(TARGET): $(OBJS)
	cargo build --target-dir out/
	cargo run --manifest-path=$(BUILDER_PATH)/Cargo.toml --bin image
	$(CC) -o $(TARGET) $(OBJS) $(CFLAGS) -Wl,-lcaliptra_hw_model_c_binding -lpthread -lstdc++ -ldl -lm
clean:
	$(RM) -rf $(OUT)
