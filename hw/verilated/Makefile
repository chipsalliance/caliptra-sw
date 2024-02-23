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

VERILATOR = verilator
VERILATED_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
CALIPTRA_RTL_DIR := $(realpath $(VERILATED_DIR)../1.0/rtl)

CFLAGS := -std=c++11 -fno-exceptions -fPIC
VERILATOR_MAKE_FLAGS = OPT_FAST="-Os"

VERILATOR_CFLAGS = $(shell pkg-config --cflags verilator)
VERILATOR_INCLUDEDIR = $(shell pkg-config --variable=includedir verilator)
VERILATOR_OBJS = out/verilated_threads.o out/verilated.o out/verilated_vcd_c.o

LIB_OBJS = out/caliptra_verilated.o

export CALIPTRA_ROOT = $(realpath ../1.0/rtl)

suppress = -Wno-WIDTH -Wno-UNOPTFLAT -Wno-LITENDIAN -Wno-CMPCONST -Wno-MULTIDRIVEN -Wno-UNPACKED

out/libcaliptra_verilated.a: out/Vcaliptra_verilated__ALL.a $(LIB_OBJS) $(VERILATOR_OBJS)
	cp out/Vcaliptra_verilated__ALL.a out/.libcaliptra_verilated.a
	ar rs out/.libcaliptra_verilated.a $(LIB_OBJS) $(VERILATOR_OBJS)
	mv out/.libcaliptra_verilated.a out/libcaliptra_verilated.a

out:
	mkdir -p out


$(VERILATOR_OBJS): out/%.o: $(VERILATOR_INCLUDEDIR)/%.cpp
	$(CXX) ${CFLAGS} $(VERILATOR_CFLAGS) -c $< -o $@

$(LIB_OBJS): out/%.o: $(VERILATED_DIR)/%.cpp
	$(CXX) -Iout ${CFLAGS} $(VERILATOR_CFLAGS) -c $< -o $@

out/Vcaliptra_verilated.h: ${VERILATED_DIR}/caliptra_verilated.sv out
	$(VERILATOR)  --cc -CFLAGS "${CFLAGS}" \
	  --trace \
	  +libext+.v+.sv +define+RV_OPENSOURCE \
	  --timescale 1ns/1ps \
	  --trace-structs \
	  $(includes) \
	  -Mdir out \
	  -MMD \
	  -Wno-fatal `#TODO: Remove this line once RTL warnings are fixed` \
	  --clk core_clk \
	  $(suppress) \
	  -f $(CALIPTRA_RTL_DIR)/src/integration/config/caliptra_top_tb.vf \
	  $(VERILATED_DIR)/caliptra_verilated.sv \
	  $(EXTRA_VERILATOR_FLAGS) \
	  --top-module caliptra_verilated

out/Vcaliptra_verilated__ALL.a: out/Vcaliptra_verilated.h
	$(MAKE) -j $(CALIPTRA_VERILATOR_JOBS) -e -C out -f Vcaliptra_verilated.mk $(VERILATOR_MAKE_FLAGS)

clean:
	rm -r out
