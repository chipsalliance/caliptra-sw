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

# Set Q= on the command line for verbosity
Q=@

# Set build targets, flags, and a defaultr
ifeq ($(findstring "debug",$(MAKECMDGOALS)),"debug")
CARGO_OUT = $(abspath ../target/debug)
CARGO_FLAG =
else ifeq ($(findstring "release,$(MAKECMDGOALS)),"release")
CARGO_OUT = $(abspath ../target/release)
CARGO_FLAG = --release
else
CARGO_OUT = $(abspath ../target/debug)
endif

RTL_SOC_IFC_INCLUDE_PATH = ../hw-latest/caliptra-rtl/src/soc_ifc/rtl
CFLAGS += -I$(RTL_SOC_IFC_INCLUDE_PATH) -I$(CARGO_OUT) -I$(abspath inc)

SOURCE += src/caliptra_api.c

OBJS := $(patsubst %.c,%.o, $(filter %.c,$(SOURCE)))

TESTS = $(sort $(notdir $(wildcard test/*)))
CLEAN_TESTS = $(addprefix clean-, $(TESTS))

.PHONY:%_test %_run clean $(CLEAN_TESTS)

debug: all
release: all
tests: $(TESTS)
all: $(OBJS) $(TESTS)

$(OBJS): $(SOURCE)
	@echo [CC] $@
	$(Q)$(CC) ${CFLAGS} -c $< -o $@

$(CLEAN_TESTS): FORCE
	@echo [CLEAN] $@
	@$(Q)$(MAKE) Q=$(Q) -C test/$(subst clean-,,$@) -f $(subst clean-,,$@).mk clean

FORCE:

clean: $(CLEAN_TESTS)
	@echo [CLEAN] $(CARGO_OUT) $(OBJS)
	$(Q)$(RM) -r $(CARGO_OUT)
	$(Q)$(RM) $(OBJS)

export CARGO_OUT
export MODEL_HEADER
export CFLAGS

%_test: $(MODEL_HEADER)
	$(Q)$(MAKE) Q=$(Q) -C test/$*_test -f $*_test.mk

%_run:
	$(Q)$(MAKE) Q=$(Q) -C test/$*_test -f $*_test.mk run
