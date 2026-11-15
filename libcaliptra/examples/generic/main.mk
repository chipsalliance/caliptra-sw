Q=@

CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar

SOURCE += ../generic/main.c ../generic/test.c ../../src/caliptra_api.c

LIBCALIPTRA_ROOT = ../..
LIBCALIPTRA_INC  = $(LIBCALIPTRA_ROOT)/inc

OBJS := $(patsubst %.c,%.o, $(filter %.c,$(SOURCE)))

# SOC REFERENCE
CALIPTRA_HW_REV ?= latest
export CALIPTRA_HW_REV

ifeq ($(CALIPTRA_HW_REV),2.1)
RTL_SOC_IFC_INCLUDE_PATH = ../../../hw/rev-2_1/caliptra-ss/third_party/caliptra-rtl/src/soc_ifc/rtl/caliptra_top_reg
DEFINES += -DCALIPTRA_MODEL_HW_VERSION=CALIPTRA_HW_VERSION_2_1
else ifeq ($(CALIPTRA_HW_REV),latest)
RTL_SOC_IFC_INCLUDE_PATH = ../../../hw/latest/caliptra-ss/third_party/caliptra-rtl/src/soc_ifc/rtl/caliptra_top_reg
DEFINES += -DCALIPTRA_MODEL_HW_VERSION=CALIPTRA_HW_VERSION_LATEST
else
$(error Unsupported CALIPTRA_HW_REV="$(CALIPTRA_HW_REV)"; expected 2.1 or latest)
endif

# INCLUDES
INCLUDES += -I$(RTL_SOC_IFC_INCLUDE_PATH) -I$(LIBCALIPTRA_INC) -I./

.PHONY = run clean

# The below lines are not optimal but required to fetch the keys from the image and calculate
# their digest, and pack them into bespoke sections for later usage.
$(TARGET): $(OBJS) $(DEPS)
	@echo [LINK] $(TARGET)
	$(Q)$(CC) -o $(TARGET) $(OBJS) $(CFLAGS)
	@echo [ADD DIGESTS] VENDOR OWNER
	$(Q)dd status=none if=$(FW_FILE) bs=4 count=434 skip=3   | sha384sum | xxd -r -p > vpk.bin
	$(Q)dd status=none if=$(FW_FILE) bs=4 count=672  skip=2292 | sha384sum | xxd -r -p > opk.bin
	$(Q)objcopy $(TARGET) --update-section VPK_HASH=vpk.bin
	$(Q)objcopy $(TARGET) --update-section OPK_HASH=opk.bin
	$(Q)rm -f vpk.bin opk.bin


$(CALIPTRA_API):
	$(Q)make -C ../../

%.o: %.c $(DEPS)
	@echo [CC] $< \-\> $@
	$(Q)$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) -g -c $< -o $@

clean:
	@echo [CLEAN] $(OBJS) $(TARGET)
	$(Q)rm -f $(OBJS) $(TARGET)
