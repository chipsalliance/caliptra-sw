Q=@

CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar

SOURCE += ../generic/main.c ../../src/caliptra_api.c

LIBCALIPTRA_ROOT = ../..
LIBCALIPTRA_INC  = $(LIBCALIPTRA_ROOT)/inc

OBJS := $(patsubst %.c,%.o, $(filter %.c,$(SOURCE)))

# SOC REFERENCE
RTL_SOC_IFC_INCLUDE_PATH = ../../../hw/1.0/rtl/src/soc_ifc/rtl

# INCLUDES
INCLUDES += -I$(RTL_SOC_IFC_INCLUDE_PATH) -I$(LIBCALIPTRA_INC)

.PHONY = run clean

# The below lines are not optimal but required to fetch the keys from the image and calculate
# their digest, and pack them into bespoke sections for later usage.
$(TARGET): $(OBJS) $(DEPS)
	@echo [LINK] $(TARGET)
	$(Q)$(CC) -o $(TARGET) $(OBJS) $(CFLAGS)
	@echo [ADD DIGESTS] VENDOR OWNER
	$(Q)dd status=none if=$(FW_FILE) bs=4 count=480 skip=2   | sha384sum | xxd -r -p > $(VPK_PATH)
	$(Q)dd status=none if=$(FW_FILE) bs=4 count=36  skip=913 | sha384sum | xxd -r -p > $(OPK_PATH)


$(CALIPTRA_API):
	$(Q)make -C ../../

%.o: %.c $(DEPS)
	@echo [CC] $< \-\> $@
	$(Q)$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) -g -c $< -o $@

clean:
	@echo [CLEAN] $(OBJS) $(TARGET) $(VPK_PATH) $(OPK_PATH)
	$(Q)rm -f $(OBJS) $(TARGET) $(VPK_PATH) $(OPK_PATH)
