Q=@

CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar


LIBCALIPTRA = libcaliptra1.a
SOURCE += ../../src/caliptra_api.c
OBJS_A := $(patsubst %.c,%.o, $(filter %.c,$(SOURCE)))

RTL_SOC_IFC_INCLUDE_PATH=../hw-latest/caliptra-rtl/src/soc_ifc/rtl/
INCLUDES  = -I$(RTL_SOC_IFC_INCLUDE_PATH)
INCLUDES += -I../../inc

$(LIBCALIPTRA): $(OBJS_A)
	@echo [AR] $@
	$(Q)$(AR) -cq $@ $(OBJS_A)


LIBCALIPTRA_ROOT = ../..
LIBCALIPTRA_INC  = $(LIBCALIPTRA_ROOT)/inc

SOURCE += ../generic/main.c 

OBJS := $(patsubst %.c,%.o, $(filter %.c,$(SOURCE)))

# SOC REFERENCE
RTL_SOC_IFC_INCLUDE_PATH = ../../../hw-latest/caliptra-rtl/src/soc_ifc/rtl

# INCLUDES
INCLUDES += -I$(RTL_SOC_IFC_INCLUDE_PATH) -I$(LIBCALIPTRA_INC)

.PHONY = run clean

# The below lines are not optimal but required to fetch the keys from the image and calculate
# their digest, and pack them into bespoke sections for later usage.
$(TARGET): $(OBJS) $(DEPS)
	@echo [LINK] $(TARGET)
	$(Q)$(CC) -o $(TARGET) $(OBJS) $(CFLAGS)
	@echo [ADD DIGESTS] VENDOR OWNER
	$(Q)dd status=none if=$(FW_FILE) bs=4 count=480 skip=2   | sha384sum | xxd -r -p > vpk.bin
	$(Q)dd status=none if=$(FW_FILE) bs=4 count=36  skip=913 | sha384sum | xxd -r -p > opk.bin
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
