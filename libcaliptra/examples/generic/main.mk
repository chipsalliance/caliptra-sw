Q=@

CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar


LIBCALIPTRA = libinterface.a
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

server: run libinterface.a
	@echo [COPY] libinterface.a to ../server folder
	$(Q)cp libinterface.a ../server
	@echo [COPY] libcaliptra.a to ../server folder
	$(Q)cp ../../../target/debug/libcaliptra_hw_model_c_binding.a ../server
	@echo [BUILD] generate emulator server
	$(Q)cd ../server && go mod init emulator && go mod tidy && go build
	@echo [COPY] caliptra_rom.bin,image_bundle.bin and emulator to dpe/out folder
	$(Q)mkdir -p ../../../dpe/out
	$(Q)cp ../../../target/debug/caliptra_rom.bin ../../../dpe/out
	$(Q)cp ../../../target/debug/image_bundle.bin ../../../dpe/out
	$(Q)cp ../server/emulator ../../../dpe/out
	

clean:
	@echo [CLEAN] $(OBJS) $(TARGET)
	$(Q)rm -f $(OBJS) $(TARGET)
