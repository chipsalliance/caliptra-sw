Q=@

CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar

ifneq ($(MAKECMDGOALS),clean)
RTL_SOC_IFC_INCLUDE_PATH=../hw-latest/caliptra-rtl/src/soc_ifc/rtl/
ifndef RTL_SOC_IFC_INCLUDE_PATH
$(error RTL_SOC_IFC_INCLUDE_PATH must be defined and point to a location where caliptra_top_reg.h can be found)
endif
endif

LIBCALIPTRA = libcaliptra.a

SOURCE += src/caliptra_api.c 
OBJS := $(patsubst %.c,%.o, $(filter %.c,$(SOURCE)))

INCLUDES  = -I$(RTL_SOC_IFC_INCLUDE_PATH)
INCLUDES += -Iinc

$(LIBCALIPTRA): $(OBJS)
	@echo [AR] $@
	$(Q)$(AR) -cq $@ $(OBJS)

%.o: %.c
	@echo [CC] $< \-\> $@
	$(Q)$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) -g -c $< -o $@

clean:
	@echo [CLEAN] $(OBJS) $(LIBCALIPTRA)
	$(Q)rm -f $(OBJS) $(LIBCALIPTRA)
