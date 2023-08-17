Q=@

CROSS_COMPILE ?=

PLAT ?= hwmodel

.PHONY: all clean run 

all:
	$(Q)make CROSS_COMPILE=$(CROSS_COMPILE) -C $(PLAT)

clean:
	@echo [CLEAN] $(PLAT)
	$(Q)make -C $(PLAT) clean

run:
	$(Q)make -C $(PLAT) run
