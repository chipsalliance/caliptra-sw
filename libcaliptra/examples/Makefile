Q=@

PLAT ?= hwmodel

.PHONY: all clean run 

all:
	$(Q)make -C $(PLAT)

clean:
	@echo [CLEAN] $(PLAT)
	$(Q)make -C $(PLAT) clean

run:
	$(Q)make -C $(PLAT) run
