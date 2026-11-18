# Licensed under the Apache-2.0 license

CONFIG_MODULE_SIG=n

KERNEL ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KERNEL)/build

obj-m += caliptra_fpga_hcd.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
