CONFIG_MODULE_SIG=n

KERNEL ?= $(shell uname -r)

obj-m += rom_backdoor.o

all:
		make -C /lib/modules/$(KERNEL)/build M=$(PWD) modules

clean:
		make -C /lib/modules/$(KERNEL)/build M=$(PWD) clean

