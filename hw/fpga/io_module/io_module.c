// Licensed under the Apache-2.0 license

#include <linux/module.h>
#include <linux/uio_driver.h>

const char caliptra_dev_name[] = "caliptra-fpga-uio-dev";
static struct device uio_dev;
static struct uio_info uio_info;

static void uio_release(struct device *dev)
{
    printk("releasing uio-device \n");
}

int init_module(void)
{
    printk("Setting up uio device\n");
    // Create UIO devices
    dev_set_name(&uio_dev, caliptra_dev_name);
    uio_dev.release = uio_release;
    if (device_register(&uio_dev) < 0) {
        printk("Failing to register uio device\n");
        return -ENODEV;
    }

    // Setup Info
    uio_info.name = caliptra_dev_name;
    uio_info.version = "1.0.0";

    //  Caliptra FPGA wrapper
    uio_info.mem[0].name = "fpga_wrapper";
    uio_info.mem[0].addr = 0xA4010000;
    uio_info.mem[0].size = 0x00010000;
    uio_info.mem[0].memtype = UIO_MEM_PHYS;

    // Caliptra MMIO interface
    uio_info.mem[1].name = "caliptra";
    uio_info.mem[1].addr = 0xA4100000;
    uio_info.mem[1].size = 0x00100000;
    uio_info.mem[1].memtype = UIO_MEM_PHYS;

    // Caliptra ROM
    uio_info.mem[2].name = "rom";
    uio_info.mem[2].addr = 0xB0000000;
    uio_info.mem[2].size = 0x00018000;
    uio_info.mem[2].memtype = UIO_MEM_PHYS;
/*
    // SS IMEM
    uio_info.mem[3].name = "ss_imem";
    uio_info.mem[3].addr = 0xB0020000;
    uio_info.mem[3].size = 0x00010000;
    uio_info.mem[3].memtype = UIO_MEM_PHYS;
    // SS Wrapper
    uio_info.mem[4].name = "ss_wrapper";
    uio_info.mem[4].addr = 0xA4020000;
    uio_info.mem[4].size = 0x00010000;
    uio_info.mem[4].memtype = UIO_MEM_PHYS;
    // I3C
    uio_info.mem[5].name = "ss_i3c";
    uio_info.mem[5].addr = 0xA4030000;
    uio_info.mem[5].size = 0x00010000;
    uio_info.mem[5].memtype = UIO_MEM_PHYS;
*/
    // Register device
    if (uio_register_device(&uio_dev, &uio_info) < 0) {
        printk("Failing to register uio device\n");
        return -EIO;
    }
    printk("Initialized uio device\n");
    return 0;
}

void cleanup_module(void)
{
    printk("Unregister uio device\n");
    uio_unregister_device(&uio_info);
    device_unregister(&uio_dev);
}
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux");
