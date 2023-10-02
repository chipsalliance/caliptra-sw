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

    //  SOC connections
    uio_info.mem[0].name = "fpga_wrapper";
    uio_info.mem[0].addr = 0x80000000;
    uio_info.mem[0].size = 0x2000;
    uio_info.mem[0].memtype = UIO_MEM_PHYS;

    // Caliptra MMIO interface
    uio_info.mem[1].name = "caliptra";
    uio_info.mem[1].addr = 0x90020000;
    uio_info.mem[1].size = 0x20000;
    uio_info.mem[1].memtype = UIO_MEM_PHYS;

    // Register device
    if (uio_register_device(&uio_dev, &uio_info) < 0) {
        printk("Failing to register uio device\n");
        return -EIO;
    }

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

