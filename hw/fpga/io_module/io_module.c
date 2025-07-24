// Licensed under the Apache-2.0 license

#include <linux/module.h>
#include <linux/uio_driver.h>

const char caliptra_dev_name0[] = "caliptra-fpga-uio-dev0";
const char caliptra_dev_name1[] = "caliptra-fpga-uio-dev1";
static struct device uio_dev0;
static struct device uio_dev1;
static struct uio_info uio_info0;
static struct uio_info uio_info1;

static void uio_release(struct device *dev)
{
    printk("releasing uio-device\n");
}

int init_module(void)
{
    printk("Setting up uio devices\n");
    // Create UIO devices
    dev_set_name(&uio_dev0, caliptra_dev_name0);
    uio_dev0.release = uio_release;
    if (device_register(&uio_dev0) < 0)
    {
        printk("Failing to register uio device 0\n");
        return -ENODEV;
    }

    // Create UIO devices
    dev_set_name(&uio_dev1, caliptra_dev_name1);
    uio_dev1.release = uio_release;
    if (device_register(&uio_dev1) < 0)
    {
        device_unregister(&uio_dev0); // clean up
        printk("Failing to register uio device 1\n");
        return -ENODEV;
    }

    // Setup Info
    uio_info0.name = caliptra_dev_name0;
    uio_info0.version = "1.0.0";

    //  Caliptra FPGA wrapper
    uio_info0.mem[0].name = "fpga_wrapper";
    uio_info0.mem[0].addr = 0xA4010000;
    uio_info0.mem[0].size = 0x00010000;
    uio_info0.mem[0].memtype = UIO_MEM_PHYS;

    // Caliptra MMIO interface
    uio_info0.mem[1].name = "caliptra";
    uio_info0.mem[1].addr = 0xA4100000;
    uio_info0.mem[1].size = 0x00040000;
    uio_info0.mem[1].memtype = UIO_MEM_PHYS;

    // Caliptra ROM
    uio_info0.mem[2].name = "rom";
    uio_info0.mem[2].addr = 0xB0000000;
    uio_info0.mem[2].size = 0x00018000;
    uio_info0.mem[2].memtype = UIO_MEM_PHYS;

    // I3C controller
    uio_info0.mem[3].name = "i3c_controller";
    uio_info0.mem[3].addr = 0xA4080000;
    uio_info0.mem[3].size = 0x00010000;
    uio_info0.mem[3].memtype = UIO_MEM_PHYS;

    // MCU SRAM
    uio_info0.mem[4].name = "mcu_sram";
    uio_info0.mem[4].addr = 0xB0080000;
    uio_info0.mem[4].size = 0x00080000;
    uio_info0.mem[4].memtype = UIO_MEM_PHYS;


    // Register device
    if (uio_register_device(&uio_dev0, &uio_info0) < 0)
    {
        printk("Failing to register uio device0 \n");
        return -EIO;
    }


    // Setup Info
    uio_info1.name = caliptra_dev_name1;
    uio_info1.version = "1.0.0";

    // LC
    uio_info1.mem[0].name = "lc";
    uio_info1.mem[0].addr = 0xA4040000;
    uio_info1.mem[0].size = 0x00002000;
    uio_info1.mem[0].memtype = UIO_MEM_PHYS;

    // MCU ROM Backdoor
    uio_info1.mem[1].name = "mcu_rom";
    uio_info1.mem[1].addr = 0xB0020000;
    uio_info1.mem[1].size = 0x00020000;
    uio_info1.mem[1].memtype = UIO_MEM_PHYS;

    // I3C
    uio_info1.mem[2].name = "ss_i3c";
    uio_info1.mem[2].addr = 0xA4030000;
    uio_info1.mem[2].size = 0x00010000;
    uio_info1.mem[2].memtype = UIO_MEM_PHYS;

    // MCI
    uio_info1.mem[3].name = "mci";
    uio_info1.mem[3].addr = 0xA8000000;
    uio_info1.mem[3].size = 0x01000000;
    uio_info1.mem[3].memtype = UIO_MEM_PHYS;

    // OTP
    uio_info1.mem[4].name = "otp";
    uio_info1.mem[4].addr = 0xA4060000;
    uio_info1.mem[4].size = 0x00002000;
    uio_info1.mem[4].memtype = UIO_MEM_PHYS;


    // Register device
    if (uio_register_device(&uio_dev1, &uio_info1) < 0)
    {
        printk("Failing to register uio device1 \n");
        return -EIO;
    }

    printk("Initialized uio devices\n");
    return 0;
}

void cleanup_module(void)
{
    printk("Unregister uio devices\n");
    uio_unregister_device(&uio_info1);
    device_unregister(&uio_dev1);
    uio_unregister_device(&uio_info0);
    device_unregister(&uio_dev0);
}
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux");
