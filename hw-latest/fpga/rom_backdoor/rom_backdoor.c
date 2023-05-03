// Licensed under the Apache-2.0 license

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <asm/io.h>

#define DEVICE_NAME "caliptra-rom-backdoor"
#define CLASS_NAME "caliptra-rom"

// Arbitrary number for device class
#define caliptra_rom_MAJOR_ID 47

struct caliptra_rom_backend_data {
    struct cdev caliptra_rom_dev;
};

static struct class *mychardev_class = NULL;
static struct caliptra_rom_backend_data mychardev_data;


static int caliptra_rom_dev_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int caliptra_rom_dev_release(struct inode *inode, struct file *file)
{
    return 0;
}

static ssize_t caliptra_rom_dev_write(struct file *file, const char __user *buf, size_t count, loff_t *offset)
{
    void *buffer;
    u8 __iomem *rom;

    printk(KERN_INFO "caliptra_rom: caliptra_rom_dev_write");
    printk(KERN_INFO "caliptra_rom:\t count %lu\n", count);
    printk(KERN_INFO "caliptra_rom:\t offset %llu\n", *offset);

    if ((*offset + count) > 0x8000) {
		printk("caliptra_rom: Transfer size too big\n");
		return -1;
    }

    rom = ioremap (0x82000000, 0x8000);
	if (rom == NULL) {
		printk("caliptra_rom: Failed ioremap\n");
		return -1;
	}

    buffer = kmalloc(count, GFP_KERNEL);

    if (copy_from_user(buffer, buf, count)) {
        printk(KERN_INFO "caliptra_rom: Failed copy_from_user\n");
        kfree(buffer);
        return 0;
    }

    memcpy_toio(rom + *offset, buffer, count);
    *offset += count;

    kfree(buffer);

    return count;
}

static ssize_t caliptra_rom_dev_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
    void *buffer;
    u8 __iomem *rom;
    printk(KERN_INFO "caliptra_rom: caliptra_rom_dev_read");
    printk(KERN_INFO "caliptra_rom:\t count %lu\n", count);
    printk(KERN_INFO "caliptra_rom:\t offset %llu\n", *offset);

    if ((*offset + count) > 0x8000) {
		printk("caliptra_rom: Transfer size too big\n");
		return -1;
    }

    rom = ioremap (0x82000000, 0x8000);
	if (rom == NULL) {
		printk("caliptra_rom: Failed ioremap\n");
		return -1;
	}

    buffer = kmalloc(count, GFP_KERNEL);

    memcpy_fromio(buffer, rom + *offset, count);

    if (copy_to_user(buf/* + *offset*/, buffer, count)) {
        printk(KERN_INFO "caliptra_rom: Failed copy_from_user\n");
        kfree(buffer);
        return 0;
    }

    *offset += count;

    kfree(buffer);

    return count;
}

static int caliptra_fsync(struct file *, loff_t, loff_t, int datasync)
{
    return 0;
}

static struct file_operations caliptra_rom_fops =
{
   .open = caliptra_rom_dev_open,
   .read = caliptra_rom_dev_read,
   .write = caliptra_rom_dev_write,
   .release = caliptra_rom_dev_release,
   .fsync = caliptra_fsync,
};

static int mychardev_uevent(struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}


static int __init register_caliptra_rom_device(void)
{
    int rc;
    dev_t dev;

    // register char Device
    rc = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
    if (rc != 0) {
        printk(KERN_ALERT "register_caliptra_rom_device: error %d in register_chrdev_region \n", rc);
        return rc;
    }

    mychardev_class = class_create(THIS_MODULE, CLASS_NAME);
    mychardev_class->dev_uevent = mychardev_uevent;

    // initialize char device
    cdev_init(&mychardev_data.caliptra_rom_dev, &caliptra_rom_fops);

    // add char device
    cdev_add(&mychardev_data.caliptra_rom_dev, MKDEV(caliptra_rom_MAJOR_ID, 0), 1);

        device_create(mychardev_class, NULL, MKDEV(caliptra_rom_MAJOR_ID, 0), NULL, DEVICE_NAME);

    return 0;
}

static void __exit caliptra_rom_backend_remove(void)
{
    device_destroy(mychardev_class, MKDEV(caliptra_rom_MAJOR_ID, 0));

    class_unregister(mychardev_class);
    class_destroy(mychardev_class);

    // delete char device
    cdev_del(&mychardev_data.caliptra_rom_dev);

    // unregister char device region
    unregister_chrdev_region(MKDEV(caliptra_rom_MAJOR_ID, 0), 1);

}


module_init(register_caliptra_rom_device);
module_exit(caliptra_rom_backend_remove);

MODULE_AUTHOR("Luke Mahowald <jlmahowa@amd.com>");
MODULE_DESCRIPTION("Caliptra FPGA ROM driver");
MODULE_LICENSE("GPL v2");
