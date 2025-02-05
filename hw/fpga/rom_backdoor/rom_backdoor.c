// Licensed under the Apache-2.0 license

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <asm/io.h>

#define DEVICE_NAME "caliptra-rom-backdoor"
#define CLASS_NAME "caliptra-rom"

// Arbitrary number for device class
#define ROM_BACKDOOR_MAJOR_ID 47

#define ROM_ADDRESS 0x82000000
#define ROM_SIZE 0x18000

struct rom_backdoor_backend_data
{
    struct cdev rom_backdoor_dev;
};

static struct class *rom_backdoor_chardev_class = NULL;
static struct rom_backdoor_backend_data rom_backdoor_chardev_data = {0};

static int rom_backdoor_dev_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int rom_backdoor_dev_release(struct inode *inode, struct file *file)
{
    return 0;
}

static ssize_t rom_backdoor_dev_write(struct file *file, const char __user *buf, size_t count, loff_t *offset)
{
    void *buffer = NULL;
    u8 __iomem *rom = NULL;

    printk(KERN_INFO "rom_backdoor: rom_backdoor_dev_write");
    printk(KERN_INFO "rom_backdoor:\t count %lu\n", count);
    printk(KERN_INFO "rom_backdoor:\t offset %llu\n", *offset);

    if ((*offset + count) > ROM_SIZE)
    {
        printk("rom_backdoor: Transfer size too big\n");
        return -1;
    }

    rom = ioremap(ROM_ADDRESS, ROM_SIZE);
    if (rom == NULL)
    {
        printk("rom_backdoor: Failed ioremap\n");
        return -1;
    }

    buffer = kmalloc(count, GFP_KERNEL);
    if (!buffer)
    {
        printk("rom_backdoor: Failed kmalloc allocation\n");
        return -1;
    }

    if (copy_from_user(buffer, buf, count))
    {
        printk(KERN_INFO "caliptra_rom: Failed copy_from_user\n");
        kfree(buffer);
        return 0;
    }

    memcpy_toio(rom + *offset, buffer, count);
    *offset += count;
    kfree(buffer);

    return count;
}

static ssize_t rom_backdoor_dev_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
    void *buffer = NULL;
    u8 __iomem *rom = NULL;

    printk(KERN_INFO "rom_backdoor: rom_backdoor_dev_read");
    printk(KERN_INFO "rom_backdoor:\t count %lu\n", count);
    printk(KERN_INFO "rom_backdoor:\t offset %llu\n", *offset);

    if ((*offset + count) > ROM_SIZE)
    {
        printk("rom_backdoor: Transfer size too big\n");
        return -1;
    }

    rom = ioremap(ROM_ADDRESS, ROM_SIZE);
    if (rom == NULL)
    {
        printk("rom_backdoor: Failed ioremap\n");
        return -1;
    }

    buffer = kmalloc(count, GFP_KERNEL);
    if (!buffer)
    {
        printk("rom_backdoor: Failed kmalloc allocation\n");
        return -1;
    }

    memcpy_fromio(buffer, rom + *offset, count);
    if (copy_to_user(buf /* + *offset*/, buffer, count))
    {
        printk(KERN_INFO "rom_backdoor: Failed copy_from_user\n");
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

static struct file_operations rom_backdoor_fops =
    {
        .open = rom_backdoor_dev_open,
        .read = rom_backdoor_dev_read,
        .write = rom_backdoor_dev_write,
        .release = rom_backdoor_dev_release,
        .fsync = caliptra_fsync,
};

static int mychardev_uevent(struct device *dev, struct kobj_uevent_env *env)
{
    return add_uevent_var(env, "DEVMODE=%#o", 0666);
}

static int __init register_rom_backdoor_device(void)
{
    int rc;
    dev_t dev;
    struct device *dev_ret = NULL;

    // register char Device
    rc = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
    if (rc != 0)
    {
        printk(KERN_ALERT "register_rom_backdoor_device: error %d in register_chrdev_region\n", rc);
        return rc;
    }

    rom_backdoor_chardev_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(rom_backdoor_chardev_class))
    {
        printk(KERN_ALERT "register_rom_backdoor_device: error %lu in class_create\n", PTR_ERR(rom_backdoor_chardev_class));
        return PTR_ERR(rom_backdoor_chardev_class);
    }

    rom_backdoor_chardev_class->dev_uevent = mychardev_uevent;

    // initialize char device
    cdev_init(&rom_backdoor_chardev_data.rom_backdoor_dev, &rom_backdoor_fops);

    // add char device
    rc = cdev_add(&rom_backdoor_chardev_data.rom_backdoor_dev, MKDEV(ROM_BACKDOOR_MAJOR_ID, 0), 1);
    if (rc < 0)
    {
        printk(KERN_ALERT "register_rom_backdoor_device: error %d in cdev_add\n", rc);
        return rc;
    }

    // create device
    dev_ret = device_create(rom_backdoor_chardev_class, NULL, MKDEV(ROM_BACKDOOR_MAJOR_ID, 0), NULL, DEVICE_NAME);
    if (IS_ERR(dev_ret))
    {
        printk(KERN_ALERT "register_rom_backdoor_device: error %lu in cdev_add\n", PTR_ERR(dev_ret));
        return PTR_ERR(dev_ret);
    }

    return 0;
}

static void __exit rom_backdoor_backend_remove(void)
{
    device_destroy(rom_backdoor_chardev_class, MKDEV(ROM_BACKDOOR_MAJOR_ID, 0));

    class_unregister(rom_backdoor_chardev_class);
    class_destroy(rom_backdoor_chardev_class);

    // delete char device
    cdev_del(&rom_backdoor_chardev_data.rom_backdoor_dev);

    // unregister char device region
    unregister_chrdev_region(MKDEV(ROM_BACKDOOR_MAJOR_ID, 0), 1);
}

module_init(register_rom_backdoor_device);
module_exit(rom_backdoor_backend_remove);

MODULE_AUTHOR("Luke Mahowald <jlmahowa@amd.com>");
MODULE_DESCRIPTION("Caliptra FPGA ROM driver");
MODULE_LICENSE("GPL v2");
