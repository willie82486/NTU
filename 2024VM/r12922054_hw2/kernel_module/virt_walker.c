#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#define DEVICE_NAME "virt_walker"

static int major;
static struct class *virt_walker_class;
static struct device *virt_walker_device;
static void __iomem *virt_device_base;

static int virt_walker_open(struct inode *inode, struct file *file) {
    return 0;
}

static int virt_walker_release(struct inode *inode, struct file *file) {
    return 0;
}

static ssize_t virt_walker_read(struct file *file, char __user *buffer, size_t count, loff_t *offset) {
    /* TODO: Add your code here. */
    u8 seek_value;
    if (count < 1) {
        return -EINVAL;
    }

    // Read from SEEK (0x0b000001)
    seek_value = ioread8(virt_device_base + 0x1);
    
    // Print seek_value and virt_device_base
    pr_info("virt_walker_read: seek_value = 0x%x\n", seek_value);
    pr_info("virt_walker_read: virt_device_base = %p\n", virt_device_base + 0x1);

    // Copy the value to user space
    if (copy_to_user(buffer, &seek_value, 1)) {
        return -EFAULT;
    }

    return count;  // Return the number of bytes read
}

static ssize_t virt_walker_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset) {
    /* TODO: Add your code here. */
    u8 hide_value;

    if (count < 1) {
        return -EINVAL;
    }

    // Copy the value from user space
    if (copy_from_user(&hide_value, buffer, 1)) {
        return -EFAULT;
    }

    // Print seek_value and virt_device_base
    pr_info("virt_walker_wtite: hide_value = 0x%x\n", hide_value);
    pr_info("virt_walker_write: virt_device_base = %p\n", virt_device_base);


    // Write to HIDE (0x0b000000)
    iowrite8(hide_value, virt_device_base);
    
    return count;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = virt_walker_open,
    .release = virt_walker_release,
    .read = virt_walker_read,
    .write = virt_walker_write,
};

static int __init virt_walker_init(void) {
    int ret;

    major = register_chrdev(0, DEVICE_NAME, &fops);
    if (major < 0) {
        pr_err("virt_walker: failed to register a major number\n");
        return major;
    }

    /* TODO: Do your initialization here. */
    // Map the MMIO physical address range (0x0b000000 - 0x0b000002)
    virt_device_base = ioremap(0x0b000000, 2);
    if (!virt_device_base) {
        pr_err("virt_walker: failed to map MMIO\n");
        unregister_chrdev(major, DEVICE_NAME);
        return -ENOMEM;
    }

    virt_walker_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(virt_walker_class)) {
        pr_err("virt_walker: class_create() failed\n");
        ret = PTR_ERR(virt_walker_class);
        goto out_chrdev;
    }
    virt_walker_device = device_create(virt_walker_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(virt_walker_device)) {
        pr_err("virt_walker: device_create() failed\n");
        ret = PTR_ERR(virt_walker_device);
        goto out_class;
    }

    pr_info("virt_walker: module loaded with device major %d\n", major);
    return 0;

out_class:
    class_destroy(virt_walker_class);
out_chrdev:
    unregister_chrdev(major, DEVICE_NAME);
    return ret;
}

static void __exit virt_walker_exit(void) {
    device_destroy(virt_walker_class, MKDEV(major, 0));
    class_destroy(virt_walker_class);

    /* TODO: Do your cleanup here. */

    unregister_chrdev(major, DEVICE_NAME);
    pr_info("virt_walker: module unloaded\n");
}

module_init(virt_walker_init);
module_exit(virt_walker_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XXX");
MODULE_DESCRIPTION("virt_walker kernel module");
