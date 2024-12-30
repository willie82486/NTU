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

static int virt_walker_open(struct inode *inode, struct file *file) {
    return 0;
}

static int virt_walker_release(struct inode *inode, struct file *file) {
    return 0;
}

static ssize_t virt_walker_read(struct file *file, char __user *buffer, size_t count, loff_t *offset) {
    /* TODO: Add your code here. */
    return count;
}

static ssize_t virt_walker_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset) {
    /* TODO: Add your code here. */
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
