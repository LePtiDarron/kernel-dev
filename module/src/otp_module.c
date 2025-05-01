#include "otp_module.h"
#include "password_list.h"

static int default_method = 0;
module_param(default_method, int, 0444);
MODULE_PARM_DESC(default_method, "Default method: 0=OTP, 1=PASSWORDS");

static int default_validity = 30;
module_param(default_validity, int, 0444);
MODULE_PARM_DESC(default_validity, "Default OTP validity (s)");

static char *default_key = "default key";
module_param(default_key, charp, 0444);
MODULE_PARM_DESC(default_key, "Default secret key");

static int debug = 0;
module_param(debug, int, 0444);
MODULE_PARM_DESC(debug, "Debug mode: 0=off, 1=on");

static struct dentry *debugfs_dir;

int major;
struct cdev otp_cdev;
struct class *otp_class;
otp_config_t otp_config;

static struct file_operations otp_fops = {
    .owner = THIS_MODULE,
    .read = otp_read,
    .write = otp_write
};

static int passwords_show(struct seq_file *m, void *v)
{
    password_node_t *node;
    list_for_each_entry(node, &passwords, list) {
        seq_printf(m, "%s\n", node->password);
    }
    return 0;
}

static int passwords_open(struct inode *inode, struct file *file)
{
    return single_open(file, passwords_show, NULL);
}

static const struct file_operations passwords_fops = {
    .owner = THIS_MODULE,
    .open = passwords_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int __init otp_init(void)
{
    dev_t dev;

    otp_config.method = default_method;
    otp_config.validity = default_validity;
    strncpy(otp_config.secret_key, default_key, sizeof(otp_config.secret_key) - 1);
    otp_config.secret_key[sizeof(otp_config.secret_key) - 1] = '\0';
    password_list_init(&passwords);

    if (alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME) < 0) {
        pr_err("[OTP]: Error while allocating a major number\n");
        return -1;
    }
    major = MAJOR(dev);
    cdev_init(&otp_cdev, &otp_fops);
    if (cdev_add(&otp_cdev, dev, 1) < 0) {
        unregister_chrdev_region(dev, 1);
        pr_err("[OTP]: Error while adding the cdev\n");
        return -1;
    }
    otp_class = class_create(THIS_MODULE, "otp_class");
    if (IS_ERR(otp_class)) {
        cdev_del(&otp_cdev);
        unregister_chrdev_region(dev, 1);
        pr_err("[OTP]: Error while creating the class\n");
        return PTR_ERR(otp_class);
    }
    if (IS_ERR(device_create(otp_class, NULL, dev, NULL, DEVICE_NAME))) {
        class_destroy(otp_class);
        cdev_del(&otp_cdev);
        unregister_chrdev_region(dev, 1);
        pr_err("[OTP]: Error while creating the device\n");
        return -1;
    }
    if (debug) {
        debugfs_dir = debugfs_create_dir("otp", NULL);
        if (!debugfs_dir) {
            pr_warn("[OTP]: Could not create the debugfs directory\n");
        } else {
            debugfs_create_file("passwords", 0444, debugfs_dir, NULL, &passwords_fops);
            debugfs_create_u32("method", 0666, debugfs_dir, (u32 *)&otp_config.method);
            debugfs_create_u32("validity", 0666, debugfs_dir, (u32 *)&otp_config.validity);
            debugfs_create_blob("key", 0444, debugfs_dir, &(struct debugfs_blob_wrapper){
                .data = otp_config.secret_key,
                .size = strlen(otp_config.secret_key)
            });
        }
    }

    pr_info("[OTP]: Module loaded: device '/dev/otp' created\n");
    return 0;
}

static void __exit otp_exit(void)
{
    dev_t dev = MKDEV(major, 0);

    password_list_clear(&passwords);
    device_destroy(otp_class, dev);
    class_destroy(otp_class);
    cdev_del(&otp_cdev);
    unregister_chrdev_region(dev, 1);
    if (debug && debugfs_dir) {
        debugfs_remove_recursive(debugfs_dir);
    }
    pr_info("[OTP]: Module unloaded.\n");
}

module_init(otp_init);
module_exit(otp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("epitech");
MODULE_DESCRIPTION("Module Kernel OTP/Passwords");
