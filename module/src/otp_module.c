#include "otp_module.h"

static int default_method = 0;
module_param(default_method, int, 0444);
MODULE_PARM_DESC(default_method, "Default method: 0=OTP, 1=PASSWORDS");

static int default_validity = 30;
module_param(default_validity, int, 0444);
MODULE_PARM_DESC(default_validity, "Default OTP validity (s)");

static char[KEY_LEN] default_key = "secretkey";
module_param(default_key, char*, 0444);
MODULE_PARM_DESC(default_key, "Default secret key for OTP");

int major;
struct cdev otp_cdev;
struct class *otp_class;
otp_config_t otp_config;

static struct file_operations otp_fops = {
    .owner = THIS_MODULE,
    .read = otp_read,
    .write = otp_write
};

static int __init otp_init(void)
{
    dev_t dev;

    otp_config.method = default_method;
    otp_config.validity = default_validity;
    strcpy(default_key, otp_config.secret_key);
    
    if (alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME) < 0) {
        pr_err("OTP Cannot alloc a major number\n");
        return -1;
    }
    major = MAJOR(dev);

    cdev_init(&otp_cdev, &otp_fops);
    if (cdev_add(&otp_cdev, dev, 1) < 0) {
        unregister_chrdev_region(dev, 1);
        pr_err("OTP Impossible d'ajouter le cdev\n");
        return -1;
    }

    otp_class = class_create(THIS_MODULE, "otp_class");
    if (IS_ERR(otp_class)) {
        cdev_del(&otp_cdev);
        unregister_chrdev_region(dev, 1);
        pr_err("OTP Erreur création de la classe\n");
        return PTR_ERR(otp_class);
    }
    if (IS_ERR(device_create(otp_class, NULL, dev, NULL, DEVICE_NAME))) {
        class_destroy(otp_class);
        cdev_del(&otp_cdev);
        unregister_chrdev_region(dev, 1);
        pr_err("OTP Erreur création du device\n");
        return -1;
    }

    pr_info("OTP Module loaded: /dev/otp0 available.\n");
    return 0;
}

static void __exit otp_exit(void)
{
    dev_t dev = MKDEV(major, 0);

    device_destroy(otp_class, dev);
    class_destroy(otp_class);
    cdev_del(&otp_cdev);
    unregister_chrdev_region(dev, 1);

    pr_info("OTP Module unloaded.\n");
}

module_init(otp_init);
module_exit(otp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("victor");
MODULE_DESCRIPTION("Module Kernel OTP avec paramètres default_method et default_validity");
