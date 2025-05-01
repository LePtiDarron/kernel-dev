#ifndef OTP_H
#define OTP_H

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/time.h>
#include <crypto/hash.h>

#define DEVICE_NAME "otp0"
#define MAX_PASSWORDS 10
#define PASSWORD_LEN 16
#define KEY_LEN 32
#define OTP_LEN 6

/// OTP CONFIG ///

// Structure stockant la configuration de l'OTP
typedef struct otp_config_s {
    char secret_key[KEY_LEN];                       // Clé secrète pour OTP basé sur le temps
    int validity;                                   // Durée de validité en secondes
    char passwords[MAX_PASSWORDS][PASSWORD_LEN];    // Liste de mots de passe
    int method;                                     // 0=OTP   1=PASSWORDS
} otp_config_t;

extern int major;
extern struct cdev otp_cdev;
extern struct class *otp_class;
extern otp_config_t otp_config;

ssize_t otp_read(struct file *file, char __user *buf, size_t len, loff_t *offset);
ssize_t otp_write(struct file *file, const char __user *buf, size_t len, loff_t *offset);

#endif // OTP_H