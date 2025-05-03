#include "otp_module.h"
#include "password_list.h"

ssize_t otp_write(struct file *file, const char __user *buf, size_t len, loff_t *offset)
{
    char user_input[64];
    char cmd_change_key[4] = "KEY ";
    char cmd_add_password[4] = "+PW ";
    char cmd_del_password[4] = "-PW ";
    char cmd_method[4] = "SET ";

    if (len <= 0) {
        pr_err("[OTP]: Invalid len\n");
        return -EFAULT;
    }
    if (copy_from_user(user_input, buf, len)) {
        pr_err("[OTP]: Error while copying user's input\n");
        return -EFAULT;
    }
    user_input[len] = '\0';
    if (!strncmp(user_input, cmd_add_password, 4)) {
        if (password_list_add(&passwords, user_input + 4) < 0) {
            return -EFAULT;
        }
    } else if (!strncmp(user_input, cmd_del_password, 4)) {
        if (password_list_remove(&passwords, user_input + 4) < 0) {
            return -EFAULT;
        }
    } else if (!strncmp(user_input, cmd_change_key, 4)) {
        if (len - 5 > KEY_LEN) {
            pr_err("[OTP]: Secret key is too long\n");
            return -EFAULT;
        }
        pr_info("[OTP]: SECRET KEY changed to %s\n", user_input + 4);
        size_t key_len = len - 4;
        if (key_len >= KEY_LEN) {
            key_len = KEY_LEN - 1;
        }
        memset(otp_config.secret_key, 0, KEY_LEN);
        strncpy(otp_config.secret_key, user_input + 4, key_len);
        if (key_blob) {
            key_blob->size = strlen(otp_config.secret_key);
        }
        otp_config.secret_key[key_len] = '\0';
    } else if (!strncmp(user_input, cmd_method, 4)) {
        if (user_input[4] == '0') {
            pr_info("[OTP]: Method set to otp\n");
            otp_config.method = 0;
            return 0;
        }
        if (user_input[4] == '1') {
            pr_info("[OTP]: Method set to passwords\n");
            otp_config.method = 1;
            return 0;
        }
        pr_err("[OTP]: Invalid method\n");
        return -EFAULT;
    } else {
        pr_err("[OTP]: Command not found\n");
        return -EFAULT;
    }

    return len;
}