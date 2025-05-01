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
        pr_err("OTP Error (otp write len).");
        return -EFAULT;
    }

    if (copy_from_user(user_input, buf, len)) {
        pr_err("OTP Error (otp write copy).");
        return -EFAULT;
    }
    user_input[len] = '\0';

    if (!strncmp(user_input, cmd_add_password, 4)) {
        // Ajouter le mot de passe
        if (password_list_add(&passwords, user_input + 4) < 0)
            return -EFAULT;
    } else if (!strncmp(user_input, cmd_del_password, 4)) {
        // Supprimer un mot de passe
        if (password_list_remove(&passwords, user_input + 4) < 0)
            return -EFAULT;
    } else if (!strncmp(user_input, cmd_change_key, 4)) {
        // Changer la clé
        if (len - 5 > KEY_LEN) {
            pr_err("OTP Secret key is too long.");
            return -EFAULT;
        }
        pr_info("OTP SECRET KEY changed to %s", user_input + 4);
        strncpy(otp_config.secret_key, user_input + 4, len - 5);
        otp_config.secret_key[len - 5] = '\0';
    } else if (!strncmp(user_input, cmd_method, 4)) {
        // Changer la methode
        if (user_input[4] == '0') {
            pr_info("OTP Method set to otp");
            otp_config.method = 0;
            return 0;
        }
        if (user_input[4] == '1') {
            pr_info("OTP Method set to passwords");
            otp_config.method = 1;
            return 0;
        }
        pr_err("Method not found.");
        return -EFAULT;
    } else {
        pr_err("OTP Command not found.");
        return -EFAULT;
    }

    return len;
}