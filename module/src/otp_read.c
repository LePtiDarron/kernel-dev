#include "otp_module.h"
#include "password_list.h"

uint32_t hash(const char *key, uint64_t time_step) {
    uint32_t hash = 0;

    // hash de la clé
    for (key; *key; key++) {
        hash = hash * 31 + *key;
    }
    // time XOR hash
    hash ^= (uint64_t)(time_step & 0xFFFFFFFF);
    return hash;
}

void generate_otp(char *otp_code) {
    struct timespec64 ts;
    time_t current_time = time(NULL);
    uint64_t otp;
    uint64_t time_step;
    
    ktime_get_real_ts64(&ts);
    time_step = ts.tv_sec / otp_config.validity;
    otp = hash(otp_config.secret_key, time_step) % 1000000;
    snprintf(otp_code, OTP_LEN + 1, "%06d", otp);
    return 0;
}

// Fonction de lecture du device (afficher OTP ou mots de passe)
ssize_t otp_read(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
    char *passwords_buffer = NULL;
    char otp_code[OTP_LEN + 1];
    size_t buffer_len = 0;

    if (*offset > 0) {
        return 0;
    }
    if (otp_config.method == 0) {
        if (generate_otp(otp_code)) {
            return -EFAULT;
        }
        otp_code[OTP_LEN] = '\0';
        if (copy_to_user(buf, otp_code, OTP_LEN + 1)) {
            return -EFAULT;
        }
        *offset += OTP_LEN;
        return OTP_LEN;
    } else {
        password_node_t *entry;
        list_for_each_entry(entry, &passwords, list) {
            buffer_len += strlen(entry->password) + 1;
            passwords_buffer = krealloc(passwords_buffer, buffer_len, GFP_KERNEL);
            strcat(passwords_buffer, entry->password);
            strcat(passwords_buffer, "\n");
        }
        if (copy_to_user(buf, passwords_buffer, buffer_len)) {
            kfree(passwords_buffer);
            return -EFAULT;
        }
        *offset += buffer_len;
        kfree(passwords_buffer);
        return buffer_len;
    }
}
