#include "otp_module.h"

// Convertit le temps (64 octes) en 8 octes
static void formate_time(uint64_t value, uint8_t *buffer) {
    int i;
    for (i = 7; i >= 0; i--) {
        buffer[i] = value & 0xFF;
        value >>= 8;
    }
}

// Fonction qui génère un OTP basé sur le temps
static int generate_otp(char *otp_code)
{
    struct timespec64 ts;
    uint8_t time_bytes[8], hmac_result[20];
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int offset, binary_code, otp_value;
    uint64_t time_step;

    // Vérifier si la clé secrète est vide
    if (strlen(otp_config.secret_key) == 0) {
        pr_err("OTP Secret key is invalid");
        return -EINVAL;
    }

    ktime_get_real_ts64(&ts);                       // Obtenir le timestamp UNIX
    time_step = ts.tv_sec / otp_config.validity;    // Divise par la durée de validité qui correspond également a l'interval
    formate_time(time_step, time_bytes);            // Convertir en 8 ocets

    // Initialiser Hmac Sha 1
    tfm = crypto_alloc_shash("hmac(sha1)", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("OTP Failed to allocate HMAC-SHA1 transform");
        return -1;
    }

    // Alloue de la place dans l'espace utilisateur
    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL); // taille de shash_desc + tfm, GFP_KERNEL parce que c'est un noyeau
    if (!desc) {
        pr_err("OTP Failed to allocate memory for shash_desc");
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;
    memset(desc + 1, 0, crypto_shash_descsize(tfm)); // mets a zero tous les octes apres slash_desc pour eviter des valeurs aléatoire dans la transformations

    // Configurer la clé secrète pour HMAC
    if (crypto_shash_setkey(tfm, otp_config.secret_key, strlen(otp_config.secret_key))) {
        pr_err("OTP Failed to set HMAC key");
        kfree(desc);
        crypto_free_shash(tfm);
        return -1;
    }

    // Calculer HMAC(time_step)
    if (crypto_shash_digest(desc, time_bytes, sizeof(time_bytes), hmac_result)) {
        pr_err("OTP Failed to calculate HMAC digest");
        kfree(desc);
        crypto_free_shash(tfm);
        return -1;
    }

    // "Dynamic Truncation" : Extraire 4 octets du HMAC
    offset = hmac_result[19] & 0x0F;                            // Nombre entre 0 et 15
    binary_code = ((hmac_result[offset] & 0x7F) << 24)      |   // 0x7F (01111111) et 0xFF (11111111)
                  ((hmac_result[offset + 1] & 0xFF) << 16)  |   // pour etre sur de ne pas avoir le
                  ((hmac_result[offset + 2] & 0xFF) << 8)   |   // premier bits de signe et donc assurer
                  ((hmac_result[offset + 3] & 0xFF));           // le fait d'avoir un nombre positif

    // Prendre les 6 derniers chiffres le nombre le plus grand possible etant 419717680
    otp_value = binary_code % 1000000;

    // Convertir en chaîne de 6 character
    snprintf(otp_code, OTP_LEN, "%07d", otp_value);

    kfree(desc);
    crypto_free_shash(tfm);
    pr_info("OTP Generated OTP: %s", otp_code);

    return 0;
}

// Fonction de lecture du device (afficher OTP ou mots de passe)
ssize_t otp_read(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
    char passwords[700] = "\0";
    char otp_code[OTP_LEN + 1];

    if (*offset > 0)
        return 0;

    if (otp_config.method == 0) {
        // Générer et envoyer l'OTP
        if (generate_otp(otp_code))
            return -EFAULT;
        otp_code[OTP_LEN] = '\0';
        if (copy_to_user(buf, otp_code, OTP_LEN + 1)) 
            return -EFAULT;
        *offset += OTP_LEN;
        return OTP_LEN;
    } else {
        // afficher les mot de passe
        for (int i = 0; i < MAX_PASSWORDS; i++) {
            if (otp_config.passwords[i][0] == '\0') break;
            strcat(passwords, otp_config.passwords[i]);
        }
        *offset += strlen(passwords);
        if (copy_to_user(buf, passwords, strlen(passwords))) 
            return -EFAULT;
        return strlen(passwords);
    }
}
