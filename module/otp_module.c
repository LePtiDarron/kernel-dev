#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/time.h>
#include <crypto/hash.h>

#define DEVICE_NAME "otp"
#define MAX_PASSWORDS 10
#define PASSWORD_LEN 16
#define KEY_VALIDITY 30
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

static int major;
static struct cdev otp_cdev;
static struct class *otp_class;
static otp_config_t otp_config = {
    .validity = KEY_VALIDITY
};


/// GENERER LE OTP ///

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
    snprintf(otp_code, OTP_LEN, "%06d", otp_value);

    kfree(desc);
    crypto_free_shash(tfm);
    pr_info("OTP Generated OTP: %s", otp_code);

    return 0;
}


/// GERER LES MOTS DE PASSE ///

// Fonction pour ajouter un mot de passe à la liste
int add_password(const char *password)
{
    for (int i = 0; i < MAX_PASSWORDS; i++) {
        if (otp_config.passwords[i][0] == '\0') {
            strncpy(otp_config.passwords[i], password, PASSWORD_LEN);
            otp_config.passwords[i][PASSWORD_LEN - 1] = '\0';
            pr_info("OTP Password added: %s", password);
            return 0;
        }
    }
    pr_err("OTP Password list is full");
    return -ENOSPC;
}

// Fonction pour supprimer un mot de passe de la liste
int delete_password(const char *password) {
    for (int i = 0; i < MAX_PASSWORDS; i++) {
        if (strncmp(otp_config.passwords[i], password, PASSWORD_LEN) == 0) {
            otp_config.passwords[i][0] = '\0';
            pr_info("OTP Password deleted: %s", password);
            return 0;
        }
    }
    pr_err("OTP Password not found: %s", password);
    return -ENOENT;
}


/// MODULE TOP ///

// Fonction de lecture du device (afficher OTP ou mots de passe)
static ssize_t otp_read(struct file *file, char __user *buf, size_t len, loff_t *offset)
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

// Fonction d'écriture pour ajouter un mot de passe ou changer la clé
static ssize_t otp_write(struct file *file, const char __user *buf, size_t len, loff_t *offset)
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
        if (add_password(user_input + 4) < 0)
            return -EFAULT;
    } else if (!strncmp(user_input, cmd_del_password, 4)) {
        // Supprimer un mot de passe
        if (delete_password(user_input + 4) < 0)
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


// Gestion des opérations sur /dev/otp0
static struct file_operations otp_fops = {
    .owner = THIS_MODULE,
    .read = otp_read,
    .write = otp_write
};

// Initialisation du module
static int __init otp_init(void)
{
    dev_t dev;
    
    // Allouer un numéro de périphérique
    if (alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME) < 0) {
        pr_err("OTP Cannot alloc a major number");
        return -1;
    }
    major = MAJOR(dev);

    // Initialiser le cdev
    cdev_init(&otp_cdev, &otp_fops);
    if (cdev_add(&otp_cdev, dev, 1) < 0) {
        unregister_chrdev_region(dev, 1);
        pr_err("OTP Impossible d'ajouter le cdev");
        return -1;
    }

    // Créer une classe et un device sous /dev/
    otp_class = class_create(THIS_MODULE, "otp_class");
    device_create(otp_class, NULL, dev, NULL, DEVICE_NAME);

    pr_info("OTP Module loaded: /dev/otp0 available.");
    return 0;
}

// Nettoyage du module
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
MODULE_DESCRIPTION("Module Kernel OTP");
