#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>

#define DEVICE "/dev/otp0"

void print_help(void)
{
    fprintf(stderr, "Usage: otp_config KEY <key>\n");
    fprintf(stderr, "                  +PW <password>\n");
    fprintf(stderr, "                  -PW <password>\n");
    fprintf(stderr, "                  SET <method>\n");
}

int main(int argc, char *argv[]) {
    int fd;

    if (argc != 3) {
        print_help();
        return 1;
    }

    char command[64];

    if (!strcmp(argv[1], "KEY")) {
        // Changer la clé
        snprintf(command, sizeof(command), "KEY %s\n", argv[2]);
        printf("Changing key to %s ...\n", argv[2]);
    } else if (!strcmp(argv[1], "+PW")) {
        // Ajouter un mot de passe
        snprintf(command, sizeof(command), "+PW %s\n", argv[2]);
        printf("Creating password %s ...\n", argv[2]);
    } else if (!strcmp(argv[1], "-PW")) {
        // Supprimer un mot de passe
        snprintf(command, sizeof(command), "-PW %s\n", argv[2]);
        printf("Deleting password %s ...\n", argv[2]);
    } else if (!strcmp(argv[1], "SET")) {
        // Supprimer un mot de passe
        snprintf(command, sizeof(command), "SET %s\n", argv[2]);
        printf("Setting method to %s ...\n", argv[2]);
    }  else if (!strcmp(argv[1], "SET")) {
        // Supprimer un mot de passe
        snprintf(command, sizeof(command), "SET %s\n", argv[2]);
        printf("Setting method to %s ...\n", argv[2]);
    } else {
        print_help();
        return 1;
    }

    fd = open(DEVICE, O_WRONLY);
    if (fd == -1) {
        perror("Failed to open device");
        return 1;
    }
    if (write(fd, command, strlen(command)) == -1) {
        perror("Failed to write to device");
        close(fd);
        return 1;
    }
    printf("Done.\n");

    close(fd);
    return 0;
}
