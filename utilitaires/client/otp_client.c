#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define DEVICE "/dev/otp0"
#define OTP_LEN 6

char *read_device(char *buffer)
{
    int fd;
    ssize_t bytes_read;

    fd = open(DEVICE, O_RDONLY);
    if (fd == -1) {
        perror("Failed to open device");
        return -1;
    }

    bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    if (bytes_read == -1) {
        perror("Failed to read from the device");
        close(fd);
        return -1;
    }

    buffer[bytes_read] = '\0';

    close(fd);
    return 0;
}

int main(int argc, char *argv[])
{
    char buffer[256];
    char *pass;

    if (argc != 2)
        return 1;

    if (read_device() == -1)
        return 1;

    pass = strtok(buffer, " \t");
    for (int i; pass[i]; i++) {
        if (!strncmp(pass[i], argv[1])) {
            free(pass);
            printf("Correct !\n");
            return 0;
        }
    }
    free(pass);
    printf("Wrong !\n");
    return 1;
}
