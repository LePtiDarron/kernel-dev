#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define DEVICE "/dev/otp0"
#define OTP_LEN 6

int read_device(char *buffer)
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
    char buffer[700];
    char *pass;

    if (argc != 2)
        return 1;

    if (read_device(buffer) == -1)
        return 1;

    pass = strtok(buffer, "\n");
    for (int i; pass; i++) {
        if (!strcmp(pass, argv[1])) {
            printf("Correct !\n");
            return 0;
        }
        pass = strtok(NULL, "\n");
    }
    printf("Wrong !\n");
    return 1;
}
