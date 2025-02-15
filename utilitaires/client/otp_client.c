#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define DEVICE "/dev/otp0"
#define OTP_LEN 6

int read_device()
{
    int fd;
    ssize_t bytes_read;
    char buffer[256];

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
    printf("%s\n", buffer);

    close(fd);
    return 0;
}

int main(int argc, char *argv[])
{
    if (read_device() == -1)
        return 1;
    return 0;
}
