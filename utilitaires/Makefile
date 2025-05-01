CC = gcc
CFLAGS = -Wall -Wextra -O2

all: otp_client otp_config

otp_client: otp_client.c
	$(CC) $(CFLAGS) -o otp_client otp_client.c

otp_config: otp_config.c
	$(CC) $(CFLAGS) -o otp_config otp_config.c

clean:
	rm -f otp_client otp_config

re:	clean all

.PHONY:	clean all otp_config otp_client
