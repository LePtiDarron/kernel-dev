obj-m := module_otp.o

module_otp-objs := src/otp_module.o src/otp_read.o src/otp_write.o src/password_list.o

KDIR := /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)

EXTRA_CFLAGS="-I$(PWD)/include"

all:
	$(MAKE) -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="-I$(PWD)/include" modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

re:	clean all

.PHONY:	all clean re
