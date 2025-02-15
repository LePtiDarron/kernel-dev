NAME			=	otp_module

KERNEL_DIR		=	/lib/modules/$(shell uname -r)/build

SRC				:=	src/$(NAME)

obj-m			:=	$(NAME).o

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean

re:	clean all

.PHONY:	all clean re
