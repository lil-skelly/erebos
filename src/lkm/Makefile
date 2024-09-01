# Makefile for the sample LKM. Use `make test` to test it
obj-m += lkm.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test:
	sudo dmesg -C
	sudo insmod lkm.ko
	sudo rmmod lkm.ko
	sudo dmesg