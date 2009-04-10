#CFILES = securitycube.c
obj-m+=securitycube.o
sc-objs := $(CFILES:.c=.o)
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
