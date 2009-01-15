CFILES = acm.c
obj-m+=lsmacm.o
obj-m+=addhook.o
obj-m+=inshook.o
obj-m+=hook2.o
lsmacm-objs := $(CFILES:.c=.o)
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
