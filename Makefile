obj-m := moddect.o
moddect-y := src/detector.o src/mod_array.o src/mod_helpers.o src/mod_kallsyms.o src/mod_rbtree.o

PWD := $(CURDIR)

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
