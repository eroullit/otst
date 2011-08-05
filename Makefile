obj-m += otst.o

MDIR := /lib/modules/$(shell uname -r)
KDIR := $(MDIR)/build

all: build

build:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

