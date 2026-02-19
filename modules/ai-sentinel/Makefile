# SPDX-License-Identifier: GPL-2.0
obj-m := ai_sentinel.o
ai_sentinel-y := src/main.o src/hooks.o src/process_tracker.o src/netlink.o src/sysfs.o
ccflags-y := -Wall -Wextra
KERNEL_DIR := /root/aegis-os/kernel/src/linux-6.6.50

all: modules

modules:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) clean
	rm -f Module.symvers modules.order
