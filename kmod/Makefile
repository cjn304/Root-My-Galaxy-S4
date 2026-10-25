# 内核模块构建（ARM32 / Samsung 3.4.5 / GT-I9500）
#
# KDIR 指向已配置好的 GT-I9500 内核源码树（需要有 .config 和 Module.symvers）。
#
#   make KDIR=/path/to/kernel_i9500
#
# 交叉编译器默认 arm-none-linux-gnueabihf-，可用 CROSS_COMPILE 覆盖。
# 仓库里只保留正式模块；实验用的 kprobe_tmp / klistprobe 没有收录，
# 需要的话在 obj-m 里加回来。

obj-m := ktool_mod.o
ccflags-y := -marm -march=armv7-a
ccflags-y += -Wno-unused-function

KDIR ?= /path/to/kernel_i9500
PWD  := $(shell pwd)
ARCH ?= arm
CROSS_COMPILE ?= arm-none-linux-gnueabihf-

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) \
		KCFLAGS='-Wno-error -fcommon' modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: all clean
