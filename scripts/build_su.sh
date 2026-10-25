#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

# 编译 su（ARM32 静态 + 静态 sqlite3）。
#
# 命令来源：P4.18 记录的原始构建（当时产出 753,912 B，与现役二进制一字节不差）：
#   gcc -static -O2 -s -I. -DSQLITE_OMIT_LOAD_EXTENSION \
#       -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_WAL -o su su_apk.c sqlite3.c
# 现在源码是 src/su_fork.c（fork 版），参数不变。
#
# 注意 -DSQLITE_THREADSAFE=0：su 是单线程用法（fork 后子进程各自开库），
# 打开多线程支持会引入 pthread mutex，静态体积更大且没必要。
#
# 用法：TOOLCHAIN=... ./build_su.sh [输出名]   默认 su_new
set -e

if [ -n "$TOOLCHAIN" ]; then
	PREFIX="$TOOLCHAIN/arm-none-linux-gnueabihf-"
else
	PREFIX="${CROSS_COMPILE:-arm-none-linux-gnueabihf-}"
fi
CC="${PREFIX}gcc"
[ -x "${CC}.exe" ] && CC="${CC}.exe"

OUT="${1:-su_new}"
cd "$(dirname "$0")/../src"

"$CC" -static -O2 -s -I. \
	-DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_WAL \
	-Wno-return-local-addr \
	-o "$OUT" su_fork.c sqlite3.c -lpthread
ls -l "$OUT"
