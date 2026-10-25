#!/bin/sh
# 编译 ktool（ARM32 静态）。
#
# 最早用 `zig cc -target arm-linux-musleabi`，后来改用 GNU 交叉工具链静态链接。
# 差别只在 libc：
#   zig/musl   -> 体积 ~1.4MB
#   gcc/glibc  -> 体积 ~3.4MB，启动稍慢（pages 多），功能一致
# 两者都是纯静态 ELF，Android 侧不经过 linker，直接 exec。
#
# 工具链选择（按优先级）：
#   TOOLCHAIN=/opt/arm/bin ./build.sh            指定工具链目录
#   CROSS_COMPILE=arm-linux-gnueabi- ./build.sh  指定前缀
#   ./build.sh                                   用 PATH 里的 arm-none-linux-gnueabihf-gcc
#
# 用法：./build.sh [输出名]   默认 ktool（输出到 ../src/）
set -e

if [ -n "$TOOLCHAIN" ]; then
	PREFIX="$TOOLCHAIN/arm-none-linux-gnueabihf-"
else
	PREFIX="${CROSS_COMPILE:-arm-none-linux-gnueabihf-}"
fi
CC="${PREFIX}gcc"
[ -x "${CC}.exe" ] && CC="${CC}.exe"
STRIP="${PREFIX}strip"
[ -x "${STRIP}.exe" ] && STRIP="${STRIP}.exe"

OUT="${1:-ktool}"
cd "$(dirname "$0")/../src"

"$CC" -static -O2 -pthread \
	-Wall -Wextra -Wno-unused-parameter -Wno-sign-compare \
	-o "$OUT" ktool.c

"$STRIP" "$OUT" 2>/dev/null || true
ls -l "$OUT"
