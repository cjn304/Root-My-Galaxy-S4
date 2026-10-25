#!/bin/bash
# 部署 su 到 /system/xbin（PC 侧脚本，走 adb）。
#
# 旧版是设备侧 sh，有两处过时/危险行为，已废弃：
#   1. 默认把 "2000" 写进 /data/system/su_allow —— 等于给 adb shell 永久免弹窗；
#      现在由 persist.sys.root_access 四档控制，不需要它（要写也只该按需手写）。
#   2. 假设二进制已经在 /data/local/tmp/su，从不校验是不是新版。
#
# 现在的流程（与 P4.92 一致）：
#   pwn（置 permissive）→ flush（必做，否则旧 AVC 条目压过新规则）
#   → mount rw → cp + chown/chmod/chcon → mount ro
#   → 还原全局 enforcing → enforce
#
# 用法：./deploy_su.sh [su 二进制路径]   默认 <repo>/src/su_new
set -e
export MSYS_NO_PATHCONV=1

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:-$HERE/../src/su_new}"
DST="/system/xbin/su"

# ktool must be reachable from the `shell` domain, i.e. under /data/local/tmp.
# /system/bin/ktool is 0700 root:root and cannot be executed there.
# deploy_ktool.sh leaves ktool_new behind, so prefer that.
KT="/data/local/tmp/ktool_new"
adb shell "[ -x $KT ]" 2>/dev/null || KT="/data/local/tmp/ktool"
adb shell "[ -x $KT ]" 2>/dev/null || { echo "设备上找不到 $KT（先跑 ./deploy_ktool.sh）"; exit 1; }

[ -f "$BIN" ] || { echo "找不到 $BIN（先跑 ./build_su.sh）"; exit 1; }
if command -v cygpath >/dev/null 2>&1; then
	BIN="$(cygpath -w "$BIN")"
fi
echo "== 部署 $BIN ($(stat -c %s "$BIN") B)，用 $KT 提权 =="

adb push "$BIN" /data/local/tmp/su_new >/dev/null
adb shell "chmod 755 /data/local/tmp/su_new"

# 先自检：跑不了就别刷进 /system
V=$(adb shell "/data/local/tmp/su_new -v" 2>&1 | tr -d '\r')
case "$V" in
17*) echo "自检 ok: $V" ;;
*)   echo "自检失败：$V"; exit 2 ;;
esac

adb shell "$KT pwn /system/bin/sh -c 'true'" >/dev/null 2>&1 || true
adb shell "$KT flush -y" >/dev/null 2>&1 || { echo "flush 失败（模块没装？）"; exit 3; }

adb shell "$KT root /system/bin/sh -c '
	mount -o rw,remount /system || exit 10
	cp $DST /data/local/tmp/su_prev.bak 2>/dev/null
	cp /data/local/tmp/su_new $DST || exit 11
	chown 0:0 $DST
	chmod 755 $DST
	chcon u:object_r:su_exec:s0 $DST
	mount -o ro,remount /system
	echo deployed
'" | tail -1

adb shell "$KT w32 0xc0c4d490 1" >/dev/null 2>&1 || true
adb shell "$KT enforce" >/dev/null 2>&1 || true

echo "== 终态 =="
adb shell "echo su=\$(ls -l $DST); echo prop=\$(getprop persist.sys.root_access); echo enforce=\$(getenforce)"
