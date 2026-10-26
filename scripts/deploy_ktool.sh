#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later

# One-shot ktool deployment (PC side, over adb).
#
#   ./deploy_ktool.sh              build output at ../src/ktool
#   ./deploy_ktool.sh path/to/ktool
#
# What it does, in one adb round trip:
#   push -> chmod -> ktool pwn (uid0 + permissive) -> flush -> remount rw
#   -> replace -> chown/chmod/chcon -> remount ro -> self test -> restore
#
# It does NOT build. Run ./build.sh first.
set -e

# Git Bash on Windows rewrites /data/... into C:/...; disable it.
export MSYS_NO_PATHCONV=1

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:-$HERE/../src/ktool}"
DEV="$HERE/device_ktool.sh"

[ -f "$BIN" ] || { echo "找不到 $BIN（先跑 ./build.sh）"; exit 1; }
[ -f "$DEV" ] || { echo "找不到 $DEV"; exit 1; }

# adb.exe is a native Windows binary: it cannot read MSYS paths like /d/foo.
# Convert the two local paths ourselves (MSYS_NO_PATHCONV is set to protect the
# /data/... remote paths from being rewritten).
if command -v cygpath >/dev/null 2>&1; then
	BIN="$(cygpath -w "$BIN")"
	DEV="$(cygpath -w "$DEV")"
fi

echo "== 部署 $BIN ($(wc -c < "$BIN") B) =="

adb push "$BIN" /data/local/tmp/ktool_new >/dev/null
adb shell chmod 755 /data/local/tmp/ktool_new
adb push "$DEV" /data/local/tmp/deploy_ktool.sh >/dev/null
adb shell chmod 755 /data/local/tmp/deploy_ktool.sh

# Escalate with the new binary itself. It is shell_data_file, and the `shell`
# domain has execute there — which is exactly what `adb shell` gives us.
# Patch first. '-u' removes the exec patch, and without it the KNOX branch in
# sys_execve refuses pwn's exec of /system/bin/sh — the deploy script would never
# start. patch only writes kernel memory through the exploit, so it needs no
# prior root and no working exec.
adb shell '/data/local/tmp/ktool_new patch' 2>&1 | tail -1
adb shell '/data/local/tmp/ktool_new pwn /system/bin/sh /data/local/tmp/deploy_ktool.sh'

echo "== 终态 =="
adb shell 'ls -lZ /system/bin/ktool; echo enforce=$(getenforce)'
