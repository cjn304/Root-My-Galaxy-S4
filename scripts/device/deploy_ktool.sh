#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

# Device-side ktool replacement. Launched by scripts/deploy_ktool.sh through
# `ktool pwn`, so by the time this runs we are uid 0 and permissive_map is set.
#
# Why it cannot be started via `su -c`: this file lives under /data/local/tmp
# (shell_data_file). The `shell` domain has execute on shell_data_file, but
# `init_shell` does not — so `su -c sh /data/local/tmp/...` fails. Going
# through `ktool pwn` keeps us in the shell domain with uid 0, which works.
#
# Deliberately NOT `set -e`: every failure path still has to reach `enforce`,
# otherwise the device is left permissive.

SYS=/system/bin/ktool
NEW=/data/local/tmp/ktool_new
BAK=/data/local/tmp/ktool.sys.bak

echo "== 1. backup =="
if [ -f "$SYS" ]; then
	cp "$SYS" "$BAK" && ls -l "$BAK"
else
	echo "no existing $SYS (first install)"
fi

# permissive_map only affects *new* verdicts. Any cached
# shell -> filesystem { remount } deny keeps winning until the cache is reset.
"$NEW" flush -y >/dev/null 2>&1 || echo "flush skipped (module not loaded?)"

echo "== 2. remount rw =="
if ! mount -o rw,remount /system; then
	echo "FATAL: remount rw failed, nothing changed"
	"$NEW" enforce
	exit 10
fi

echo "== 3. replace =="
if ! cp "$NEW" "$SYS"; then
	echo "FATAL: copy failed"
	mount -o ro,remount /system
	"$NEW" enforce
	exit 11
fi
chown root:root "$SYS"
chmod 700 "$SYS"

# Module file, if the PC side pushed one. This has to happen inside the
# permissive window opened above: the shell domain has no write on system_file,
# and it is only permissive_map that lets this cp through.
if [ -f /data/local/tmp/ktool_mod.ko ]; then
	if cp /data/local/tmp/ktool_mod.ko /system/lib/modules/ktool_mod.ko; then
		chown root:root /system/lib/modules/ktool_mod.ko
		chmod 644 /system/lib/modules/ktool_mod.ko
		echo "module file: $(ls -l /system/lib/modules/ktool_mod.ko)"
	else
		echo "module file deploy FAILED"
	fi
else
	echo "module file: not provided"
fi
chcon u:object_r:system_file:s0 "$SYS" || echo "chcon failed (label may already be right)"
ls -lZ "$SYS"

echo "== 4. remount ro =="
mount -o ro,remount /system || echo "warn: still rw"

echo "== 5. self test =="
"$SYS" target || echo "self test FAILED — binary runs but target lookup failed"

echo "== 6. close the permissive window =="
"$SYS" enforce || echo "enforce FAILED — run 'ktool enforce' manually"

echo DEPLOY_OK
