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

echo "== 3b. boot hook =="
# Only the marked block is appended. The lines before it are the device's own
# stock script and are not the same across firmware builds, so replacing the
# whole file would silently drop whatever Samsung put there.
BOOT=/system/etc/init.sec.boot.sh
BOOTBAK=/data/local/tmp/init.sec.boot.sh.orig
if [ -f /data/local/tmp/boot_hook.sh ]; then
	if grep -q "2a auto begin" "$BOOT" 2>/dev/null; then
		echo "boot hook: already present, left alone"
	else
		# First clean copy becomes the restore point install.sh -u copies back.
		[ -f "$BOOTBAK" ] || cp "$BOOT" "$BOOTBAK"
		# The stock file need not end with a newline.
		printf '\n' >> "$BOOT"
		cat /data/local/tmp/boot_hook.sh >> "$BOOT"
		if sh -n "$BOOT" 2>/dev/null; then
			echo "boot hook: installed, syntax ok"
		else
			cp "$BOOTBAK" "$BOOT"
			echo "boot hook: SYNTAX FAIL after append — reverted"
		fi
	fi
else
	echo "boot hook: not provided"
fi

echo "== 4. remount ro =="
mount -o ro,remount /system || echo "warn: still rw"

echo "== 5. self test =="
"$SYS" target || echo "self test FAILED — binary runs but target lookup failed"

echo "== 6. close the permissive window =="
# rc=4 is not a failure here: it means permissive_map was cleared but the AVC
# cache could not be flushed, because avcflush goes through the module and on a
# fresh install the module is not loaded yet. install.sh loads it and runs
# enforce again, which is when the flush actually lands.
"$SYS" enforce
enforce_rc=$?
case "$enforce_rc" in
0) ;;
4) echo "enforce: map cleared, AVC flush deferred to the activation step" ;;
*) echo "enforce FAILED rc=$enforce_rc — run 'ktool enforce' manually" ;;
esac

echo DEPLOY_OK
