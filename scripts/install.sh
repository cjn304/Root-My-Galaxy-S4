#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
#   ./install.sh          persistent install (default)
#   ./install.sh -t        temporary: /data/local/tmp only, gone after reboot
#   ./install.sh -u       uninstall, back to stock without flashing
#
# Persistent install writes four files under /system and appends a marked block
# to init.sec.boot.sh, so root comes back on every boot.
#
# Temporary install writes nothing to /system: no boot hook, no module, no su.
# Only the ktool binary goes into /data/local/tmp. After a reboot there is no
# root left, and the leftover copy can be deleted at will.
set -e

export MSYS_NO_PATHCONV=1
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../src"

usage() {
	cat <<'EOF'
usage: install.sh [-t|-u]

  (no args)  persistent install: ktool + su under /system, boot hook installed
  -t         temporary install: ktool only, in /data/local/tmp, gone after reboot
  -u         uninstall: restore the stock boot script, remove /system files
EOF
}

MODE=persistent
while [ $# -gt 0 ]; do
	case "$1" in
	-t|--temp)      MODE=temp ;;
	-u|--uninstall) MODE=uninstall ;;
	-h|--help)      usage; exit 0 ;;
	*)              echo "unknown option: $1" >&2; usage; exit 2 ;;
	esac
	shift
done

# ---- device ---------------------------------------------------------------
adb get-state >/dev/null 2>&1 || { echo "no device connected" >&2; exit 1; }

q() { adb shell "$1" 2>/dev/null | tr -d '\r\n'; }

# ---- state ----------------------------------------------------------------
# The three install artefacts are independent, so measure each and then
# collapse into one verdict. "mixed" means an install was interrupted halfway.
HAS_KT=$(q 'if [ -f /system/bin/ktool ]; then echo 1; else echo 0; fi')
HAS_SU=$(q 'if [ -f /system/xbin/su ]; then echo 1; else echo 0; fi')
HAS_HOOK=$(q 'if grep -q "2a auto begin" /system/etc/init.sec.boot.sh 2>/dev/null; then echo 1; else echo 0; fi')
HAS_TMP=$(q 'if [ -x /data/local/tmp/ktool_temp ] || [ -x /data/local/tmp/ktool_new ]; then echo 1; else echo 0; fi')
HAS_MOD=$(q 'lsmod 2>/dev/null | grep -c ktool_mod')

if [ "$HAS_KT" = 1 ] && [ "$HAS_HOOK" != 0 ]; then
	STATE=persistent
elif [ "$HAS_KT" = 1 ] || [ "$HAS_HOOK" != 0 ]; then
	STATE=mixed
elif [ "$HAS_TMP" = 1 ]; then
	STATE=temp
else
	STATE=clean
fi

echo "== state: $STATE"
echo "   /system/bin/ktool=$HAS_KT  /system/xbin/su=$HAS_SU  boot hook=$HAS_HOOK  tmp copy=$HAS_TMP  module=$HAS_MOD"
echo

# ---- persistent -----------------------------------------------------------
install_persistent() {
	case "$STATE" in
	persistent) echo "   already persistent — redeploying over it" ;;
	mixed)      echo "   WARNING: partial install detected; continuing anyway" ;;
	temp)       echo "   temporary copy present; it stays until /data is wiped" ;;
	clean)      : ;;
	esac

	echo "== [1/4] ktool binary =="
	if [ -f "$SRC/ktool" ]; then
		echo "src/ktool present, skipping build"
	else
		"$HERE/build.sh"
	fi

	echo "== [2/4] deploy ktool =="
	"$HERE/deploy_ktool.sh"

	echo "== [3/4] su binary =="
	if [ -f "$SRC/su_new" ]; then
		echo "src/su_new present, skipping build"
	else
		"$HERE/build_su.sh"
	fi

	echo "== [4/4] deploy su =="
	"$HERE/deploy_su.sh"

	echo "== done: ktool + su installed (persistent) =="
}

# ---- temporary ------------------------------------------------------------
install_temp() {
	case "$STATE" in
	persistent|mixed)
		echo "refusing: a persistent install is present on this device." >&2
		echo "         run './install.sh -u' first, or use the default mode to update it." >&2
		exit 3
		;;
	temp)
		echo "   overwriting the existing temporary copy"
		;;
	clean)
		: ;;
	esac

	echo "== [1/3] ktool binary =="
	if [ -f "$SRC/ktool" ]; then
		echo "src/ktool present, skipping build"
	else
		"$HERE/build.sh"
	fi

	echo "== [2/3] push to /data/local/tmp =="
	adb push "$SRC/ktool" /data/local/tmp/ktool_temp >/dev/null
	adb shell chmod 755 /data/local/tmp/ktool_temp
	echo "   /data/local/tmp/ktool_temp"

	echo "== [3/3] self test =="
	adb shell '/data/local/tmp/ktool_temp backend probe'

	echo
	echo "temporary install done. Nothing was written to /system."
	echo "   use:  adb shell /data/local/tmp/ktool_temp <command>"
	echo "   wipe: adb shell rm -f /data/local/tmp/ktool_temp   (or just reboot)"
	echo "   note: no module and no su, so 'ish' / 'ctx' / the avtab rules are"
	echo "         unavailable. Persistent-only features are simply absent."
}

# ---- uninstall ------------------------------------------------------------
#
# What this can and cannot do without a reboot:
#
#   yes  revoke the 8 avtab rules (echo avrestore > /dev/ktool)
#   yes  drop the permissive window and flush AVC
#   yes  restore init.sec.boot.sh, delete the /system files, wipe /data
#   no   undo the exec_br patch
#
# The exec patch cannot be undone here on purpose: with the KNOX branch back in
# place, even /system/bin/rm refuses to execute, so the deletions that follow
# would fail. It lives in memory only and a reboot clears it. Everything else
# is gone before the reboot, which is what matters.
uninstall() {
	case "$STATE" in
	clean)
		echo "nothing to remove — device is already clean"
		exit 0
		;;
	temp)
		echo "== removing the temporary install =="
		adb shell rm -f /data/local/tmp/ktool_temp
		echo "done. /system was never touched."
		exit 0
		;;
	esac

	KT=""
	for c in /data/local/tmp/ktool_new /data/local/tmp/ktool_temp /data/local/tmp/ktool; do
		if [ "$(q "if [ -x $c ]; then echo 1; else echo 0; fi")" = 1 ]; then
			KT=$c
			break
		fi
	done
	if [ -z "$KT" ]; then
		echo "no ktool binary on the device; cannot drive the kext removal." >&2
		echo "flash the stock firmware instead." >&2
		exit 5
	fi
	echo "   driving with $KT"

	echo "== [1/6] revoke avtab rules, close the permissive window =="
	adb shell "$KT pwn /system/bin/sh -c 'echo avrestore > /dev/ktool; echo avcflush > /dev/ktool'" 2>&1 |
		grep -E "avrestore done|avc cache flushed" || echo "   (module not loaded; avtab rules die with the reboot anyway)"

	echo "== [2/6] restore the boot script =="
	adb shell "$KT root /system/bin/sh -c '
		mount -o rw,remount /system || exit 10
		if [ -f /data/local/tmp/init.sec.boot.sh.orig ]; then
			cp /data/local/tmp/init.sec.boot.sh.orig /system/etc/init.sec.boot.sh
			echo used .orig backup
		else
			sed -i \"/2a auto begin/,/2a auto end/d\" /system/etc/init.sec.boot.sh
			sed -i \"/SPDX-License-Identifier: GPL-3.0-or-later/d\" /system/etc/init.sec.boot.sh
			echo stripped the marked block
		fi
		if sh -n /system/etc/init.sec.boot.sh 2>/dev/null; then
			echo syntax-ok
		else
			echo SYNTAX_FAIL
			mount -o ro,remount /system
			exit 11
		fi
		mount -o ro,remount /system
	'"

	echo "== [3/6] delete the /system files and su_allow =="
	adb shell "$KT root /system/bin/sh -c '
		mount -o rw,remount /system
		rm -f /system/xbin/su /system/lib/modules/ktool_mod.ko /system/bin/ktool
		rm -f /data/system/su_allow
		mount -o ro,remount /system
		ls /system/bin/ktool 2>/dev/null && echo LEFTOVER || echo removed
	'"

	echo "== [4/6] unload the module =="
	# rmmod goes through capable(CAP_SYS_MODULE), and the shell domain is not
	# granted sys_module — it works only because the permissive window opened in
	# step 1 is still open. That is the whole reason this step is here and not
	# after 'enforce'.
	adb shell "$KT root /system/bin/rmmod ktool_mod" 2>&1 | grep -v '^$' || \
		echo "   rmmod refused (module stays loaded until reboot)"

	echo "== [5/6] close the permissive window and drop the exec patch =="
	# enforce: permissive_map -> 0. The AVC flush it wants to do needs the module
	# we just unloaded, so that part fails — the map is what actually matters and
	# it is cleared regardless.
	adb shell "$KT enforce" 2>&1 | grep -v '^$' || true
	# unpatch is last: after it the KNOX branch is back and root exec is refused.
	# adb shell is uid 2000, so step 6 still works.
	adb shell "$KT unpatch" 2>&1 | grep -v '^$' || \
		echo "   unpatch failed (harmless: the reboot clears it either way)"

	echo "== [6/6] wipe /data leftovers =="
	# shell owns these; no root needed, which is why this can run after unpatch.
	adb shell 'rm -rf /data/local/tmp/ktool_new /data/local/tmp/ktool_temp \
		/data/local/tmp/ktool /data/local/tmp/sud /data/local/tmp/su_new \
		/data/local/tmp/su_prev.bak /data/local/tmp/su_access_mode'

	echo
	echo "uninstalled. The boot hook is back to stock and the /system files are"
	echo "gone, so nothing can rebuild root on the next boot."
	echo "If rmmod was refused above, the module is still resident until then."
	echo
	echo "   reinstall now:   ./install.sh — it only deploys binaries and needs no"
	echo "                    reboot. The module and the avtab rules come back on"
	echo "                    the next boot, or immediately with:"
	echo "                      ktool patch && ktool boot /system/lib/modules/ktool_mod.ko"
	echo "   reboot to finish: adb reboot"
	echo "   app prompt binary: uninstall phh's Superuser from Settings if you"
	echo "                      do not want the APK hanging around either"
}

case "$MODE" in
persistent) install_persistent ;;
temp)       install_temp ;;
uninstall)  uninstall ;;
esac
