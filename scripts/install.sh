#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
#   ./install.sh          persistent install
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
  -t         temporary install: ktool only, in /data/local/tmp (root gone after reboot)
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

	echo "== [1/6] ktool binary =="
	if [ -f "$SRC/ktool" ]; then
		echo "src/ktool present, skipping build"
	else
		"$HERE/build.sh"
	fi

	echo "== [2/6] deploy ktool (+ module file + boot hook) =="
	# Everything /system-bound rides along with the ktool deploy: that script
	# runs inside the permissive window, which is the only state in which the
	# shell domain can write to /system. Doing it later, as its own step, fails
	# — and doing it through su fails too, because su itself needs /dev/ktool,
	# which only exists once the module is loaded.
	KO="$HERE/../kmod/ktool_mod.ko"
	if [ -f "$KO" ]; then
		KOW="$KO"
		if command -v cygpath >/dev/null 2>&1; then
			KOW="$(cygpath -w "$KO")"
		fi
		adb push "$KOW" /data/local/tmp/ktool_mod.ko >/dev/null
	else
		echo "   kmod/ktool_mod.ko not built — module will be skipped"
	fi
	# Only the marked block, not the whole file: the lines before it are the
	# device's own stock script and differ between firmware builds.
	HOOK="$HERE/init.sec.boot.v9g.sh"
	if [ -f "$HOOK" ]; then
		sed -n '/2a auto begin/,/2a auto end/p' "$HOOK" > /tmp/ktool_hook.$$
		if [ -s /tmp/ktool_hook.$$ ]; then
			HOOKW=/tmp/ktool_hook.$$
			if command -v cygpath >/dev/null 2>&1; then
				HOOKW="$(cygpath -w /tmp/ktool_hook.$$)"
			fi
			adb push "$HOOKW" /data/local/tmp/boot_hook.sh >/dev/null
		else
			echo "   boot hook block not found in $HOOK — persistence will be skipped"
		fi
		rm -f /tmp/ktool_hook.$$
	else
		echo "   scripts/init.sec.boot.v9g.sh missing — persistence will be skipped"
	fi
	"$HERE/deploy_ktool.sh"
	adb shell rm -f /data/local/tmp/ktool_mod.ko /data/local/tmp/boot_hook.sh 2>/dev/null || true

	echo "== [3/6] su binary =="
	if [ -f "$SRC/su_new" ]; then
		echo "src/su_new present, skipping build"
	else
		"$HERE/build_su.sh"
	fi

	echo "== [4/6] deploy su =="
	# Inlined from the old deploy_su.sh: it had no standalone entry point and
	# could not run unless deploy_ktool.sh had already left
	# /data/local/tmp/ktool_new behind, so the extra layer only added a file.
	#
	# Two things from that script are here on purpose. The version check refuses
	# to install a binary that cannot print its own version — a su that starts
	# but breaks later is worse than no su. And nothing writes
	# /data/system/su_allow: the old device-side script put "2000" there, which
	# silently grants adb permanent root and bypasses the tier setting.
	SU="$SRC/su_new"
	if [ ! -f "$SU" ]; then
		echo "   $SU missing — skipping su (build it with ./scripts/build_su.sh)"
	else
		SUW="$SU"
		if command -v cygpath >/dev/null 2>&1; then
			SUW="$(cygpath -w "$SU")"
		fi
		adb push "$SUW" /data/local/tmp/su_new >/dev/null
		adb shell chmod 755 /data/local/tmp/su_new
		V=$(adb shell '/data/local/tmp/su_new -v' 2>&1 | tr -d '\r')
		case "$V" in
		17*) echo "   self test ok: $V" ;;
		*)   echo "   self test FAILED: $V"; exit 2 ;;
		esac
		# deploy_ktool.sh closed the permissive window when it finished, and a
		# remount on an enforcing kernel is refused. Step 5 closes it again.
		adb shell '/data/local/tmp/ktool_new pwn /system/bin/sh -c true' >/dev/null 2>&1 || true
		# Best effort: avcflush goes through the module, which may not be loaded
		# yet. Step 5 runs enforce after insmod, and that one does flush.
		adb shell '/data/local/tmp/ktool_new flush -y' >/dev/null 2>&1 || \
			echo "   flush skipped (module not loaded yet; step 5 flushes)"
		adb shell "/data/local/tmp/ktool_new root /system/bin/sh -c '
			mount -o rw,remount /system || exit 10
			cp /system/xbin/su /data/local/tmp/su_prev.bak 2>/dev/null
			cp /data/local/tmp/su_new /system/xbin/su || exit 11
			chown 0:0 /system/xbin/su
			chmod 755 /system/xbin/su
			chcon u:object_r:su_exec:s0 /system/xbin/su
			mount -o ro,remount /system
			echo deployed
		'" | grep -E "deployed|denied|fail" || echo "   su deploy FAILED"
	fi

	echo "== [5/6] activate now =="
	# Everything above only put files on disk; the module is not loaded and the
	# avtab rules are not in the policy until something runs boot. Doing it here
	# is what makes install -> uninstall -> install repeatable without rebooting.
	if [ "$HAS_MOD" = 0 ]; then
		adb shell '/data/local/tmp/ktool_new patch' 2>&1 | grep -v '^$' || \
			echo "   patch failed"
		adb shell '/data/local/tmp/ktool_new boot /system/lib/modules/ktool_mod.ko' 2>&1 |
			grep -v '^$' || echo "   boot failed"
		adb shell '/data/local/tmp/ktool_new enforce' 2>&1 | grep -v '^$' || true
	else
		echo "   module already loaded, nothing to activate"
	fi

	echo "== [6/6] done: ktool + su + module installed (persistent) =="
	echo "   root survives reboots via /system/etc/init.sec.boot.sh"
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
# Everything runs without a reboot. What is left afterwards is the loaded
# module (only if rmmod was refused) and whatever a reboot clears anyway.
#
# Two steps cannot be reordered, and each one says why at the step itself:
#   [4] rmmod needs the permissive window that [1] opened
#   [5] unpatch is last — with the KNOX branch back, root exec is refused
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
		# /data/local/tmp/sud is created by su and owned by root; the final step
		# runs as shell and cannot remove it, so it goes here while we still have
		# a working root exec.
		rm -rf /data/local/tmp/sud
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
