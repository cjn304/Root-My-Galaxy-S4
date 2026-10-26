#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
#   ./install.sh          persistent install (default)
#   ./install.sh -temp    temporary: /data/local/tmp only, gone after reboot
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
usage: install.sh [-temp|-u]

  (no args)  persistent install: ktool + su under /system, boot hook installed
  -temp      temporary install: ktool only, in /data/local/tmp, gone after reboot
  -u         uninstall: restore the stock boot script, remove /system files
EOF
}

MODE=persistent
while [ $# -gt 0 ]; do
	case "$1" in
	-temp|--temp)   MODE=temp ;;
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
uninstall() {
	echo "uninstall is not implemented yet." >&2
	echo "It needs avtab rule removal ('ktool avdel') to restore the policy" >&2
	echo "without a reboot; that lands in the next commit." >&2
	exit 4
}

case "$MODE" in
persistent) install_persistent ;;
temp)       install_temp ;;
uninstall)  uninstall ;;
esac
