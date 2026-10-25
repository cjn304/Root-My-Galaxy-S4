#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later

# Full install: ktool (exploit + toolbox) and su (the root front-end apps talk to).
#
#   ./install.sh
#
# Builds whatever is missing, then runs the two deploy scripts in order.
# If you already have prebuilt binaries in src/, no toolchain is needed.
#
# Only want ktool, for command-line work without app prompts?
#   ./deploy_ktool.sh      is enough on its own.
set -e

export MSYS_NO_PATHCONV=1
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../src"

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

echo "== done: ktool + su installed =="
