# APK-side sources

**English** | [简体中文](README.zh-CN.md)

A partial snapshot of **phh's Superuser**, kept for reference: the prompt activities, the settings
screen, and the socket authorization protocol that the `su` binary speaks.

## This directory does not build

`Android.mk` is the upstream build file, and it references sources that are not in this snapshot —
`utils.c`, `pts.c`, `binds.c`, `sqlite3/`, `jni/`, `packageName`. It is here to show how the pieces
fit together, not to be run.

The `su` binary this project ships is `../src/su_fork.c`: an independent implementation of the same
protocol, built with `../scripts/build_su.sh` and deployed by `../scripts/deploy_su.sh`.

## License

**Apache-2.0.** Every file that carries a header says so:

- `activity.c`, `daemon.c` — Copyright 2010 Adam Shanks, 2008 Zinx Verituse
- `db.c` — Copyright 2013 Koushik Dutta
- `phh_su.c`, `phh_su.h`, `su.h`, `utils.h`, `koush/su.c`, `koush/su.h` — Copyright 2015
  Pierre-Hugues Husson, plus the above
- `MultitaskSuRequestActivity.java`, `RequestActivity.java` — same upstream tree

A few files carry no header in this snapshot (`Settings.java`, `SuHelper.java`,
`SuCheckerReceiver.java`, `lsu_Shell.java`, and the two empty `koush/` placeholders); they come from
the same upstream tree.

Apache-2.0 is **incompatible with GPL-2.0** — its patent clause has no GPL-2.0 equivalent — which is
why this directory stays a separate program. It communicates with `su` over a socket, and nothing
here is linked against `kmod/` or `src/`.

## What this project changed in the protocol

- `SO_PEERCRED` on the accepted socket: only the managing app's uid is accepted, so no other app
  can connect first and forge an `ALLOW`
- Four-tier policy through `persist.sys.root_access`, with `/data/local/tmp/su_access_mode` as an
  override that takes precedence
- ADB requests bypass the prompt in the `adb_only` and `apps_and_adb` tiers; apps always go through
  the allowlist and the prompt

## Files

| File | Purpose |
|---|---|
| `RequestActivity.java` | Permission prompt |
| `MultitaskSuRequestActivity.java` | Prompt variant for multi-window |
| `Settings.java` | Settings screen (tier selection) |
| `SuHelper.java` | Protocol wrapper |
| `SuCheckerReceiver.java` | Root status check |
| `lsu_Shell.java` | `libsuperuser` shell wrapper |
| `phh_su.c` | Main `su` implementation (Apache-2.0) |
| `su.c` | Byte-identical copy of `phh_su.c`, kept because `Android.mk` names it |
| `phh_su.h`, `su.h`, `utils.h` | Shared headers |
| `activity.c`, `daemon.c`, `db.c` | Upstream activity / daemon / database layer |
| `hacks.c` | Platform shims |
| `koush/su.c`, `koush/su.h` | Koush's original implementation |
| `koush/daemon.c`, `koush/db.c` | Empty placeholders in this snapshot |
| `Android.mk` | Upstream build file, incomplete here (see above) |
