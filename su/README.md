# APK-side sources

**English** | [中文](README.zh-CN.md)

A copy of the `su` sources and APK-side code from **phh's Superuser**, kept for reference: the prompt activities, the settings
screen, and the socket authorization protocol that the `su` binary speaks.

## This directory does not build

`Android.mk` is the upstream build file. All of `jni/su/` is present here — `activity.c`,
`daemon.c`, `db.c`, `hacks.c`, `utils.c`, `pts.c`, `binds.c` and their headers — so the `su`
sources themselves are complete.

What is still missing for an actual `ndk-build` is the third-party payload: `jni/libselinux`,
`jni/libsepol` and `jni/sqlite3`, roughly 12 MB. They are not vendored. Clone the upstream repo if
you genuinely want to build the original `su`; this project does not.

The `su` binary this project ships is `../src/su_fork.c`: an independent implementation of the same
protocol, built from that file plus `../src/sqlite3.c`. **Nothing in this directory is needed to
build or run it.** This snapshot exists only to document the protocol and the APK-side changes.

## License

**GPL-3.0**, matching the `LICENSE` file in this directory (copied from upstream).

Most `.c` files still carry Apache-2.0 headers, dated from before the project relicensed:

- `activity.c`, `daemon.c` — Copyright 2010 Adam Shanks, 2008 Zinx Verituse
- `db.c` — Copyright 2013 Koushik Dutta
- `phh_su.c`, `phh_su.h`, `su.h`, `utils.h`, `koush/su.c`, `koush/su.h` — Copyright 2015
  Pierre-Hugues Husson, plus the above
- `binds.c`, `pts.c`, `utils.c` — same upstream tree, same headers

That is not a contradiction. Apache-2.0 is compatible with GPL-3.0 — GPL-3.0 carries a patent
clause that covers Apache's — so the combined work is distributed under GPL-3.0, which is what the
upstream `LICENSE` declares.

`kmod/` is GPL-2.0 because it is a kernel module, and GPL-3.0 is incompatible with the kernel.
Nothing here is linked against it; the two sides talk over a socket.

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
| `phh_su.c` | Main `su` implementation |
| `phh_su.h`, `su.h`, `utils.h` | Shared headers |
| `activity.c`, `daemon.c`, `db.c` | Upstream activity / daemon / database layer |
| `utils.c` | Shared helpers |
| `pts.c`, `pts.h` | PTY handling for the shell |
| `binds.c`, `binds.h` | Bind / unbind helper threads |
| `hacks.c` | Platform shims |
| `koush/su.c`, `koush/su.h` | Koush's original implementation, for comparison |
| `packageName` | Build input — the APK package name, passed as `-DREQUESTOR` |
| `Android.mk` | Upstream build file. It names `su/su.c`, which is `phh_su.c` under a different filename. |
| `LICENSE` | GPL-3.0, from upstream |
