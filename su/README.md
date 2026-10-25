# APK-side changes

Everything in this directory is derived from **phh's Superuser**: the `RequestActivity` /
`Settings` / `SuHelper` Java sources, plus the authorization database layer
(`activity.c`, `db.c`, `phh_su.c`).

Original copyright headers are kept in each file.

## License

phh's Superuser is **GPL-3.0**. This directory is a derivative and stays GPL-3.0.

The GPL-2.0 at the repository root covers `src/`, `kmod/`, `scripts/` and `tools/` only.
The two are separate programs — they communicate over a socket protocol rather than by
linking — so both licenses can coexist in one repository.

## Notes

- **The APK is not distributed here.** Either build it from these sources and sign it with
  your own key, or install the published build:
  https://fxedel.gitlab.io/fdroid-website/en/packages/me.phh.superuser/
- The su binary (`../src/su_fork.c`) speaks phh's socket protocol: it listens on
  `/data/local/tmp/sud/s<pid>`, launches the prompt via `am start`, and the app replies
  `ALLOW` / `DENY` over that socket.
- What this project changed in that protocol: `SO_PEERCRED` accepts only the managing app's
  uid (so no other app can connect first and forge an `ALLOW`), four-tier policy through
  `persist.sys.root_access`, and the managing app can switch tiers over stdin.

## Files

| File | Purpose |
|---|---|
| `RequestActivity.java` | Permission prompt |
| `MultitaskSuRequestActivity.java` | Prompt variant for multi-window |
| `Settings.java` | Settings screen (four tiers) |
| `SuHelper.java` | Protocol wrapper around su |
| `SuCheckerReceiver.java` | Root status check |
| `lsu_Shell.java` | `libsuperuser` shell wrapper |
| `phh_su.c` / `db.c` / `activity.c` | Native authorization library and database |
| `daemon.c` / `hacks.c` | Daemon logic and platform shims |
| `su.c` / `su.h` / `phh_su.h` / `utils.h` | Reference su implementation and shared headers |
| `Android.mk` | Build file |
| `koush/` | Koush Superuser compatibility layer |
