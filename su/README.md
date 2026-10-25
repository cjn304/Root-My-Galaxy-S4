# 配套 APK 侧改动

这里是从 **phh's Superuser** 派生的部分：`RequestActivity` / `Settings` / `SuHelper` 等
Java 源码，以及授权数据库的适配层（`activity.c` / `db.c` / `phh_su.c`）。

原始版权头均保留在各文件内。

## 许可证

phh's Superuser 采用 **GPL-3.0**。本目录作为其派生物，沿用 GPL-3.0。

根目录的 GPL-2.0 **只覆盖** `src/`、`kmod/`、`scripts/`、`tools/`。
两者是独立程序（通过 socket 协议通信，不是链接关系），因此可以在同一仓库共存。

## 说明

- **APK 本体不分发**。请从 phh 上游获取并用你自己的 key 签名。
- `su` 二进制（`../src/su_fork.c`）与 APK 之间走 phh 的 socket 授权协议：
  su 在 `/data/local/tmp/sud/s<pid>` 建监听，通过 `am start` 拉起授权界面，
  APK 连上 socket 后写 `ALLOW` / `DENY`。
- 本项目对该协议的改动：`SO_PEERCRED` 只认管理 App 的 uid（防止任意应用抢连伪造授权）、
  四档策略（`persist.sys.root_access`）、管理 App 可通过 stdin 改档。

## 目录

| 文件 | 作用 |
|---|---|
| `RequestActivity.java` | 授权弹窗 |
| `MultitaskSuRequestActivity.java` | 多任务场景下的弹窗变体 |
| `Settings.java` | 设置页（四档切换） |
| `SuHelper.java` | 与 su 的协议封装 |
| `SuCheckerReceiver.java` | root 状态检查 |
| `lsu_Shell.java` | `libsuperuser` 的 shell 封装 |
| `phh_su.c` / `db.c` / `activity.c` | 原生侧授权库与数据库 |
| `daemon.c` / `hacks.c` | 常驻逻辑与平台适配 |
| `koush/` | Koush Superuser 的兼容层 |
