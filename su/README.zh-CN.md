# APK 侧源码

[English](README.md) | **中文**

这是 **phh's Superuser** 的部分快照，留作参考：授权弹窗 Activity、设置页，以及 `su` 二进制所使用的
socket 授权协议。

## 这个目录不能构建

`Android.mk` 是上游的构建文件，它引用的源文件并不在这份快照里 —— `utils.c`、`pts.c`、`binds.c`、
`sqlite3/`、`jni/`、`packageName` 都缺。它在这里的作用是展示各部分如何配合，不是拿来跑的。

本项目实际发布的 `su` 二进制是 `../src/su_fork.c`：同一套协议的独立实现，只用这个文件和
`../src/sqlite3.c` 构建。**这个目录里的任何文件都不是构建或运行它所必需的。** 这份快照的作用只是
记录协议和 APK 侧的改动。

## 许可证

**Apache-2.0。** 每个带版权头的文件都是这么写的：

- `activity.c`、`daemon.c` —— Copyright 2010 Adam Shanks、2008 Zinx Verituse
- `db.c` —— Copyright 2013 Koushik Dutta
- `phh_su.c`、`phh_su.h`、`su.h`、`utils.h`、`koush/su.c`、`koush/su.h` —— Copyright 2015
  Pierre-Hugues Husson，以及上述作者
- `MultitaskSuRequestActivity.java`、`RequestActivity.java` —— 同一上游

少数文件在这份快照里没有版权头（`Settings.java`、`SuHelper.java`、`SuCheckerReceiver.java`、
`lsu_Shell.java`，以及 `koush/` 下两个空占位），它们来自同一上游。

Apache-2.0 与 **GPL-2.0 不兼容** —— 它的专利条款在 GPL-2.0 里没有对应物 —— 所以这个目录保持为独立
程序。它通过 socket 与 `su` 通信，不与 `kmod/` 或 `src/` 链接。

## 本项目对协议做的改动

- 在 accept 后的 socket 上做 `SO_PEERCRED` 校验：只认管理 App 的 uid，别的应用无法抢先连上伪造
  `ALLOW`
- 四档策略走 `persist.sys.root_access`，`/data/local/tmp/su_access_mode` 作为优先级更高的覆盖
- ADB 请求在 `adb_only` 与 `apps_and_adb` 两档下不弹窗；应用请求始终走 allowlist 和弹窗

## 文件

| 文件 | 作用 |
|---|---|
| `RequestActivity.java` | 授权弹窗 |
| `MultitaskSuRequestActivity.java` | 多窗口下的弹窗变体 |
| `Settings.java` | 设置页（选档） |
| `SuHelper.java` | 协议封装 |
| `SuCheckerReceiver.java` | root 状态检查 |
| `lsu_Shell.java` | `libsuperuser` 的 shell 封装 |
| `phh_su.c` | `su` 主实现（Apache-2.0） |
| `phh_su.h`、`su.h`、`utils.h` | 共享头文件 |
| `activity.c`、`daemon.c`、`db.c` | 上游的 activity / daemon / 数据库层 |
| `hacks.c` | 平台适配 |
| `koush/su.c`、`koush/su.h` | Koush 的原始实现，供对照 |
| `Android.mk` | 上游构建文件，此处不完整。它引用 `su/su.c`，那个文件就是换了文件名的 `phh_su.c` —— 重复副本已从快照中删除。 |
