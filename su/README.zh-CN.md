# APK 侧源码

[English](README.md) | **中文**

这是 **phh's Superuser** 的 `su` 源码与 APK 侧代码，留作参考：授权弹窗 Activity、设置页，以及 `su` 二进制所使用的
socket 授权协议。

## 这个目录不能直接构建

`Android.mk` 是上游的构建文件。`jni/su/` 下的源文件这里已经齐了 —— `activity.c`、`daemon.c`、
`db.c`、`hacks.c`、`utils.c`、`pts.c`、`binds.c` 以及配套头文件 —— 所以 `su` 本身的源码是完整的。

真正 `ndk-build` 还缺的是第三方依赖：`jni/libselinux`、`jni/libsepol`、`jni/sqlite3`，合计约 12 MB。
这些没有收录。真想编出上游原版 `su` 的话，去 clone 上游仓库；本项目不这么做。

本项目实际发布的 `su` 二进制是 `../src/su_fork.c`：同一套协议的独立实现，只用这个文件和
`../src/sqlite3.c` 构建。**这个目录里的任何文件都不是构建或运行它所必需的。** 这份快照的作用只是
记录协议和 APK 侧的改动。

## 许可证

**GPL-3.0**，与这个目录里的 `LICENSE` 一致（从上游复制）。

多数 `.c` 文件仍带着 Apache-2.0 头，那是项目改许可之前留下的：

- `activity.c`、`daemon.c` —— Copyright 2010 Adam Shanks、2008 Zinx Verituse
- `db.c` —— Copyright 2013 Koushik Dutta
- `phh_su.c`、`phh_su.h`、`su.h`、`utils.h`、`koush/su.c`、`koush/su.h` —— Copyright 2015
  Pierre-Hugues Husson，以及上述作者
- `binds.c`、`pts.c`、`utils.c` —— 同一上游，同样的头

这不矛盾。Apache-2.0 与 GPL-3.0 兼容 —— GPL-3.0 自带覆盖 Apache 专利条款的机制 —— 所以合并后的
作品以 GPL-3.0 分发，上游的 `LICENSE` 就是这么写的。

`kmod/` 是 GPL-2.0，因为它是内核模块，而 GPL-3.0 与内核不兼容。这里没有任何东西链接进它；两边通过
socket 通信。

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
| `phh_su.c` | `su` 主实现 |
| `phh_su.h`、`su.h`、`utils.h` | 共享头文件 |
| `activity.c`、`daemon.c`、`db.c` | 上游的 activity / daemon / 数据库层 |
| `utils.c` | 通用辅助函数 |
| `pts.c`、`pts.h` | shell 用的 PTY 处理 |
| `binds.c`、`binds.h` | bind / unbind 辅助线程 |
| `hacks.c` | 平台适配 |
| `koush/su.c`、`koush/su.h` | Koush 的原始实现，供对照 |
| `packageName` | 构建输入 —— APK 包名，通过 `-DREQUESTOR` 传入 |
| `Android.mk` | 上游构建文件。它引用 `su/su.c`，那个文件就是换了文件名的 `phh_su.c`。 |
| `LICENSE` | GPL-3.0，来自上游 |
