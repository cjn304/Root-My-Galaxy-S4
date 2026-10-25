# Root My Galaxy S4

> Runtime root + surgical SELinux policy patching on the Samsung Galaxy S4 (GT-I9500 / Exynos 5410) — no boot image flashing, no KNOX Warranty Bit trip.

在 GT-I9500（Galaxy S4 Exynos Octa，Android 5.0.1，内核 3.4.5）上做纯运行时的 root：
不刷 boot.img、不进 recovery、不写 `selinuxfs`，因此 **KNOX Warranty Bit 不会被翻转**。

整套东西的核心不是"CVE + 提权"那一步（那是公开利用），而是后面两件麻烦事：

1. **这台机器开了 `CONFIG_ALWAYS_ENFORCE`** —— `setenforce 0` 是死的，permissive 必须在内存里手工置位；
2. **提权之后什么都不能干** —— uid 0 但仍在 `shell`/`untrusted_app` 域，写 `/system`、exec root 进程全被 AVC 拒。

所以项目最终形态是：一个内核模块把 SELinux 的 `policydb` 直接在内存里改掉（8 条定向规则），
再配一套带四档授权的 `su`。**permissive_map 最终归零，系统停在 Enforcing。**

---

## 状态

| 项 | 结果 |
|---|---|
| 任意内核读 / 写 | CVE-2015-1805（pipe iovec 越界），读写双方向 |
| 提权 | `prepare_kernel_cred(NULL)` + 直改 `task->cred`，uid/gid/caps 全 0 |
| SELinux 终态 | `Enforcing`，`permissive_map` = 0，无残留 permissive 三元组 |
| 策略改动 | 内存 `te_avtab` 插入 8 条 allow 规则（不落盘、不写 selinuxfs） |
| root 授权 | 四档：全拒 / 仅 ADB / 仅应用 / 全部；应用侧弹窗走 phh Superuser 协议 |
| 系统可写 | `/system` 分区 remount rw → 改 → 回 ro，正常冷启动 |
| KNOX | Warranty Bit 未翻转，`RST_STAT` 正常 |

设备指纹（本项目的验证基线）：

```
model : GT-I9500
device: ja3g
build : LRX22C.I9500ZSSHQD1
kernel: 3.4.5-6264821
sepf  : SEPF_GT-I9500_5.0.1-1_0039
```

---

## 技术链路

```
  ┌─────────────────────────────────────────────────────────────────┐
  │ 1. 任意读                                                       │
  │    CVE-2015-1805：pipe_read 的 iovec 越界（readv 方向）         │
  │    → 读内核任意地址，8 字节对齐，单次上限 2000 B                │
  └─────────────────────────────────────────────────────────────────┘
                              │
  ┌─────────────────────────────────────────────────────────────────┐
  │ 2. 任意写                                                       │
  │    同漏洞 writev 方向。实测：kwrite() 恒返回 0，但只有 8 字节块   │
  │    真正可靠（见下方"写原语"）→ 强制 8 字节块 + 写后读回校验       │
  └─────────────────────────────────────────────────────────────────┘
                              │
  ┌─────────────────────────────────────────────────────────────────┐
  │ 3. 提权                                                         │
  │    find_self() 扫 task 链表 → 改 real_cred/cred 的 uid/gid/caps  │
  │    不走 commit_creds()：避免 security_task_fix_setuid 重算 SID   │
  └─────────────────────────────────────────────────────────────────┘
                              │
  ┌─────────────────────────────────────────────────────────────────┐
  │ 4. 绕过 SELinux（项目的真正难点）                                │
  │    4a. permissive_map 置位（内存 ebitmap，不碰 selinuxfs）       │
  │    4b. avc_ss_reset(0) 清 AVC 缓存（否则旧 deny 粘着不放）        │
  │    4c. 改 policydb 的 te_avtab，插入 8 条定向 allow              │
  │    4d. permissive_map 归零 + 再清一次缓存 → Enforcing            │
  └─────────────────────────────────────────────────────────────────┘
                              │
  ┌─────────────────────────────────────────────────────────────────┐
  │ 5. 授权框架                                                     │
  │    /system/xbin/su（fork 版，phh 协议）                          │
  │    → 守护 socket + 弹窗 + 四档策略 + 白名单                       │
  └─────────────────────────────────────────────────────────────────┘
```

### 写原语：为什么必须是 8 字节

`kwrite()` 走 iovec 越界，**无论成功与否一律返回 0**。同一长度连做 5 次独立测试的落地率：

| 写入长度 | 落地次数 |
|---|---|
| 8 B | 5 / 5 |
| 16 B | 1 / 5 |
| 32 B | 0 / 5 |
| 48 B | 0 / 5 |
| 72 B | 1 / 5 |

所以 `kwrite_buf()` 固定按 8 字节分块，每块写后读回比对，任何一块失败即整笔回滚（`undo` 日志）。
代价是慢（1 MB 约 1 分钟），换来的是"绝不静默半改"。

### 为什么 `setenforce 0` 没用

这台机器的内核开了 `CONFIG_ALWAYS_ENFORCE`，`avc_denied()` 里是：

```c
if (!(avd->flags & AVD_FLAGS_PERMISSIVE))
        return -EACCES;          /* 完全不看 selinux_enforcing */
```

`selinux_enforcing = 0` 和写 `/sys/fs/selinux/enforce` 都不改变这条路径。
唯一有效的是把 `permissive_map`（一个 ebitmap）里的位真正置起来，且位图地址要靠符号解析拿到。

### 为什么 permissive 之后还要 flush

`AVD_FLAGS_PERMISSIVE` 是在**计算**权限时烤进 `avd->flags` 的。
一个三元组一旦被算过并缓存，之后再改 `permissive_map` 不会重算它 —— 已缓存的 deny 继续生效，
已缓存的 allow 继续放行。所以 `enforce` / `flush` 必须调用 `avc_ss_reset(0)`。

这条也解释了为什么"permissive 开着却 mount 不上 /system"这种诡异现象：
`shell -> filesystem { remount }` 的判定在 permissive 之前就被缓存了。

### 为什么改 avtab 而不是落盘策略

写 `/sys/fs/selinux/load` 会触发 TIMA 对内核做完整性度量（`Tl_TIMA_PKM: ret = -1`），
进程直接卡 D 状态。所以策略改动全部在内存里做：

- `policydb + 0x74` = `te_avtab`（htable / nslot / mask / nel）
- key 是 4 个 u16 拼成 64 位：`cls | tgt << 2 | src << 9`
- 哈希 `(cls + (tgt << 2) + (src << 9)) & mask`，节点 16 字节
- **必须有序插入** —— `avtab_search_node()` 有 early-break，乱序插入等于没插

落地的 8 条规则（`untrusted_app 809` / `init_shell 986` / `shell 1178` / `shell_data_file 200` / `su_exec 161` / `system_prop 342`）：

```
init_shell   -> system_prop  : property_service { set }          # 改 persist.sys.root_access
init_shell   -> untrusted_app: fd { use }                        # 把弹窗 socket 交给 app
untrusted_app-> init_shell   : process { sigchld }               # app 等 su 结果
untrusted_app-> shell_data   : sock_file { create write setattr unlink }   # 建弹窗 socket
untrusted_app-> shell_data   : dir { add_name remove_name write search }
shell        -> su_exec      : file { execute execute_no_trans }
init_shell   -> shell        : fd { use }
shell        -> shell_data   : sock_file { create write setattr unlink }
```

权限掩码按 `1 << (权限值 - 1)` 计算，已用独立的 `sepolicy_parse.py` 解析设备策略交叉核对
（`execute(14) -> 0x2000`，`execute_no_trans(18) -> 0x20000` 等）。

---

## 仓库结构

```
.
├── docs/                 55 篇分阶段技术记录（P1 PoC → P4 落地）
│   └── README.md         文档索引，按阶段分组
├── src/
│   ├── ktool.c           主工具，3700+ 行，45+ 命令
│   ├── su_fork.c         fork 版 su（phh 协议）
│   ├── su.c              早期 su（单进程版，留作对照）
│   ├── targets.h         机型/内核 -> 地址表
│   ├── appwrite.c        以 app 身份写 app 私有数据
│   ├── apprm.c           以 app 身份删文件
│   ├── sqlite3.c/h       静态 sqlite（su 的授权库）
│   └── poc/              69 个漏洞验证 / 探测小程序
├── kmod/
│   ├── ktool_mod.c       内核模块：kread/kwrite 后端、avtab 手术、门禁
│   └── Makefile
├── scripts/
│   ├── build.sh          编译 ktool
│   ├── build_su.sh       编译 su
│   ├── deploy_su.sh      部署 su（PC 侧，走 adb）
│   └── init.sec.boot.v9g.sh   开机自举（patch → insmod → 策略 → restore）
├── tools/
│   ├── sepolicy_parse.py 纯 Python policydb v26 解析器
│   ├── sepolicy_query.py 针对性策略查询
│   ├── avtab_query.py    avtab 查询
│   └── avtab_walk.py     avtab 遍历
└── su/                   配套 APK 的源码改动（phh Superuser 派生物，GPL-3.0）
```

### ktool 能干什么

用户态工具，通过 CVE 拿到内核读写后提供 45+ 命令。常用的：

```
target                          打印机型/内核识别结果与地址表，确认地址对不对
root                            提权（改 cred）
pwn [cmd]                       提权 + 全量 permissive，然后 exec
patch / unpatch                 改 exec 分支（让 root 进程能正常 exec）
enforce [--noflush]             关 permissive + 清 AVC 缓存（别名 restore）
flush                           只清 AVC 缓存
dump <addr> <len>               读内存
kread_file <addr> <len> <out> [-r|--resume]   大段读落盘，支持续传
kwrite_file <in> <addr> [-n]    大段写（8 字节块 + 回滚）
undo                            用 undo 日志还原上次写入
scan / scan4                    字节/字符串/4 字节扫描
findcred <start> <len>          按 cred 形状找对象
walk <sym|addr> <off>...        指针追踪
fld <addr> <off:type>...        按字段读结构
dis <addr> [n]                  ARM32 反汇编（保守解码）
setsid <sid|init_shell> <cmd>   改当前进程 SID 后 exec（AVC 死锁时的救援通道）
repl                            交互会话，历史持久化到 /data/local/tmp/.ktool_hist
```

---

## 构建

需要 ARM32 交叉工具链（`arm-none-linux-gnueabihf-`）：

```sh
# 工具链在 PATH 里
./scripts/build.sh

# 或者指定目录
TOOLCHAIN=/opt/arm-gnu-toolchain/bin ./scripts/build.sh
```

内核模块需要一份配置好的 GT-I9500 内核源码树：

```sh
cd kmod
make KDIR=/path/to/kernel_i9500 CROSS_COMPILE=arm-none-linux-gnueabihf-
```

---

## 部署

前提：设备已通过 CVE-2015-1805 拿到一次任意读写（`ktool root` 可用），
`/system` 可通过 `pwn + flush` 后 remount。

```sh
# 1. 编译
./scripts/build.sh

# 2. 推到设备
adb push src/ktool /data/local/tmp/ktool_new
adb shell chmod 755 /data/local/tmp/ktool_new

# 3. 提权 + permissive + remount，替换 /system/bin/ktool
adb shell '/data/local/tmp/ktool pwn /system/bin/sh -c "
    mount -o rw,remount /system &&
    cp /data/local/tmp/ktool_new /system/bin/ktool &&
    chown root:root /system/bin/ktool &&
    chmod 700 /system/bin/ktool &&
    chcon u:object_r:system_file:s0 /system/bin/ktool &&
    mount -o ro,remount /system'"

# 4. 收口（必须做，否则一直 permissive）
adb shell su -c '/system/bin/ktool restore'
```

开机自举脚本 `scripts/init.sec.boot.v9g.sh` 挂到 `/system/etc/init.sec.boot.sh`，
负责每次开机重新 patch、insmod、应用 avtab 规则、恢复 Enforcing。
**注意：这个文件必须是 LF 换行。** 用 Windows 编辑器存成 CRLF 会让 mksh 报
`syntax error: 'do' unexpected`，整脚本一条都不执行，然后连锁表现为"su 全程不可用"。

---

## 已知边界

这些是实测撞过的，不是猜测：

| 现象 | 原因 | 处置 |
|---|---|---|
| `kwrite` 大块写"成功"但内存没变 | iovec 越界落地不稳定 | 只信 8 字节块 + 读回比对 |
| `setenforce 0` 后仍是 Enforcing | `CONFIG_ALWAYS_ENFORCE` | 改 `permissive_map` |
| permissive 开了但 remount 仍被拒 | AVC 缓存粘性 | `flush`（`avc_ss_reset`） |
| 写 `selinuxfs/load` 后进程卡 D 状态 | TIMA 内核完整性度量 | 不写 selinuxfs，只改内存 |
| 改完 sid 读回校验失败 | 写 SID 后域已切换，原语行为变了 | `setsid` 只写不校验，用 `/proc/self/attr/current` 复核 |
| 撤掉 exec patch 后 root 进程 exec 失败 | 特权能力丢失，不全是 EACCES | 保留 patch，或 `ktool patch` 重新打 |

`setsid` 是最后的救援通道：当 AVC 缓存死锁、`mount` 和 `/dev/ktool` 全不可用时，
它直接改当前进程的 `cred->security->sid` 换一个**新 SID**，让判定重新计算。

---

## 文档

`docs/` 里是完整的推导过程，包括大量**失败的尝试**（Binder UAF、GhostLock、dirtycow、
semtimedop、ION、ashmem 等路线都被证伪并记录在案）。按阶段读：

- `P1_*` — 设备摸底与可行性
- `P2_*` — 泄漏通道与 UAF 路线评估（多数被否决）
- `P3_*` — iovec 分配路径静态确认与越界自检
- `P4_*` — 从任意读到 root、模块、SELinux 手术、su、开机自举的完整落地

索引见 [`docs/README.md`](docs/README.md)。

---

## 参考

- CVE-2015-1805：`pipe_read()` / `pipe_write()` 的 iovec 越界（iovyroot 利用思路）
- phh's Superuser（su 协议与 APK 侧对接）
- SELinux 内核实现：`security/selinux/ss/{avtab,policydb,services}.c`、`avc.c`

---

## 免责声明

仅用于**自己持有设备**的安全研究与系统维护。
对设备做任何写入前请先确认有可用的恢复手段；本项目不对任何设备损坏、数据丢失或保修失效负责。
不同 ROM / 内核版本的地址与类型编号不同，`targets.h` 里有校验，识别不到会直接拒绝执行地址类操作。

## License

除 `su/` 目录外，本项目采用 GPL-2.0（内核模块必须与内核兼容）。
`su/` 是 phh's Superuser 的派生物，沿用其 GPL-3.0，作为独立程序分发。
