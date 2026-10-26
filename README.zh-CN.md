# Root My Galaxy S4

[English](README.md) | **中文**

在三星 Galaxy S4（GT-I9500 / Exynos 5410）上做纯运行时的 root，并对 SELinux 策略做定点手术。
不刷 boot.img、不进 recovery、不写 `selinuxfs` —— 所以 **KNOX Warranty Bit 不会被翻转**。

装了开机脚本之后，root 可以在重启后保持。KNOX 相关应用能正常使用。Smart Manager 偶尔会弹
"检测到未经授权的动作"，那是它的完整性检查发现了 `/system` 的改动，不是 e-fuse，纯属提示。

---

## 怎么用

### 1. 前提

- 三星 Galaxy S4 **GT-I9500**，系统 `LRX22C.I9500ZSSHQD1` / 内核 `3.4.5-6264821`
  （其它版本见 [移植](#移植到其它机型)）
- 电脑上有 `adb`，设备用 USB 连上

### 2. 安装

```sh
./scripts/install.sh
```

这一条会装上两半：`ktool`（exploit 加工具箱）和 `su`（应用实际打交道的授权前端）。缺什么编什么
—— 如果 `src/` 里已经有预编译好的二进制，就不需要交叉工具链 —— 然后按顺序跑两步部署。两步都是
幂等的，重复跑没问题。

只要命令行 root、不需要应用弹窗？单跑 `./scripts/deploy_ktool.sh` 就够。

应用侧的 root 弹窗由 **phh's Superuser** 处理，授权前先装上它：

https://fxedel.gitlab.io/fdroid-website/en/packages/me.phh.superuser/

源码：https://github.com/phhusson/Superuser

本项目发布的 `su` 二进制（`src/su_fork.c`）是同一套 socket 协议的独立实现。

> **四档。** `0` 全拒，`1` 只放应用，`2` 只放 ADB，`3` 应用 + ADB。`adb shell su` 在 2 和 3 两档
> 下不弹窗直接放行；应用请求始终要走 allowlist 和 phh 弹窗。本机实测：`0` 和 `1` 拒绝 uid 2000，
> `2` 和 `3` 返回 `uid=0`。
>
> 改档：用 Superuser 设置页，或者写 `/data/local/tmp/su_access_mode`，内容为
> `access_disabled` / `apps_only` / `adb_only` / `apps_and_adb` —— 这个文件的优先级高于属性。
> 从 `adb shell` 执行 `setprop persist.sys.root_access N` 会报告成功但被静默丢弃：`shell` 域对
> `system_prop` 没有写权限。

### 3. 验证

```sh
adb shell '/data/local/tmp/ktool_new target'    # 必须显示 "verified: yes"
adb shell 'getenforce'                          # Enforcing
adb shell 'su -c id'                            # uid=0（需要 2 或 3 档）
```

第一条故意用 `/data/local/tmp` 里的副本：`/system/bin/ktool` 是 `0700 root:root`，`shell` 域执行
不了它。装好 `su` 之后，也可以改用 `adb shell 'su -c "/system/bin/ktool target"'`。

开机保持是可选的：`/data/local/tmp/ktool_new boot /system/lib/modules/ktool_mod.ko`，然后把
`scripts/init.sec.boot.v9g.sh` 装成 `/system/etc/init.sec.boot.sh`。这个文件必须是 **LF** ——
CRLF 会让 mksh 连一行都执行不到就退出。

---

## 现状

| 项目 | 结果 |
|---|---|
| 任意内核读写 | CVE-2015-1805（pipe iovec 越界），读写双向 |
| 提权 | 原地覆写当前 `cred` 的 uid/gid/caps；`cred->security` 不动，所以 SID 不变 |
| SELinux 终态 | `Enforcing`，`permissive_map` = 0，无残留 permissive 三元组 |
| 策略改动 | 8 条 allow 规则插入内存中的 `te_avtab`；不落盘 |
| root 策略 | `persist.sys.root_access`：`0` 全拒、`1` 只放应用、`2` 只放 ADB、`3` 应用 + ADB。2 和 3 两档下 ADB 直接放行不弹窗；应用请求始终走 allowlist 和 phh 弹窗 |
| `/system` 写入 | remount rw → 改 → 回 ro，冷启动验证通过 |
| KNOX | Warranty Bit 完好，`RST_STAT` 正常 |

基线设备：

```
model : GT-I9500
device: ja3g
build : LRX22C.I9500ZSSHQD1
kernel: 3.4.5-6264821
sepf  : SEPF_GT-I9500_5.0.1-1_0039
```

---

## 工作原理

```
1. 任意读            CVE-2015-1805 的 pipe_read iovec 越界。8 字节对齐，单次 2000 B。
2. 任意写            同一个洞的 writev 方向。kwrite() 永远返回 0，所以每次写完
                     都要读回比对；只有 8 字节块可信。
3. 提权              遍历 task 链表 -> task->real_cred/cred -> 原地覆写 uid/gid/caps。
                     cred->security 不动，所以 SELinux 的 SID 不变。
4. SELinux           a) 置 permissive_map（内存里的 ebitmap，绝不碰 selinuxfs）
                     b) avc_ss_reset(0) —— 否则已缓存的拒绝继续生效
                     c) 往 policydb->te_avtab 插 8 条 allow 规则
                     d) 清空 permissive_map 再 flush 一次 -> Enforcing
5. 授权              /system/xbin/su（fork 版，phh 协议）+ Superuser APK
```

**`kwrite` 会谎报长度。** 无论结果如何，每次调用都返回 0。5 次独立测试的落地率：8 B → 5/5，
16 B → 1/5，32 B → 0/5，48 B → 0/5，72 B → 1/5。所以固定按 8 字节分块、写后读回校验，并保留
undo 日志。它很慢 —— 搬 1 MB 是分钟级 —— 这也是 `kread_file` 存在的原因：大块读取走它，写保持小。

### 8 条 avtab 规则

本策略里的 type 编号：`untrusted_app 809`、`init_shell 986`、`shell 1178`、`shell_data_file 200`、
`su_exec 161`、`system_prop 342`。

```
init_shell    -> system_prop  : property_service { set }                    # 写 persist.sys.root_access
init_shell    -> untrusted_app: fd { use }                                  # 把弹窗 socket 交给应用
untrusted_app -> init_shell   : process { sigchld }                         # 应用等 su 结果
untrusted_app -> shell_data   : sock_file { create write setattr unlink }   # 建弹窗 socket
untrusted_app -> shell_data   : dir { add_name remove_name write search }
shell         -> su_exec      : file { execute execute_no_trans }
init_shell    -> shell        : fd { use }
shell         -> shell_data   : sock_file { create write setattr unlink }
```

插规则的细节很关键：`policydb + 0x74` 是 `te_avtab`（htable / nslot / mask / nel），key 是四个
`u16` 拼成的 64 位（`cls | tgt << 2 | src << 9`），节点 16 字节，而且**必须有序插入** ——
`avtab_search_node()` 在有序链表上会提前跳出，乱序插进去等于没插。

---

## 构建

```sh
./scripts/build.sh                              # ktool
TOOLCHAIN=/opt/arm/bin ./scripts/build_su.sh    # su（静态，内置 sqlite3）
```

内核模块：

```sh
cd kmod
make KDIR=/path/to/kernel_i9500 CROSS_COMPILE=arm-none-linux-gnueabihf-
```

`KDIR` 必须指向一份已配置好的 GT-I9500 内核树（含 `.config` 和 `Module.symvers`）。

---

## 漏洞路线调查

以下每一条都针对这个确切的内核（`3.4.5-6264821`）核对过。表格刻意保留两列：漏洞是否还在代码里，
以及 `shell` uid 的进程是否真能碰到它。一共查了 19 条，能用的一条。

| CVE | 子系统 | 漏洞是否存在 | 可达性 | 依据 |
|---|---|---|---|---|
| **CVE-2015-1805** | pipe iovec 越界 | **存在** | **本项目在用** | `pipe_iov_copy_from_user` 仍是 4 参数形态（修复版多一个 `atomic_t *`）。任意读写在真机上验证通过。 |
| CVE-2026-43499 | GhostLock，futex PI | 存在 | 受阻（缺读原语） | 链的 A/B/C 三阶段在本机跑通过，但前提是用 CVE-2015-1805 的读能力构造出自洽的伪造节点 —— 自洽之后两道 `CONFIG_DEBUG_LIST` 检查才过得去。没有读原语就造不出自洽节点，链无法起步；而一旦有了读原语，GhostLock 又没有增量。 |
| CVE-2016-3134 | netfilter，`xt_compat_match_from_user` | 存在 | 受阻（CAP_NET_ADMIN） | `memcpy(m->data, cm->data, msize - sizeof(*cm))` 之前没有 `msize` 下限检查。但整条 iptables 路径需要 `CAP_NET_ADMIN`。 |
| CVE-2016-9793 | socket，`SO_SNDBUFFORCE` | 存在 | 受阻（CAP_NET_ADMIN） | `sk_sndbuf` 没有上限检查。实测：`SO_SNDBUF` 会被 `min_t` 夹住，而 `SO_SNDBUFFORCE` 即使 uid 0 且 `CapEff=ffffffff` 也返回 EPERM。 |
| CVE-2016-5195 | dirtycow，`follow_page` | 已修 | — | 三条件检查齐全（`FOLL_FORCE` \| `FOLL_COW` 对 pte dirty）。金丝雀跑了约 57 万次写没反应。 |
| CVE-2016-0728 | keyring | 已修 | — | `join_session_keyring` 末尾有 `key_put(keyring)`。 |
| CVE-2016-4470 | keyring | 已修 | — | `__key_link_end` 只在 `link_ret == 0` 时执行。 |
| CVE-2016-8655 | AF_PACKET | 已修 | — | `packet_set_ring()` 里有 `if (unlikely(rb->pg_vec))` 守卫。 |
| CVE-2015-3636 | ping socket UAF | 已修 | — | 设备实测。 |
| CVE-2019-2215 | binder UAF | 已修 | — | `binder_free_thread` 会把 `t->from` 和 `t->to_thread` 清零。 |
| CVE-2016-5340 | ashmem | 不存在 | — | 3.4 没有 `is_ashmem_file()`；`ashmem_pin_unpin` 的四道检查齐全。 |
| CVE-2016-3951 | USB usbnet | 不存在 | — | `CONFIG_USB_USBNET` 未启用。 |
| CVE-2017-11176 | `mq_notify` | 不存在 | — | `CONFIG_POSIX_MQUEUE` 未启用。 |
| CVE-2017-6074 | DCCP | 不存在 | — | `CONFIG_IP_DCCP` 未启用。 |
| CVE-2019-2181 | binder | 不存在 | — | 这个内核树里没有引入。 |
| CVE-2020-0041 | binder | 不存在 | — | 这个内核树里没有引入。 |
| CVE-2020-0009 | ashmem 保护位 | 设计如此 | — | 在本内核上是预期行为，不是漏洞。 |
| CVE-2016-6728 | ION，msm custom ioctl | 不存在 | — | 打的是高通 msm ION 的 custom/secure 路径。S4 用的是三星自己的 `drivers/gpu/ion/ion.c`，`ION_IOC_CUSTOM` 是空的 —— 实测命令 0..8 全部返回 ENOTTY。 |
| CVE-2017-0564 | ION，msm | 不存在 | — | 同上：这套实现里根本没有那些入口点。 |

关于最后两条要补一句：ABSENT 只是**本机**的结论。S5 的固件里带的是高通 msm ION
（`msm_ion_custom_ioctl`、`ion_cp_change_mem_v2`、`ion_secure_*`），所以这两条在 S5 上必须按 msm
代码重新审计，不能从 S4 的结论继承。

四条"受阻"判决里有两条撞的是同一堵墙，值得点名：`CAP_NET_ADMIN` 并没有授予 `shell` 域，所以
`capable()` 在 SELinux 层就失败了，跟 `CapEff` 写着什么无关。CVE-2016-3134 和 CVE-2016-9793 都
死在这里。只看补丁状态的话，这两条都会被标成"可利用"，然后接下来两周就走了条起不了步的链。

另有两条泄漏路线被否掉，都是看着有戏、一测就废。系统化的 infoleak 扫描（254 个探针，覆盖所有
`shell` 可达面）零命中，拿不到任何可用的栈地址。`WARN`-`%p` 通道确实会打印真实内核栈地址，而且
这个 build 上 `dmesg` 从 `shell` 就能读 —— 但触发路径会在 `pi_lock` 临界区里 BUG，线程带着真锁
死掉，约 27 秒后 softlockup，整机 panic。不是没有泄漏，是这个泄漏自杀。

### GhostLock 可用性

决定这条链能不能用的，不是一次再平衡会碰几个节点，而是内核在解引用之前**会不会校验**这个节点。

在 3.4 上，`CONFIG_DEBUG_LIST=y` 加上 `CONFIG_SEC_DEBUG_LIST_PANIC` 让 `list_debug` 成为非零
全局变量，于是 `if (list_debug) BUG_ON(...)` 永远走 BUG 分支。落到实际发布的二进制里，
`__list_del_entry`（`0xc025cd68`）里的四道一致性检查被编译成了**无条件**的 `udf #0x12`。
没有周旋余地：伪造节点要么满足所有检查，要么 panic。

`lib/rbtree.c`（这棵树里 401 行）**完全没有任何运行时校验** —— 没有 `DEBUG_RBTREE`、没有
`__rb_erase_valid`、`rb_insert_color` 里也没有。它只管解引用然后往下走，所以伪造的 `rb_node`
不需要自洽。而且 `rb_insert_color` 在再平衡时会顺带把栈地址泄漏出来，这就是同一个洞在新内核上
好做得多的原因。

| 内核 | `waiter` 形态 | 节点是否校验 | 需要外部读原语 | 单 GhostLock |
|---|---|---|---|---|
| 3.4 / 3.10（S4、S5、S6） | `plist_node` | 有 —— `udf` | **需要**，而且必须是*栈*地址 | **不行** |
| 3.14 及以后（S7 起，4.4 / 4.9 / …） | `rb_node` | 无 | 不需要 | 有希望 |

S5 的固件从另一面印证了这点：同样是 `CONFIG_DEBUG_LIST=y`，但用的是 `panic()` 而不是 `udf`
—— 效果一样，指令不同。S6 用的是同样的 plist 结构。S7 及以后的公开链存在，但本仓库没有验证过。

这让 S4 处在一个尴尬位置：唯一能交出栈地址的就是 CVE-2015-1805 本身，而一旦有了任意读写，
GhostLock 就没有增量。这也是本项目根本不用这条链的原因，也是"单 GhostLock"在**任何** plist
内核上都不成立、而不只是这一台的原因。

ION 也救不了。它的 infoleak 给的是**内核堆**地址（S4 实测 `handle = 0xd8aed780`），而伪造的
`node_list` 必须指向**栈**上的 `waiter + 0x0C`。堆不是栈。它的 SHARE/FREE 竞态最多只赢到一个
引用计数 —— 是泄漏，不是内存破坏 —— 所以也拿不到读原语。如果另有某个 ION 漏洞能提供真正的读写，
S4 这一行就得改；这次审计没找到。另外 S5 用的是高通 msm ION 而不是三星这套，攻击面更大，需要单独
审计。

---

## 移植到其它机型

只需要改**一个文件**：`src/targets.h`。内核模块 include 的是同一个头文件，所以两边不可能对不上。

### 可能的候选

下面这些行是**没有实测过的推测，不是已验证的目标** —— 没人在这几台上跑通过整条链。依据是结构上
的相似：同一代 KNOX、同一套 `lkmauth` 机制、同样的 SELinux `policydb` 布局。这让**方法**可以迁移，
但没有任何一个地址可以直接复用。

| 设备 | SoC | 内核线 | 评估 |
|---|---|---|---|
| SM-N900（Note 3） | Exynos 5420 | 3.4.x | 最接近：与 S4 同分支、同 KNOX 代际 |
| GT-I9505（S4 LTE） | Snapdragon 600 | 3.4.x | 同分支但 SoC 不同 —— 整个内核侧等于重新移植 |
| GT-I9300（S3） | Exynos 4412 | 3.0.x | 分支更老：`task_struct` 布局不同，`[B]` 不能照抄 |
| GT-N7100（Note 2） | Exynos 4412 | 3.0.x | 情况同 S3 |

怎么读：

- **Note 3** 是第一个值得试的。同一代内核，`[B]` 偏移有真正的复用机会，`lkmauth_bootmode` 也在
  同名符号下存在。
- **I9505** 的用户态部分完全不用改，但内核是另一棵树（msm）。`[A]` 地址全都要重新找；exec 补丁点
  要独立验证，不能假设分支距离相近。
- **S3 / Note 2** 跑的是 3.0.x。`task_struct` 和 `cred` 的布局不一样，`[B]` 必须重新推导而不是
  照抄。4.3 之后就有 `lkmauth`，但策略构建更老，`perm_bit` 一定对不上。

在任何一台上都**不会**迁移的：`init_task`、`permissive_map`、`avc_slots`、`exec_br`、
`lkmauth_bootmode`、`perm_bit`。同一分支的内核之间**通常**能迁移的：`[B]` 偏移。

### 必须成立的前提

- ARM32 内核，`task_struct`/`cred` 布局接近 3.4.x
- CVE-2015-1805（或另一个原语）能给出任意读写
- 存在三星的 `lkmauth` 启动模式变量（`boot` 命令要用它）

### 步骤 1 —— 身份（匹配主键）

```sh
adb shell getprop ro.product.device     # -> device
adb shell cat /proc/version             # -> "3.4.5-XXXXXXX" -> kernel
```

匹配要求 device 和内核版本**都**相等。只按 device 匹配是危险的：同一台手机换了内核，地址全变，
而表会照样往错的地方写。匹配不上时，所有涉及地址的命令都会拒绝执行。

### 步骤 2 —— `[B]` 偏移（跟配置走，通常可复用）

```
off_task_tasks off_task_real_cred off_task_cred off_task_comm
off_cred_uid off_cred_caps off_cred_security
```

这些跟内核配置（`CONFIG_KEYS`、`CONFIG_SECURITY`、`CONFIG_DEBUG_*`）走，不跟镜像构建走。从带调试
信息的 `vmlinux` 里取：

```sh
pahole -C task_struct vmlinux | grep -E "tasks|real_cred|cred|comm"
pahole -C cred vmlinux | grep -E "uid|caps|security"
```

拿到读写能力之后在设备上做一次合理性检查：`fld <init_task> 0x1d0:p 0x2f8:p 0x304:s` 应该打印出
一个指向 task 链表的指针、`real_cred` 解析到 `init_cred`（旁边跟着符号标注就是好兆头），以及
字符串 `swapper/0`。本机实测：

```
+0x1d0 p  0xe68481d0
+0x2f8 p  0xc0b9f1dc  Dinit_cred+0x0
+0x304 s  "swapper/0"
```

### 步骤 3 —— `[A]` 地址（每个镜像都要重新推导）

| 字段 | 怎么取 |
|---|---|
| `init_task` | 那个确切内核的 `System.map` / `kallsyms` |
| `modprobe_path` | 符号；`.data` 里 256 字节可写区，借来当假 ebitmap 节点的暂存区 |
| `permissive_map` | `policydb.permissive_map` 的地址；从符号表定位 `policydb`，再加上对应策略版本的结构偏移 |
| `avc_slots` | `avc_cache.slots[512]`，仅调试用 |
| `exec_br` | `sys_execve` 里跳过三星 KNOX 检查的那条 `beq` |
| `exec_br_orig` / `exec_br_patch` | 原始分支指令和被替换成的 `b`（本 build 是 `0x0a000002` → `0xea000047`） |
| `lkmauth_bootmode` | `.bss` 变量，每次启动归零 |

`exec_br` 要找的话，反汇编 `sys_execve`，找那条跳过凭据检查的条件分支；`exec_br_patch` 里的分支
偏移必须按实际指令距离算，不能照抄。

### 步骤 4 —— `perm_bit`

这是 `init_shell` 的 **type value**，不是它的 SID，而且每个策略构建都会变：

```sh
adb pull /sepolicy
python3 tools/sepolicy_parse.py sepolicy .
# 读类型表；init_shell 的下标就是 perm_bit
```

`tools/sepolicy_query.py` 可以交叉核对单条规则和类型编号。

### 步骤 5 —— 信任之前先验证

1. `ktool target` —— 地址看着合理，新条目的 `verified = 0`
2. `ktool backend probe` —— 必须打印 `probe(init_task=...): OK`
3. `ktool dump <init_task> 64` —— 应该能解出像样的 `task_struct`
4. `ktool sym init_task` —— 必须与表里一致
5. 只有在真机上把整条链（root → mount → 模块 → restore → Enforcing）走通之后，才把
   `verified` 改成 1，并把测过什么写进 `note`

任何一条对不上，**就不要往下走** —— 在内核 `.data` 里猜地址，是把手机变砖的标准姿势。

### 步骤 6 —— 模块侧参数

模块还需要 8 条 avtab 规则用的 SELinux type 编号。这些是运行时模块参数，不需要重新编译：

```sh
insmod ktool_mod.ko av_app_type=809 av_initshell_type=986 av_shelldata_type=200 \
                    av_suexec_type=161 av_shell_type=1178 av_sysprop_type=342
```

开机脚本会传入从 `targets.h` 推导出的值；换策略时要相应调整。

---

## ktool 命令参考

全局：`ktool [-t <秒>] <命令> ...` —— `-t/--timeout` 限制读写重试的总时长。

### 目标 / 后端

| 命令 | 说明 |
|---|---|
| `target` | 打印匹配到的型号/build/内核、全部地址与偏移，以及 `verified` 标志 |
| `backend` | 显示后端名称和读写上限 |
| `backend probe` | 真实竞态读一次 `init_task`；判断"读写还活着吗"的权威方式 |
| `sym <name\|name*wild\|0xADDR> [-a] [-f mapfile] [-n max]` | 符号查询（`-a` = 全部匹配，`-f` = 自定义 System.map） |

### 读

| 命令 | 说明 |
|---|---|
| `dump <addr> <len>` | 读并 hexdump，上限 4096 B |
| `read <addr> <len>` | 读并把裸二进制输出到 stdout，上限 16 MB |
| `kread_file <addr> <len> <out> [-r\|--resume]` | 分块读落盘；`-r` 从已有文件长度续传 |
| `bench [addr] [n]` | 读吞吐：ms/次 和平均重试次数 |
| `selftest <addr>` | 对同一地址连读 4 次并打印头几个字 —— 看读是否稳定 |

### 写

| 命令 | 说明 |
|---|---|
| `kwrite_file <in> <addr> [-n]` | 分块写，写后读回校验；`-n` 不写 undo 日志 |
| `w32 <addr> <value>` | 单次 32 位写（保留高 4 字节） |
| `undo` | 回放 undo 日志，撤销上一次 `kwrite_file` |
| `wtest [len] [off]` | 写原语诊断：试写一个长度并报告是否真的落地 |

### 搜索 / 结构

| 命令 | 说明 |
|---|---|
| `scan <start> <len> <pattern\|s:text> [max]` | 字节或字符串扫描 |
| `scan4 <start> <len> <value\|lo-hi> [max] [-u]` | 32 位扫描，`-u` = 非对齐 |
| `findcred <start> <len> [-u uid] [max]` | 按 `struct cred` 的形状找对象 |
| `find <comm>` | 遍历 task 链表并匹配 `comm` |
| `walk <sym\|addr> <off>... [-d n]` | 沿指针链追踪，并 dump 终点 |
| `fld <addr> <off:type>...` | 按字段读结构；类型 `p u h b s x` |
| `dis <addr> [n]` | ARM32 反汇编，保守解码（不认识就输出 `.word`） |

### 权限

| 命令 | 说明 |
|---|---|
| `root <cmd>` | 提权后 `exec`（别名 `x`、`rawexec`）—— 会结束会话 |
| `promote` | 提权但留在会话里；同时保留一份 cred 快照 |
| `unroot` | 用 `promote` 留下的快照还原 cred（先校验 task/comm） |
| `pwn [cmd]` | 提权 + 全量 permissive，然后 `exec` |
| `sh` | 打 exec 补丁 + 切到 `init_shell`，然后交给 shell |
| `boot <ko>` | 提权、置 `lkmauth_bootmode=2`、全量 permissive、打 exec 补丁，然后 `exec insmod <ko>` —— 一次 exploit 跑完五步。exec 补丁是必需的：`c0012164` 处的 KNOX 分支会拦 kernel 域的 `exec`，不打的话 `insmod` 直接 EACCES |
| `who` | 当前 uid/euid/gid/caps |
| `caps` | 把当前 cred 的所有 capability 组填满 |
| `showcred` | dump 链表里每个 task 的凭据 |

### SELinux

| 命令 | 说明 |
|---|---|
| `permissive [bit]` | 置 `permissive_map` 的单个位（默认 `init_shell`） |
| `enforce [--noflush]` | 清 `permissive_map` + 还原 `modprobe_path` + flush AVC（别名 `unperm`、`restore`）。它只撤销内存里的 permissive 窗口 —— 不会卸载任何东西。`--noflush` 并**没有**真正恢复强制 |
| `flush [-y]` | 只清 AVC 缓存；`-y` 跳过 3 秒警告 |
| `patch` / `unpatch` | 打上 / 撤销 KNOX 的 `sys_execve` 分支补丁 |
| `setsid <sid\|init_shell> <cmd...>` | 改写当前 `cred->security->sid` 然后 exec。AVC 缓存死锁时的救援通道 |

### 文件 / shell

| 命令 | 说明 |
|---|---|
| `cat <path>` | 提权 + permissive 后读文件 |
| `cp <src> <dst>` | 提权 + permissive 后复制 |
| `ls <path>` | 提权 + permissive 后列目录 |

### 会话

| 命令 | 说明 |
|---|---|
| `repl` | 交互会话（别名 `shell`、`-i`）。历史持久化到 `/data/local/tmp/.ktool_hist` |
| `help` / `?` | 会话内显示命令列表 |
| `history` / `!N` | 会话内查看 / 回放历史 |
| `exit` / `quit` / `q` | 退出会话 |

在 REPL 会话里，exploit 的准备成本只付一次，`promote` 升的权限对后续命令持续有效。

---

## 已知边界

| 现象 | 原因 | 处理 |
|---|---|---|
| 大块 `kwrite` 报成功但内存没变 | iovec 越界落地不稳定 | 只用 8 字节块 + 读回校验 |
| `setenforce 0` 之后仍是 Enforcing | `CONFIG_ALWAYS_ENFORCE` | 改 `permissive_map` |
| permissive 开着但 `remount` 被拒 | AVC 缓存粘性 | `flush`（`avc_ss_reset`） |
| 碰过 `selinuxfs/load` 之后进程卡在 D 状态 | TIMA 完整性度量 | 永远不要写 selinuxfs |
| `sid` 写入报失败 | 写完之后域已经变了，读回不可信 | `setsid` 只写一次不校验；用 `/proc/self/attr/current` 确认 |
| `unpatch` 之后 root 进程 exec 不了 | 特权能力没了，不只是 EACCES | 保留补丁，或者重新 `ktool patch` |
| 改过开机脚本之后 `su` 完全不工作 | CRLF 换行，脚本在执行任何一行之前就退出 | 转成 LF，在设备上用 `sh -n` 校验 |

`setsid` 是最后的救援手段：当 AVC 缓存死锁、`mount` 和 `/dev/ktool` 都不能用的时候，它把
`cred->security->sid` 改写成一个**新** SID，让判定从头重算。

---

## 致谢

- CVE-2015-1805 —— `pipe_read()` / `pipe_write()` 的 iovec 越界（iovyroot 的利用思路）
- **KNOXout**（Lev Aronsky，Viral Security Group）—— 三星 TIMA 与 RKP 究竟拦什么。
  「永远不写 `selinuxfs`」这条规则就来自这里，之后才在设备上得到确认
- phh's Superuser —— su 协议与 APK 侧

本仓库的代码和文字有相当一部分是在 AI 协助下完成的。但每一个地址、偏移、权限掩码和 `verified`
声明都在真机上核对过：实验、失败分析和"保留什么"的判断是人做的。

---

## 免责声明

仅用于**自己持有设备**上的安全研究与系统维护。
动手写任何东西之前，先确认你有可用的恢复手段。不提供任何形式的担保；作者不对变砖、数据丢失或
保修失效负责。
地址和 type 编号随 ROM 与内核而变 —— 匹配失败时 `targets.h` 会拒绝执行，这个检查存在是有原因的。

---

## 许可证

两部分：

- **`src/`、`scripts/`、`tools/` 是 GPL-3.0-or-later** —— 根目录的 `LICENSE`。它们是普通用户态
  程序，通过系统调用与内核交互；没有任何东西把它们链接进内核代码，所以这里的许可是一种选择，
  而不是约束。
- **`kmod/` 必须是 GPL-2.0** —— `kmod/LICENSE`。它是 Linux 内核模块：调用内核内部函数、遍历内核
  私有结构（`policydb`、`task_struct`），并被加载进一个 GPL-2.0-only 的内核。它还声明了
  `MODULE_LICENSE("GPL")`，这是它能解析 `EXPORT_SYMBOL_GPL` 符号的前提。这里不能用 GPL-3.0 ——
  它与内核的许可不兼容。文件头写的是 `SPDX-License-Identifier: GPL-2.0`。

这里每个源文件都以一行 `SPDX-License-Identifier` 开头，所以每个文件的条款都是明确的。
