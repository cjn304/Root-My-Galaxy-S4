#!/system/bin/sh
#
# 这份文件是**追加**到设备 /system/etc/init.sec.boot.sh 末尾的标记块，
# 不是完整脚本，运行 install.sh 也不会覆盖原文件。
#
# 从 shebang 到下面的 begin 标记之间是 GT-I9500 原版 init.sec.boot.sh
# 的内容，只作对照：说明块插在哪、它之前是什么。这几行在不同固件之间
# 不一样，所以 install.sh 只截取两个标记之间的内容追加到设备现有文件
# 之后，不覆盖原文件。
#
# 注意：这段注释里不能出现标记行的原文 —— install.sh 是用那两行原文做
# sed 匹配的，注释里写一遍会让提取范围从注释就开始。
#
# 块内容：机型表校验 → 标签断言 → exec 补丁 → 门禁 → permissive 收口。
#
# 标记块本身是 GPL-3.0-or-later（同仓库根 LICENSE）；上面那几行原版内容
# 是三星的代码，不适用。

echo "init.sec.boot.sh: start" > /dev/kmsg

# start deferred initcalls
cat /proc/deferred_initcalls

## strace for system_server
#str=""
#while [ "$str" = "" ]; do
#  str=`ps | grep system_server`
#  sleep 0.1
#done
#
#pid=${str:10:4}
#echo "init.sec.boot.sh: strace -tt -T -o /data/log/strace.txt -p ${pid}" > /dev/kmsg
#strace -tt -T -o /data/log/strace.txt -p ${pid}

# ---- 2a auto begin ----
{
  echo "=== 2a start ==="
  date
  echo "id: $(id)"
  echo "attr: $(cat /proc/self/attr/current)"

  # 1) lkmauth_bootmode = 2（BSS，每次开机归零）
  #    这个地址和 src/targets.h 里的 lkmauth_bootmode 是同一个值，换机型
  #    两边都要改。ktool w32 是原始写，不走 target 表，写错地址等于在内核
  #    BSS 里随机位置写 —— 所以移植时先改 targets.h，再同步改这一行。
  /system/bin/ktool w32 c0c0ae28 2
  echo "bootmode_rc=$?"

  # 2) permissive 只标 init_shell 一个 type（highbit=1536，节点链完整）
  #    本脚本本身就在 init_shell 域，且 init_shell 有 CAP_SYS_MODULE 和
  #    system_file:file {execute,execute_no_trans}，所以下一步不需要 kernel 域
  /system/bin/ktool permissive
  echo "permissive_rc=$?"

  # 3) su 的 socket 目录（P4.90）
  #    su 的 app 域子进程要在 /data/local/tmp/sud 里 bind socket；
  #    目录一旦缺失，bind 直接 ENOENT，父进程报 "su: socket not ready"，
  #    am start 根本不会执行 —— 表现就是"授权弹窗不出来"。
  #    此处 init_shell 已是 permissive，可以建。0777 是为了让 app uid 能写。
  mkdir -p /data/local/tmp/sud && chmod 777 /data/local/tmp/sud
  sud_rc=$?
  echo "sud_rc=$sud_rc"
  if [ "$sud_rc" != "0" ]; then
    # 失败会让 su 的 bind ENOENT -> "socket not ready" -> 弹窗永不出现。
    # /data/local/tmp 是 shell:shell 0771，root 是 other；要靠 init_shell 的
    # dac_override + 本步的 permissive 才建得动。建不动就把原因留痕。
    echo "KT_SUD_FAIL rc=$sud_rc $(ls -ldZ /data/local/tmp 2>&1)" > /dev/kmsg
  fi

  # 2b) exec patch：su 提权后 uid 变 0，KNOX 的 sys_execve 检查块会对
  #     uid 0 的进程做 sec_check_execpath 检查；没有 patch 时
  #     su 里 execl("/system/bin/sh") 会 EACCES。
  /system/bin/ktool patch
  echo "patch_rc=$?"

  # 2c) 机型/build 适配（P4.29）：主键是「机型 + 内核 version 串」。
  #     表在 src/targets.h，用户态和模块共用同一张；对不上就拒绝地址类操作。
  KT_DEV="$(getprop ro.product.device)"
  read _ _ KT_KVER _ < /proc/version
  KT_TARGET="${KT_DEV}:${KT_KVER}"
  echo "ktool_target=${KT_TARGET}"

  # 3) init_shell 直接 insmod。/system/bin/insmod 不在 /data/ 下，
  #    KNOX 的 sec_check_execpath 不拦，所以也不需要 exec patch。
  n=0
  for d in 0 2 4; do
    if [ "$d" != "0" ]; then sleep "$d"; fi
    echo "--- insmod attempt $n (delay ${d}s) ---"
    /system/bin/insmod /system/lib/modules/ktool_mod.ko ktool_enforce=1 ktool_target="$KT_TARGET"
    echo "insmod_rc=$?"
    if [ -c /dev/ktool ]; then
      echo "dev_ktool=ok"; break
    fi
    echo "dev_ktool=missing"
    n=$((n+1))
  done

  # 3a) 标签断言（P4.33）
  #     模块 init 是把 /dev/ktool 的 i_security 指针指向 /dev/null 的；
  #     策略重载后这个 blob 会失效，实测出现过 /dev/ktool 被标成
  #     u:r:platform_app:s0 —— 那时 ctx/ish 写不进去，su 静默失效到重启。
  #     模块已在 open() 里自愈，这里只做断言，出问题留痕。
  if ls -Z /dev/ktool 2>/dev/null | grep -q null_device; then
    echo "ktool label ok"
  else
    echo "KT_LABEL_BAD: $(ls -Z /dev/ktool 2>&1)" > /dev/kmsg
    echo "ktool label BAD"
  fi

  # 3b) permissive 收口（P4.28）
  #     insmod 需要 CAP_SYS_MODULE，这一步借的正是 init_shell 的 permissive
  #     bit。模块进内存之后，permissive 就没有存在必要了 —— 立刻清零并
  #     清 AVC 缓存，让"关掉"立即对所有三元组生效（不用重启）。
  #     实测 permissive 全关状态下：su 弹窗路径 0 拒绝、appwrite 正常、
  #     ktool 门禁正常、root exec 不受影响（exec patch 保留）。
  if [ -c /dev/ktool ]; then
    /system/bin/ktool enforce
    enforce_rc=$?
    echo "enforce_rc=$enforce_rc"
    if [ "$enforce_rc" != "0" ]; then
      # 4 = avcflush 不可用：permissive_map 已清但缓存未清，
      # 看起来是 Enforcing，实际旧的三元组仍按 permissive 放行。
      echo "KT_ENFORCE_FAIL rc=$enforce_rc" > /dev/kmsg
    fi
  else
    # 模块没起来就别假装收口成功：permissive 还开着。
    echo "KT_NO_MODULE: insmod failed, permissive left ON" > /dev/kmsg
  fi

  # 3b-2) avtab 规则是否真的应用（模块 init 里打的）
  echo "avrule_applied=$(dmesg | grep -c 'avrule: su rules applied')"
  echo "root_access=$(getprop persist.sys.root_access)"

  # 4) ktool 的 DAC 锁由模块 init 做（ktool_apply_ktool_mode，内存兜底）。
  #    落盘值由部署时一次真实 chmod 设好（/system 只读，boot 脚本改不了）：
  #    untrusted_app -> system_file:file 有 execute，ktool 只要是 755，
  #    任何 app 都能 exec 这个自带 exploit 的二进制，门禁完全绕过。
  #    调试用 /data/local/tmp/ktool 副本（750 shell:shell，app 既过不了
  #    SELinux 的 untrusted_app->shell_data_file 无 execute，也过不了 DAC）；
  #    重启后本模块自动改回 700。
  echo "ktool mode: $(ls -l /system/bin/ktool)"

  echo "--- final ---"
  ls -l /dev/ktool 2>&1
  cat /proc/modules 2>&1

  echo "--- su self test ---"
  /system/xbin/su -c 'id; cat /proc/self/attr/current' 2>&1

  echo "=== 2a end ==="
} > /data/system/2a.log 2>&1
# ---- 2a auto end ----
