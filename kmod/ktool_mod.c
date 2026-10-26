// SPDX-License-Identifier: GPL-2.0

/*
 * ktool_mod.c — minimal LKM interface for ktool
 *
 *   echo "root <pid>" > /dev/ktool   给指定进程提权（kernel 域）
 *   echo "root"       > /dev/ktool   给写接口的当前进程提权（kernel 域）
 *   echo "ish"        > /dev/ktool   当前进程 -> uid 0 + u:r:init_shell:s0
 *   echo "avrestore"   > /dev/ktool   撤回插入的 8 条 avtab 规则
 *   cat /dev/ktool                   查看当前进程的 uid / SID
 *
 * /dev/ktool 在 init 时被重标为 null_device，shell 域在 enforcing 下也能写。
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/cred.h>

/* 与用户态共用同一张机型/build 适配表（P4.29） */
#include "../src/targets.h"
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/file.h>
#include <linux/kallsyms.h>
#include <linux/signal.h>
#include <linux/delay.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <asm/barrier.h>

#define KTOOL_SU_PATH "/system/xbin/su"
#define KTOOL_BIN_PATH "/system/bin/ktool"
#define KTOOL_DEV_PATH "/dev/ktool"

/*
 * /dev/ktool 门禁（P4.25 重做，P4.24 五连崩后的正确版）
 *
 * 要堵的后门：/dev/ktool 是 0666 + `allow domain null_device:chr_file write`，
 * 任何 app 都能 `echo ish > /dev/ktool` 直接拿 uid0 + init_shell，
 * 完全绕过 su 的授权弹窗。
 *
 * P4.24 失败的根因（P4.25 探针实测钉死）：
 *   本模块编译期 task_struct.cred = 0x2EC，设备实际 0x2FC，整体错位 16 字节；
 *   task.mm 同样错位。所以 current_cred()/current->mm->exe_file 全是野指针，
 *   v3~v8 五个版本全崩在这上面。而 struct cred 布局是对的（security=0x58）。
 *
 * 新设计三条原则：
 *   1. 只用内核 API 取指针，不用任何编译期结构体偏移——
 *      get_task_mm() 已导出，get_mm_exe_file() 未导出但走 kallsyms。
 *   2. 比字符串不比 dentry（P4.24 实测 dentry 比较对 su 失效），
 *      且必须 /system/ 前缀：app 无法写 /system，/data 下的冒充进不来。
 *   3. 域门砍掉：管理命令（w32/permissive/patch/boot/root/...）
 *      由 /system/bin/ktool 用户态自己做（自带 do_root exploit），
 *      不经过 /dev/ktool。过 /dev/ktool 的只有 su 发的 ish/ctx，
 *      所以这里只需要路径一道门。
 *
 * enforce=0（默认）：只打印放行，用于第一次部署验证字符串；
 * enforce=1：真正拦截。boot 脚本验证通过后传 enforce=1。
 */
static int ktool_enforce = 0;
module_param(ktool_enforce, int, 0644);
MODULE_PARM_DESC(ktool_enforce, "1=deny non-su callers, 0=log only");

static char ktool_su_path[64] = KTOOL_SU_PATH;
module_param_string(su_path, ktool_su_path, sizeof(ktool_su_path), 0644);

/*
 * ktool_target="<device>:<kernel version>"，开机脚本从
 * ro.product.device + /proc/version 拼出来传进来。
 * 不传时：表里只有一个目标就退回它，多个目标就拒绝地址类操作。
 */
static char *ktool_target;
module_param(ktool_target, charp, 0444);
MODULE_PARM_DESC(su_path, "only this exe may use ish/ctx via /dev/ktool");

/* get_mm_exe_file 在本树未 EXPORT_SYMBOL，init 时解析一次 */
static struct file *(*ktool_get_mm_exe_file)(struct mm_struct *mm);

static inline int ktool_is_kaddr(u32 p)
{
	return p >= 0xbf000000u;
}

/*
 * 当前进程是否已经是 uid 0。
 *
 * P4.49 修正：必须用实测偏移，不能用内核内联 current_uid()。
 *
 * 设备内核的 task_struct 与源码树差 16 字节：源码树编译出来 cred 在
 * task+0x2EC，设备实际在 task+0x2FC。双重实证：
 *   - P4.25 探针钉死 task+0x2FC = cred
 *   - dump init_task：+0x2F8=real_cred、+0x2FC=cred（都指向 init_cred
 *     0xc0b9f1dc）、+0x304=comm "swapper/0"、+0x30=sched_class
 *     =0xc0701f4c(idle_sched_class)
 * current_uid() 按编译期偏移去读 +0x2EC，拿到的是 cpu_timers[1].prev，
 * 于是恒定返回垃圾（实测 -816291736 / -428549080 等随机值），把真正的
 * uid0 进程也一并拒掉 —— 这就是 sem_canary 连续 8 次 EACCES 的根因。
 *
 * struct cred 布局两边一致：cred+4 = uid（system_server uid 1000 实测
 * cred+4 = 0x3e8 ✓），所以只需把偏移从 +0x2EC 改成 +0x2FC。
 * 再加 usage/地址合理性检查，避免万一读到垃圾也误判。
 */
static int ktool_is_uid0(void)
{
	u32 c = *(u32 *)((char *)current + 0x2FC);	/* task->cred（实测） */

	if (!ktool_is_kaddr(c))
		return 0;
	return *(u32 *)((char *)c + 4) == 0;		/* cred+4 = uid */
}

static void ktool_set_panic_on_oops(void)
{
	unsigned long (*lookup)(const char *);
	unsigned long a;

	lookup = (void *)kallsyms_lookup_name;
	a = lookup("panic_on_oops");
	if (!a)
		return;
	*(volatile u32 *)a = 0;
	wmb();
	printk(KERN_INFO "ktool: panic_on_oops -> 0 (dev aid, resets on boot)\n");
}

/*
 * 返回 1 = 放行。总是打印实际看到的 exe 路径（先观察后 Enforcement）。
 */
static int ktool_gate_ok(void)
{
	struct mm_struct *mm;
	struct file *exe;
	char *buf, *p;
	int ok = 0, n, su_n;

	if (!ktool_get_mm_exe_file) {
		printk(KERN_WARNING "ktool: gate: get_mm_exe_file unresolved\n");
		return 0;
	}

	mm = get_task_mm(current);
	if (!mm)
		return 0;

	exe = ktool_get_mm_exe_file(mm);
	if (exe) {
		buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (buf) {
			p = d_path(&exe->f_path, buf, PATH_MAX);
			if (!IS_ERR(p)) {
				n = strlen(p);
				su_n = strlen(ktool_su_path);
				ok = (n == su_n && !strcmp(p, ktool_su_path));
				printk(KERN_WARNING
				       "ktool: gate exe=%s -> %s%s\n",
				       p, ok ? "ALLOW" : "DENY",
				       ktool_enforce ? "" : " (log-only)");
			} else {
				printk(KERN_WARNING "ktool: gate d_path err %ld\n",
				       PTR_ERR(p));
			}
			kfree(buf);
		}
		fput(exe);
	}
	mmput(mm);
	return ok;
}

static int ktool_allow(const char *kbuf)
{
	/* 只有这三个命令需要过 /dev/ktool，其余（root/w32/...）走 ktool 用户态 */
	int priv = !strncmp(kbuf, "ish", 3) || !strncmp(kbuf, "ctx ", 4) ||
		   !strncmp(kbuf, "avrule", 6) || !strncmp(kbuf, "avset", 5) ||
		   !strncmp(kbuf, "avcflush", 8) || !strncmp(kbuf, "avrestore", 9) ||
		   !strncmp(kbuf, "warntest", 8) ||
		   !strncmp(kbuf, "bugtest", 7) || !strncmp(kbuf, "waiter ", 7) ||
		   !strncmp(kbuf, "fixlbl", 6) || !strncmp(kbuf, "lbldbg", 6) ||
		   !strncmp(kbuf, "kread ", 6) || !strncmp(kbuf, "ksym ", 5) ||
		   !strncmp(kbuf, "wdump ", 6) || !strncmp(kbuf, "wfind ", 6) ||
		   !strncmp(kbuf, "wfind16 ", 8);
	int ok;

	if (!priv)
		return 0;

	/*
	 * ctx / avcflush 额外放行「已经是 uid0」的进程（P4.27）：
	 * appwrite 由 su/root 拉起（uid0）后要 ctx 到 untrusted_app 写 app 数据；
	 * avcflush 要 uid0 才能清 AVC。app 永远到不了 uid0，
	 * 所以这条不放宽攻击面。
	 */
	if ((!strncmp(kbuf, "ctx ", 4) || !strncmp(kbuf, "avrule", 6) ||
	     !strncmp(kbuf, "avset", 5) ||
	     !strncmp(kbuf, "avcflush", 8) ||
	     !strncmp(kbuf, "warntest", 8) || !strncmp(kbuf, "bugtest", 7) ||
	     !strncmp(kbuf, "waiter ", 7) || !strncmp(kbuf, "fixlbl", 6) ||
	     !strncmp(kbuf, "lbldbg", 6) || !strncmp(kbuf, "kread ", 6) ||
	     !strncmp(kbuf, "ksym ", 5) ||
	     !strncmp(kbuf, "wdump ", 6) || !strncmp(kbuf, "wfind ", 6) ||
	     !strncmp(kbuf, "wfind16 ", 8)) &&
	    ktool_is_uid0()) {
		printk(KERN_WARNING "ktool: gate '%.8s' uid0-> ALLOW (cur_uid=%d)\n", kbuf, current_uid());
		return 1;
	}
	ok = ktool_gate_ok();	/* 总是执行并打印 */
	if (!ktool_enforce)
		return 1;		/* 观察模式：只记录不拦截 */
	return ok;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ktool");
MODULE_DESCRIPTION("ktool minimal kernel interface");

/* 地址/偏移全部来自 targets.h；tgt 在 init 里按 ktool_target 选定 */
static const struct ktool_target *tgt;

/* permissive_map / modprobe_path / exec_br 由用户态 ktool 直接读写，模块不再引用 */
#define TASK_REAL_CRED	(tgt->off_task_real_cred)
#define TASK_CRED	(tgt->off_task_cred)
#define TASK_COMM	(tgt->off_task_comm)


/*
 * warntest — 发一条我们自己的 WARN，带一个栈地址
 *
 * 目的：隔离验证「本内核的 WARN 正文会不会落进 dmesg/log」。
 * 这决定 GhostLock 那条 %p 泄漏通道是否成立：
 *   - 正文能落盘 → list_del 的 %p 泄漏是真的
 *   - 只有 "cut here" 没有正文 → 泄漏通道不存在（Samsung 日志机制吞了）
 */
static int ktool_bugtest(void)
{
	unsigned int marker = 0xdeadbeef;

	/* 先把本线程的内核栈地址打出来，再 BUG —— 用来模拟
	 * "泄漏之后线程被 oops 打死" 的真实时序 */
	printk(KERN_WARNING "ktool bugtest: stack=%p marker=%08x\n",
	       (void *)&marker, marker);
	BUG();
	return 0;
}

static int ktool_warntest(void)
{
	unsigned int marker = 0xfeedface;
	void *stackaddr = &marker;

	WARN(1, "ktool warntest: stack=%p marker=%08x\n", stackaddr, marker);
	return 0;
}


/*
 * waiter <pid> — 量 rt_mutex_waiter 的真实位置（P4.35）
 *
 * 为什么不用 kprobe：这台内核 CONFIG_KPROBES=n，register_kprobe 是空壳。
 * 做法：pid_task() 拿 task（不走 task_struct 偏移），然后把 task_struct 前
 * 0x600 字节按 u32 扫一遍：
 *   - 8KB 对齐且在 0xc0000000..0xf0000000 的值 → 候选 task->stack
 *   - 落在 [stack, stack+0x2000) 的值 → 候选 pi_blocked_on（waiter 就在自己栈上）
 * 只读已映射内存，不 deref 任何候选指针，安全。
 */
static int ktool_waiter(int pid)
{
	struct task_struct *t;
	char comm[17];
	u32 stack, pbo, state, prio;
	unsigned long base;

	rcu_read_lock();
	t = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (!t) {
		rcu_read_unlock();
		return -ESRCH;
	}

	/*
	 * 只读已知字段，不再扫 0x600 字节 —— P4.35 那次扫描越过了
	 * task_struct 对象边界，跨到未映射页直接 fault 重启。
	 *   +0x04  task->stack
	 *   +0x18  task->prio / +0x14 state 附近（仅打印参考）
	 *   +0x304 task->comm
	 *   +0x3ac task->pi_blocked_on（P4.35 实测值）
	 */
	stack = *(u32 *)((char *)t + 0x04);
	pbo   = *(u32 *)((char *)t + 0x3ac);
	state = *(u32 *)((char *)t + 0x14);
	prio  = *(u32 *)((char *)t + 0x18);
	memcpy(comm, (char *)t + 0x304, 16);
	comm[16] = 0;
	base = (unsigned long)stack & ~0x1fffUL;

	printk(KERN_INFO "ktool: waiter pid=%d task=%p comm=%s state=%08x prio=%d\n",
	       pid, t, comm, state, (int)prio);
	printk(KERN_INFO "ktool:   task->stack=%08x base=%08lx\n",
	       stack, base);
	if (pbo)
		printk(KERN_INFO
		       "ktool:   pi_blocked_on=%08x off_from_base=%03lx (waiter)\n",
		       pbo, (unsigned long)pbo - base);
	else
		printk(KERN_INFO "ktool:   pi_blocked_on=NULL\n");

	rcu_read_unlock();
	return 0;
}


/*
 * kread <hexaddr> <len> — 模块内直接读内核内存并打到 dmesg
 *
 * 为什么不让用户态用 ktool dump：dump 走的是 CVE-2015-1805 的竞态，
 * 经常抢不到窗口、偶尔还会把机器带崩；模块本来就在内核里，直接读。
 * 用 probe_kernel_read（kallsyms 解析）避免踩到未映射页时 oops。
 */
static long (*ktool_probe_kread)(void *dst, const void *src, unsigned long n);

static int ktool_kread(unsigned long addr, int len)
{
	u32 v;
	int i, n = 0;

	if (!ktool_probe_kread)
		ktool_probe_kread = (void *)kallsyms_lookup_name("probe_kernel_read");
	printk(KERN_INFO "ktool: kread %08lx len=%d (probe=%s)\n", addr, len,
	       ktool_probe_kread ? "yes" : "no");
	for (i = 0; i + 4 <= len; i += 4) {
		int rc;

		if (ktool_probe_kread)
			rc = ktool_probe_kread(&v, (void *)(addr + i), 4);
		else {
			v = *(u32 *)(addr + i);
			rc = 0;
		}
		if (rc) {
			printk(KERN_INFO "ktool:   %08lx: <fault %d>\n",
			       addr + i, rc);
			break;
		}
		printk(KERN_INFO "ktool:   %08lx: %08x\n", addr + i, v);
		n++;
	}
	return n ? 0 : -EFAULT;
}


/*
 * wdump <pid> — 把该线程内核栈的高半页（base+0x1A00 .. base+0x2000）打出来
 *
 * 直接给"喷栈落点"定位用：waiter 在 base+0x1DF8，msgctl 的 0x3C 字节
 * 缓冲区按模型应落在 base+0x1E28 附近；全打出来就能看到实际偏移，
 * 不用在 shell 里做十六进制运算。
 */
static int ktool_wfind(int pid, u32 pat);

static int ktool_wdump(int pid)
{
	struct task_struct *t;
	u32 stack, v;
	unsigned int off;
	int bad = 0;

	rcu_read_lock();
	t = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (!t) {
		rcu_read_unlock();
		return -ESRCH;
	}
	stack = *(u32 *)((char *)t + 0x04);
	rcu_read_unlock();

	if (!ktool_probe_kread)
		ktool_probe_kread = (void *)kallsyms_lookup_name("probe_kernel_read");
	if (!ktool_probe_kread)
		return -ENOSYS;

	printk(KERN_INFO "ktool: wdump pid=%d stack=%08x\n", pid, stack);
	for (off = 0x1A00; off < 0x2000; off += 4) {
		if (ktool_probe_kread(&v, (void *)(stack + off), 4)) {
			printk(KERN_INFO "ktool:   w%03x <fault>\n", off);
			if (++bad > 4)
				break;
			continue;
		}
		printk(KERN_INFO "ktool:   w%03x %08x\n", off, v);
	}
	/* 顺带全页搜喷栈图案 buf[0]=0xcafe0000 */
	ktool_wfind(pid, 0xcafe0000u);
	return 0;
}


/*
 * wfind <pid> <hexval> — 在整页内核栈（8KB）里搜一个 u32 图案，打印命中偏移
 *
 * 用来定位 msgctl 的栈拷贝落点：喷栈图案 buf[i]=0xcafe0000+4i，
 * 搜 0xcafe0000 的命中偏移就是 buf[0] 的落点。
 */
static int ktool_wfind(int pid, u32 pat)
{
	struct task_struct *t;
	u32 stack, v;
	unsigned int off;
	int hits = 0;

	rcu_read_lock();
	t = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (!t) {
		rcu_read_unlock();
		return -ESRCH;
	}
	stack = *(u32 *)((char *)t + 0x04);
	rcu_read_unlock();

	if (!ktool_probe_kread)
		ktool_probe_kread = (void *)kallsyms_lookup_name("probe_kernel_read");
	if (!ktool_probe_kread)
		return -ENOSYS;

	printk(KERN_INFO "ktool: wfind pid=%d stack=%08x pat=%08x\n",
	       pid, stack, pat);
	for (off = 0; off < 0x4000; off += 4) {
		if (ktool_probe_kread(&v, (void *)(stack + off), 4))
			continue;
		if (v == pat) {
			int k;
			u32 w;

			hits++;
			printk(KERN_INFO "ktool:   HIT off=%03x abs=%08x\n",
			       off, stack + off);
			/* 顺便把命中点后 0x40 字节打出来，便于核对顺序 */
			for (k = 0; k < 0x40; k += 4) {
				if (!ktool_probe_kread(&w, (void *)(stack + off + k), 4))
					printk(KERN_INFO "ktool:     +%02x %08x\n",
					       k, w);
			}
			if (hits >= 4)
				break;
		}
	}
	printk(KERN_INFO "ktool: wfind done hits=%d\n", hits);
	return 0;
}


/* wfind16 <pid> <hex16> — 按 2 字节粒度扫，用于 6 字节结构体（sembuf）等非 4 对齐图案 */
static int ktool_wfind16(int pid, u16 pat)
{
	struct task_struct *t;
	u32 stack;
	unsigned int off;
	int hits = 0;

	rcu_read_lock();
	t = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (!t) {
		rcu_read_unlock();
		return -ESRCH;
	}
	stack = *(u32 *)((char *)t + 0x04);
	rcu_read_unlock();

	if (!ktool_probe_kread)
		ktool_probe_kread = (void *)kallsyms_lookup_name("probe_kernel_read");
	if (!ktool_probe_kread)
		return -ENOSYS;

	printk(KERN_INFO "ktool: wfind16 pid=%d stack=%08x pat=%04x\n", pid, stack, pat);
	for (off = 0; off < 0x4000; off += 2) {
		u16 v;

		if (ktool_probe_kread(&v, (void *)(stack + off), 2))
			continue;
		if (v == pat) {
			hits++;
			printk(KERN_INFO "ktool:   HIT16 off=%03x abs=%08x\n",
			       off, stack + off);
			if (hits >= 6)
				break;
		}
	}
	printk(KERN_INFO "ktool: wfind16 done hits=%d\n", hits);
	return 0;
}


/* ksym <symbol> — 用 kallsyms_lookup_name 取符号地址并打印（P4.48）
 * /proc/kallsyms 对 shell/root 都打码，但模块在内核里查表不受影响。 */
static int ktool_ksym(const char *name)
{
	unsigned long a;

	if (!name || !name[0])
		return -EINVAL;
	a = kallsyms_lookup_name(name);
	printk(KERN_INFO "ktool: ksym %s = %lx\n", name, a);
	return a ? 0 : -ENOENT;
}

/* ------------------------------------------------------------------
 * P4.92: te_avtab 手术 —— 直接往内存里的策略表插入 allow 规则
 *
 * 为什么不用 load_policy：本机 security_load_policy 被 Samsung 挂钩，
 * 写 /sys/fs/selinux/load 会触发 TIMA 对内核做完整性度量；我们改过 .text，
 * 度量必然失败，trustlet 返回 -1，write 永不返回（P4.89 实测卡 D 状态）。
 * 所以 supolicy / magiskpolicy 那条路是死的，只能改内存中的表。
 *
 * 为什么安全：判定路径只读这张表；插入是"先把节点填满，smp_wmb 之后再用
 * 一次 store 发布指针"，读者要么看到旧链、要么看到完整新节点；本机策略
 * 不会重载，不存在并发删除。链表必须按 (src,tgt,cls) 升序，否则
 * avtab_search_node 的 early-break 会让新节点永远查不到。
 *
 * 结构布局（security/selinux/ss/avtab.h，32 位 ARM）：
 *   key   = u16 src, u16 tgt, u16 cls, u16 specified   (8B)
 *   datum = u32                                       (4B)
 *   node  = key + datum + next                        (16B)
 *   avtab = htable(4) nel(4) nslot(4) mask(2+pad2)     (16B)
 *
 * te_avtab 在 policydb+0x74。该偏移用三条独立事实核对过：
 *   ① te_avtab.nel == 16072，等于 sepolicy_parse.py 解出的规则总数；
 *   ② nslot == 2048 且 mask == 0x7ff（2 的幂 - 1）；
 *   ③ 按内核哈希 (cls + (tgt<<2) + (src<<9)) & mask 定位 (986,188,7)
 *      得到 allowed=0x00100020（search|setattr），与解析器算出的完全一致。
 * 运行时还会再自检一遍，任何一条不满足就拒绝动手。
 * ------------------------------------------------------------------ */
#define P4K_TE_AVTAB_OFF	0x74
#define P4K_AVTAB_ALLOWED	0x0001

struct p4k_avtab_key {
	u16 source_type;
	u16 target_type;
	u16 target_class;
	u16 specified;
};

struct p4k_avtab_datum {
	u32 data;
};

struct p4k_avtab_node {
	struct p4k_avtab_key key;
	struct p4k_avtab_datum datum;
	struct p4k_avtab_node *next;
};

struct p4k_avtab {
	struct p4k_avtab_node **htable;
	u32 nel;
	u32 nslot;
	u16 mask;
};

static int ktool_avrule(int src, int tgt, int cls, u32 mask);

/* 取 te_avtab；自检不过就返回 NULL（宁可不改，也不能写错地方） */
static struct p4k_avtab *p4k_te_avtab(void)
{
	unsigned long pd = kallsyms_lookup_name("policydb");
	struct p4k_avtab *av;

	if (!pd)
		return NULL;
	av = (struct p4k_avtab *)(pd + P4K_TE_AVTAB_OFF);
	if (!av->htable || !ktool_is_kaddr((u32)(unsigned long)av->htable))
		return NULL;
	if (!av->nslot || (av->nslot & (av->nslot - 1)))
		return NULL;			/* nslot 必须是 2 的幂 */
	if (av->mask != (u16)(av->nslot - 1))
		return NULL;
	if (av->nel < 1000 || av->nel > 300000)
		return NULL;
	return av;
}

static int p4k_hash(struct p4k_avtab *av, int src, int tgt, int cls)
{
	return (cls + (tgt << 2) + (src << 9)) & av->mask;
}

/* avruleq <src> <tgt> <cls>：只查不改，用于验证布局 */
static int ktool_avruleq(int src, int tgt, int cls)
{
	struct p4k_avtab *av = p4k_te_avtab();
	struct p4k_avtab_node *cur;
	int hv, n = 0;

	if (!av) {
		printk(KERN_INFO "ktool: avtab selfcheck FAILED\n");
		return -EIO;
	}
	hv = p4k_hash(av, src, tgt, cls);
	printk(KERN_INFO "ktool: avtab nel=%u nslot=%u mask=%#x htable=%p slot=%d\n",
	       av->nel, av->nslot, av->mask, av->htable, hv);
	for (cur = av->htable[hv]; cur; cur = cur->next) {
		if (cur->key.source_type == src &&
		    cur->key.target_type == tgt &&
		    cur->key.target_class == cls) {
			printk(KERN_INFO "ktool: avruleq %d->%d:%d spec=%#x allowed=%#x at %d\n",
			       src, tgt, cls, cur->key.specified,
			       cur->datum.data, n);
			return 0;
		}
		if (++n > 200)
			break;
	}
	printk(KERN_INFO "ktool: avruleq %d->%d:%d NOT FOUND (chain %d)\n",
	       src, tgt, cls, n);
	return -ENOENT;
}

/*
 * 开机自动应用 su 需要的四条规则（幂等：已有节点就 OR）。
 *
 * 数值来自 sepolicy_parse.py（policyvers=26）：untrusted_app=809、
 * init_shell=986、shell_data_file=200；class fd=8、process=2、dir=7、sock_file=12。
 * 换 ROM 后 type 值可能整体平移，所以这里先用 policydb 的形状做闸门：
 * types/classes 数量对不上就只告警、不自动加规则（仍可用 avrule 手工加）。
 */
static int p4k_avrule_enable = 1;
module_param_named(avrule_enable, p4k_avrule_enable, int, 0444);
MODULE_PARM_DESC(avrule_enable, "1=apply su avtab rules at init (default), 0=skip");

static int p4k_src_app = 809;
module_param_named(av_app_type, p4k_src_app, int, 0444);
static int p4k_tgt_initshell = 986;
module_param_named(av_initshell_type, p4k_tgt_initshell, int, 0444);
static int p4k_tgt_shelldata = 200;
module_param_named(av_shelldata_type, p4k_tgt_shelldata, int, 0444);
/*
 * 以下三个原来写死在规则里。换 ROM 时 type value 会整体平移，
 * 而 types/classes 数量校验只能挡住"数量变了"，挡不住"数量没变但编号变了"，
 * 所以全部做成可覆盖参数，出问题时不用重编。
 */
static int p4k_su_exec_type = 161;
module_param_named(av_suexec_type, p4k_su_exec_type, int, 0444);
static int p4k_shell_type = 1178;
module_param_named(av_shell_type, p4k_shell_type, int, 0444);
static int p4k_system_prop_type = 342;
module_param_named(av_sysprop_type, p4k_system_prop_type, int, 0444);

/*
 * untrusted_app -> shell_data_file:dir 这条原策略就有，插入时是 OR 上去的，
 * 所以回收只能覆盖回原值。0x00500013 = getattr|ioctl|open|read|search，
 * 从本机 sepolicy 解出来的；换 ROM 用 tools/avtab_query.py 重算。
 */
static int p4k_dir_orig_mask = 0x00500013;
module_param_named(av_dir_orig_mask, p4k_dir_orig_mask, int, 0444);

#define P4K_NPRIM_TYPES		1343
#define P4K_NPRIM_CLASSES	86

static void p4k_apply_su_rules(void)
{
	unsigned long pd = kallsyms_lookup_name("policydb");
	u32 nt, nc;

	if (!p4k_avrule_enable) {
		printk(KERN_INFO "ktool: avrule disabled by avrule_enable=0\n");
		return;
	}
	if (!pd) {
		printk(KERN_WARNING "ktool: avrule: policydb not found\n");
		return;
	}
	nt = *(u32 *)((char *)pd + 0x20);	/* symtab[SYM_TYPES].nprim  */
	nc = *(u32 *)((char *)pd + 0x10);	/* symtab[SYM_CLASSES].nprim */
	if (nt != P4K_NPRIM_TYPES || nc != P4K_NPRIM_CLASSES) {
		printk(KERN_WARNING
		       "ktool: avrule skipped: policy shape changed (types=%u/%u classes=%u/%u)\n",
		       nt, P4K_NPRIM_TYPES, nc, P4K_NPRIM_CLASSES);
		return;
	}
	if (!p4k_te_avtab()) {
		printk(KERN_WARNING "ktool: avrule skipped: te_avtab selfcheck failed\n");
		return;
	}

	/*
	 * init_shell -> system_prop:property_service { set }
	 *
	 * 为什么需要：phh 的「超级用户访问权限」四档存在系统属性
	 * persist.sys.root_access 里（Settings.getSuperuserAccess 读它）。
	 * App 改档位的做法是 exec("su") 再把 "setprop persist.sys.root_access N"
	 * 写进 su 的 stdin；su 已切到 init_shell，所以真正执行 setprop 的是
	 * init_shell —— 而被 deny 的恰恰是这一步。
	 *
	 * 注意不能只给 shell 域：property_service（init 进程）里有**用户态 AVC**，
	 * shell 域那条 set 早在某次真实拒绝时就被缓存成 denied，之后即使加规则、
	 * 甚至全量 permissive 也不会重算；init_shell 是全新条目，规则一加就生效。
	 * 实测：shell 域 setprop 始终 rc=0 但值不变；init_shell 域 setprop 立刻生效。
	 *
	 * system_prop=342、property_service=84、set=bit1=0x1（来自 sepolicy_parse）。
	 */
	if (ktool_avrule(p4k_tgt_initshell, p4k_system_prop_type, 84, 0x1))
		printk(KERN_WARNING "ktool: avrule prop-set FAILED\n");

	/* init_shell -> untrusted_app:fd use（父进程用 fork 前创建的管道） */
	ktool_avrule(p4k_tgt_initshell, p4k_src_app, 8, 0x1);
	/* untrusted_app -> init_shell:process sigchld（子进程退出通知父进程） */
	ktool_avrule(p4k_src_app, p4k_tgt_initshell, 2, 0x4);
	/* untrusted_app -> shell_data_file:sock_file：
	 *   create(bit4=0x8) | write(bit3=0x4) | setattr(bit6=0x20) | unlink(bit11=0x400)
	 *   = 0x42c
	 *   - create：bind() 建 socket 节点
	 *   - setattr：chmod(sock, 0777)（漏了它 socket 停在 0600，APK 连不上，弹窗一闪就退）
	 *   - unlink：bind 前清理上一次的残留节点
	 *   - write：**APK 的 connect() 要它**。实测 audit：syscall=283(connect)
	 *     tclass=sock_file perms={write} —— 不是 unix_stream_socket，别删。
	 * 不需要 read / getattr；原值 0x43e 已收窄到 0x42c。 */
	ktool_avrule(p4k_src_app, p4k_tgt_shelldata, 12, 0x42c);
	/* untrusted_app -> shell_data_file:dir（add_name/remove_name/write/search） */
	ktool_avrule(p4k_src_app, p4k_tgt_shelldata, 7, 0x160004);

	/*
	 * ADB 侧（caller = AID_SHELL = 2000，域 shell）。
	 * 这三条让 adb shell 也能用 su；不想要 ADB root 就把 avrule_enable 之外的
	 * 这三条删掉——它们只服务于「仅限于 ADB / 应用程序和 ADB」两档。
	 *   shell -> su_exec:file {execute,execute_no_trans} = 0x22000
	 *       （实测最小集：open 不需要；漏 execute 就是 EACCES，
	 *         dontaudit 掩盖了审计，只能靠二分试出来）
	 *   init_shell -> shell:fd use = 0x1
	 *       （父进程 ish 之后要用 fork 前的管道，否则 socket not ready）
	 *   shell -> shell_data_file:sock_file {create,write,setattr,unlink} = 0x42c
	 *       （子进程在 sud 里 bind socket）
	 */
	if (p4k_tgt_initshell) {
		if (ktool_avrule(p4k_shell_type, p4k_su_exec_type, 6, 0x22000) ||
		    ktool_avrule(p4k_tgt_initshell, p4k_shell_type, 8, 0x1) ||
		    ktool_avrule(p4k_shell_type, p4k_tgt_shelldata, 12, 0x42c))
			printk(KERN_WARNING "ktool: avrule adb-path FAILED\n");
	}

	printk(KERN_INFO "ktool: avrule: su rules applied (app=%d ish=%d shd=%d)\n",
	       p4k_src_app, p4k_tgt_initshell, p4k_tgt_shelldata);
}

/* avrule <src> <tgt> <cls> <mask>：OR 进已有节点，没有就按序插入新节点 */
static int ktool_avrule_ex(int src, int tgt, int cls, u32 mask, int or_mode)
{
	struct p4k_avtab *av = p4k_te_avtab();
	struct p4k_avtab_node *cur, *prev, *node;
	int hv, n = 0;

	if (!av) {
		printk(KERN_INFO "ktool: avtab selfcheck FAILED\n");
		return -EIO;
	}
	if (!mask)
		return -EINVAL;
	hv = p4k_hash(av, src, tgt, cls);

	for (prev = NULL, cur = av->htable[hv]; cur; prev = cur, cur = cur->next) {
		if (cur->key.source_type == src &&
		    cur->key.target_type == tgt &&
		    cur->key.target_class == cls &&
		    (cur->key.specified & P4K_AVTAB_ALLOWED)) {
			u32 old = cur->datum.data;

			cur->datum.data = or_mode ? (old | mask) : mask;
			printk(KERN_INFO "ktool: avrule %d->%d:%d OR %#x -> %#x (node %p)\n",
			       src, tgt, cls, old, cur->datum.data, cur);
			return 0;
		}
		if (src < cur->key.source_type)
			break;
		if (src == cur->key.source_type && tgt < cur->key.target_type)
			break;
		if (src == cur->key.source_type && tgt == cur->key.target_type &&
		    cls < cur->key.target_class)
			break;
		if (++n > 200)
			return -ELOOP;
	}

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;
	node->key.source_type = src;
	node->key.target_type = tgt;
	node->key.target_class = cls;
	node->key.specified = P4K_AVTAB_ALLOWED;
	node->datum.data = mask;
	node->next = prev ? prev->next : av->htable[hv];

	smp_wmb();				/* 节点填满后再发布指针 */

	if (prev)
		prev->next = node;
	else
		av->htable[hv] = node;
	av->nel++;

	printk(KERN_INFO "ktool: avrule %d->%d:%d ADD %#x node=%p slot=%d nel=%u\n",
	       src, tgt, cls, mask, node, hv, av->nel);
	return 0;
}

/*
 * 摘掉 (src,tgt,cls,ALLOWED) 节点 —— uninstall 时回收插进去的规则。
 *
 * 不 kfree：avtab_search_node() 遍历链表时不在链表上加锁（内核假定策略加载
 * 完就是只读的），free 掉会和并发遍历撞成 OOB。摘链之后规则不再被命中，
 * 代价是泄漏一个 16 字节的节点 —— 一台机器一次卸载，可以忽略。
 */
static int ktool_avdel(int src, int tgt, int cls)
{
	struct p4k_avtab *av = p4k_te_avtab();
	struct p4k_avtab_node **pp, *cur;
	int hv, n = 0;

	if (!av) {
		printk(KERN_INFO "ktool: avtab selfcheck FAILED\n");
		return -EIO;
	}
	hv = p4k_hash(av, src, tgt, cls);
	for (pp = &av->htable[hv]; (cur = *pp) != NULL; pp = &cur->next) {
		if (cur->key.source_type == src &&
		    cur->key.target_type == tgt &&
		    cur->key.target_class == cls &&
		    (cur->key.specified & P4K_AVTAB_ALLOWED)) {
			smp_wmb();
			*pp = cur->next;
			av->nel--;
			printk(KERN_INFO "ktool: avdel %d->%d:%d off node=%p nel=%u\n",
			       src, tgt, cls, cur, av->nel);
			return 0;
		}
		if (++n > 400)
			break;
	}
	printk(KERN_INFO "ktool: avdel %d->%d:%d not found\n", src, tgt, cls);
	return -ENOENT;
}

/*
 * 把 p4k_apply_su_rules() 加的东西全部退掉：六条纯新增的摘链，一条原本
 * 就存在、只是被 OR 过权限的覆盖回原 mask。
 *
 * init_shell -> system_prop:property_service 不用管：原策略本来就有 set，
 * 插入时 OR 上去等于没改。
 */
static void p4k_avrestore(void)
{
	int r = 0;

	r |= ktool_avdel(p4k_tgt_initshell, p4k_src_app, 8);		/* fd */
	r |= ktool_avdel(p4k_src_app, p4k_tgt_initshell, 2);		/* process */
	r |= ktool_avdel(p4k_src_app, p4k_tgt_shelldata, 12);		/* sock_file */
	r |= ktool_avdel(p4k_shell_type, p4k_su_exec_type, 6);		/* file */
	r |= ktool_avdel(p4k_tgt_initshell, p4k_shell_type, 8);		/* fd */
	r |= ktool_avdel(p4k_shell_type, p4k_tgt_shelldata, 12);	/* sock_file */

	ktool_avrule_ex(p4k_src_app, p4k_tgt_shelldata, 7,
			(u32)p4k_dir_orig_mask, 0);			/* dir */

	printk(KERN_INFO "ktool: avrestore done (del rc=%d)\n", r);
}

static int ktool_avrule(int src, int tgt, int cls, u32 mask)
{
	return ktool_avrule_ex(src, tgt, cls, mask, 1);
}

/*
 * avcflush — 只清 AVC 缓存，不动 policydb（P4.28）
 *
 * 为什么需要它：AVC 条目在**计算时**就把 AVD_FLAGS_PERMISSIVE 烤进了
 * avd->flags，所以 permissive_map 清零后，已缓存的三元组仍然按 permissive
 * 放行 —— 这就是"permissive_map 清了但 remount 还是被拒"的根因。
 *
 * 为什么用 avc_ss_reset 而不是自己遍历链表：
 *   它是内核自己的 API（security_load_policy 也用它），内部按 slot 加
 *   spin_lock + call_rcu 回收，安全。手工无锁改活哈希表会造环链，
 *   avc_search_node 死循环 → 看门狗复位（P4.24 实测过）。
 *
 * 代价：清完之后，之前被 permissive 放过的真拒绝会重新变成拒绝并进审计。
 *   这是"恢复强制"的必然结果，不是副作用。
 */
static int ktool_avcflush(void)
{
	void (*avc_reset)(u32);

	avc_reset = (void *)kallsyms_lookup_name("avc_ss_reset");
	if (!avc_reset) {
		printk(KERN_INFO "ktool: avc_ss_reset not found\n");
		return -ENOSYS;
	}
	avc_reset(0);
	printk(KERN_INFO "ktool: avc cache flushed\n");
	return 0;
}


/*
 * ish — 把「当前进程」切成 uid 0 + u:r:init_shell:s0
 *
 * 与 "root" 的区别：kernel 域对 system_file 只有 execute 没有 execute_no_trans，
 * exec 任何东西都会被拒。init_shell 两者都有，且能读 /data/data。
 *
 * 做法：prepare_kernel_cred(NULL) 拿到 uid0 + full caps 的 cred（security blob
 * 由 selinux_cred_prepare 独立复制，改它不会污染 init_cred），再把
 * task_security_struct 的 osid/sid 换成查表得到的 init_shell SID。
 *
 * SID 必须查表：type value 986 != sidtab 索引，硬编码会指向错误的 context。
 */
static int ktool_ish(void)
{
	int (*ctx2sid)(const char *, u32, u32 *);
	struct cred *new;
	u32 sid = 0;
	char ctx[] = "u:r:init_shell:s0";
	char *sec;

	ctx2sid = (void *)kallsyms_lookup_name("security_context_to_sid");
	if (!ctx2sid) {
		printk(KERN_INFO "ktool: security_context_to_sid not found\n");
		return -ENOSYS;
	}
	if (ctx2sid(ctx, sizeof(ctx) - 1, &sid) || !sid) {
		printk(KERN_INFO "ktool: ctx2sid(%s) failed\n", ctx);
		return -EINVAL;
	}

	new = prepare_kernel_cred(NULL);
	if (!new)
		return -ENOMEM;

	sec = (char *)new->security;
	if (sec) {
		*(u32 *)(sec + 0)  = sid;	/* osid       */
		*(u32 *)(sec + 4)  = sid;	/* sid        */
		*(u32 *)(sec + 8)  = 0;		/* exec_sid   */
		*(u32 *)(sec + 12) = 0;		/* create_sid */
		*(u32 *)(sec + 16) = 0;		/* keycreate  */
		*(u32 *)(sec + 20) = 0;		/* sockcreate */
	}

	commit_creds(new);
	printk(KERN_INFO "ktool: ish -> uid0 sid=%u\n", sid);
	return 0;
}

/*
 * ctx — 换 SELinux 域，可选同时改 fsuid/fsgid
 *
 * 用法:  ctx <context>              只换域
 *        ctx <context> <uid> <gid>  换域 + 直接写 fsuid/fsgid
 *
 * 为什么 uid/gid 必须由内核写（P4.27 实测）：
 *   sys_setfsuid()/sys_setfsgid() 第一步就是 capable(CAP_SETUID/SETGID)，
 *   而该检查走 SELinux 的 capability class。init_shell 的 capability 规则
 *   在部分策略版本里不含 setuid/setgid（实测 capable 被拒），且**失败是静默的**
 *   ——syscall 直接 return old_fsuid，不设 errno，用户态完全看不出来。
 *   内核侧写 cred 字段不经过任何检查，且 prepare_creds 之后改动是原子的。
 *
 * 只改 fsuid/fsgid，不改 uid/euid：文件 owner 由 fsuid 决定，
 * 而 DAC 判定也只看 fsuid，所以两把钥匙（fsuid=owner + untrusted_app）就够了。
 */
static int ktool_setctx(const char *ctx, int len)
{
	int (*ctx2sid)(const char *, u32, u32 *);
	struct cred *new;
	u32 sid = 0;
	char *sec;
	char buf[96];
	char *sp;
	long uid = -1, gid = -1;
	int clen;

	if (len <= 0 || len >= (int)sizeof(buf))
		return -EINVAL;
	memcpy(buf, ctx, len);
	buf[len] = 0;

	/* 尾部可选 "<uid> <gid>"：从右往左剥两个纯数字字段 */
	sp = strrchr(buf, ' ');
	if (sp && sp[1] >= '0' && sp[1] <= '9') {
		char *sp2;

		gid = simple_strtol(sp + 1, NULL, 10);
		*sp = 0;
		sp2 = strrchr(buf, ' ');
		if (sp2 && sp2[1] >= '0' && sp2[1] <= '9') {
			uid = simple_strtol(sp2 + 1, NULL, 10);
			*sp2 = 0;
		} else {
			uid = gid;	/* 只给了 1 个数字：当 uid，gid 沿用 uid */
			gid = uid;
		}
	}

	clen = strlen(buf);
	if (!clen)
		return -EINVAL;

	ctx2sid = (void *)kallsyms_lookup_name("security_context_to_sid");
	if (!ctx2sid)
		return -ENOSYS;
	if (ctx2sid(buf, clen, &sid) || !sid)
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	sec = (char *)new->security;
	if (sec) {
		*(u32 *)(sec + 0)  = sid;
		*(u32 *)(sec + 4)  = sid;
		*(u32 *)(sec + 8)  = 0;
		*(u32 *)(sec + 12) = 0;
	}
	if (uid >= 0)
		new->fsuid = (uid_t)uid;
	if (gid >= 0)
		new->fsgid = (gid_t)gid;

	commit_creds(new);
	printk(KERN_INFO "ktool: ctx -> %s sid=%u fsuid=%ld fsgid=%ld\n", buf, sid,
	       uid, gid);
	return 0;
}

/*
 * /system/bin/ktool 的 DAC 锁（P4.25 v10）
 *
 * 为什么在模块里做而不是 boot 脚本：
 *   - boot 脚本（sec-sh）是 uid0+init_shell 但**没有 CAP_SYS_ADMIN**，
 *     mount -o rw,remount /system 必 EPERM，chmod 撞 EROFS —— v9/v9b 实测。
 *   - 借 `ktool sh` 的 caps 挂载则会把 permissive_map **全开**且重启不还原，
 *     直接毁掉"只有 1 个 type permissive"的设计。
 *
 * 为什么必须是 700（P4.25 v10 实测）：
 *   untrusted_app → system_file:file **有 execute**，所以 ktool 只要是 755，
 *   任何 app 都能直接 exec 这个自带 exploit 的二进制拿 root，门禁完全绕过。
 *   700 root:root 下：sec-sh（uid 0）能 exec，app 和 adb shell（uid 2000）都不能。
 *
 * 局限（诚实记录）：这是**内存**修改，不标记 inode dirty。/system 是只读挂载，
 *   ext4 不会回收，inode 一旦被内存压力回收就会从磁盘读回旧值 —— v10 实测
 *   开机后 10~20 秒被翻回 755。真正的落盘要靠 boot 脚本里一次真实 chmod
 *   （见 init.sec.boot.v9d），这里只是内存兜底。
 *
 * 调试通道：/data/local/tmp/ktool（ktool 二进制副本，750 shell:shell）。
 *   SELinux 对 untrusted_app → shell_data_file **无 execute**，DAC 又挡 app，
 *   所以 app 用不了它；adb shell 是 owner 可以用。重启后本模块自动改回 700。
 */




static void ktool_apply_ktool_mode(void)
{
	struct path pflag, pkt;
	mode_t want;
	int ret;

	/* dev flag：存在则 755（adb 调试），否则 700（锁定） */
	ret = kern_path("/data/local/tmp/ktool_dev", 0, &pflag);
	if (!ret) {
		path_put(&pflag);
		want = 0755;
	} else {
		printk(KERN_INFO "ktool: dev flag lookup -> %d\n", ret);
		want = 0700;
	}

	if (kern_path(KTOOL_BIN_PATH, LOOKUP_FOLLOW, &pkt))
		return;
	pkt.dentry->d_inode->i_mode =
		(pkt.dentry->d_inode->i_mode & S_IFMT) | want;
	path_put(&pkt);
	printk(KERN_INFO "ktool: %s -> %o (%s)\n", KTOOL_BIN_PATH, want,
	       want == 0700 ? "locked" : "dev");

	/*
	 * 设备节点模式也必须显式设：miscdevice.mode 只在 devtmpfs 首次
	 * 创建节点时通过 devnode 回调生效，模块反复 rmmod/insmod 后实测
	 * 会拿到 0600 —— 那时 adb shell / su 都打不开，表现成
	 * "can't create /dev/ktool: Permission denied"，很容易误判成 SELinux。
	 */
	if (!kern_path(KTOOL_DEV_PATH, 0, &pkt)) {
		pkt.dentry->d_inode->i_mode =
			(pkt.dentry->d_inode->i_mode & S_IFMT) | 0666;
		path_put(&pkt);
	}
}

/*
 * 标签校验与修复（P4.33）
 *
 * 原实现只做一次 `kt[i_security] = null[i_security]`（**拷贝指针**）。
 * 这个指针会在策略重载后失效/被复用 —— 实测出现过 /dev/ktool 被标成
 * `u:r:platform_app:s0`（那是某个进程的域），后果是 ctx/ish 写不进去，
 * **su 静默失效到下次重启**。
 *
 * 现在改成：
 *   1) 用 security_context_to_sid("u:object_r:null_device:s0") 算出期望 SID
 *   2) 读 inode_security_struct.sid（偏移 0x10，见 objsec.h）比对
 *   3) 不一致就重新拷贝并**再校验**；还不行就把旧指针写回去，不留坏 blob
 *   4) init 时重试 5 次；另外每次 open() 再校验一次（策略重载后自愈）
 */
#define ISEC_SID_OFF	0x10	/* struct inode_security_struct.sid */

static u32 ktool_expect_sid(void)
{
	int (*ctx2sid)(const char *, u32, u32 *);
	static const char ctx[] = "u:object_r:null_device:s0";
	u32 sid = 0;

	ctx2sid = (void *)kallsyms_lookup_name("security_context_to_sid");
	if (!ctx2sid)
		return 0;
	if (ctx2sid(ctx, sizeof(ctx) - 1, &sid))
		return 0;
	return sid;
}

/*
 * /dev/ktool 的 SELinux 标签（P4.37 重做）
 *
 * 失败史：
 *   v1「拷 /dev/null 的 blob 指针」—— 两个 inode 共用一个 blob，而 sid 是
 *      sidtab 的**序号**；策略一重载序号就整体重映射，/dev/null 和
 *      /dev/ktool 会一起变成别的类型（实测 u:r:system_server:s0），
 *      连 `> /dev/null` 都被拒，su 静默失效。
 *   v2「把期望 SID 写进共享 blob」—— 会连带改掉 /dev/null，照样炸。
 *
 * 现在：自己 kmalloc 一个 inode_security_struct，内容从 /dev/zero 的 blob
 * 复制（拿到正确的 sclass 与已初始化的 mutex），然后改回自己：
 *   +0x00 inode 反向指针   +0x04/+0x08 list 自环   +0x0C task_sid
 *   +0x10 sid              +0x14 sclass(u16)       +0x16 initialized(u8)
 * 每次 open() 再用 security_context_to_sid("u:object_r:null_device:s0")
 * 现算 SID 刷新 —— 策略重载后自动跟上新的序号。
 */
#define ISEC_SZ		0x40
#define ISEC_SID	0x10

static void *ktool_blob;
static struct inode *ktool_inode;

static struct inode *ktool_path_inode(const char *path)
{
	struct path p;
	struct inode *i = NULL;

	if (!kern_path(path, 0, &p)) {
		i = p.dentry->d_inode;
		path_put(&p);
	}
	return i;
}

static int ktool_refresh_blob(const char *why)
{
	u32 sid = ktool_expect_sid();
	void **slot;
	void *cur;

	if (!ktool_inode || !ktool_blob || !sid)
		return -1;
	slot = (void **)((char *)ktool_inode + offsetof(struct inode, i_security));
	cur = *slot;
	if (cur != ktool_blob) {
		*slot = ktool_blob;
		smp_wmb();
		printk(KERN_INFO "ktool: blob re-attached (%s)\n", why);
	}
	*(u32 *)((char *)ktool_blob + ISEC_SID) = sid;
	return 0;
}

static void ktool_relabel(void)
{
	struct inode *zf = ktool_path_inode("/dev/zero");
	void *ref, *mine;
	int i;

	ktool_inode = ktool_path_inode("/dev/ktool");
	for (i = 0; i < 10 && !ktool_inode; i++) {
		msleep(50);
		ktool_inode = ktool_path_inode("/dev/ktool");
	}
	if (!ktool_inode) {
		printk(KERN_INFO "ktool: ktool path fail\n");
		return;
	}
	if (!zf) {
		printk(KERN_INFO "ktool: zero path fail\n");
		return;
	}
	ref = *(void **)((char *)zf + offsetof(struct inode, i_security));
	if (!ref) {
		printk(KERN_INFO "ktool: zero blob null\n");
		return;
	}
	mine = kmalloc(ISEC_SZ, GFP_KERNEL);
	if (!mine) {
		printk(KERN_INFO "ktool: blob alloc fail\n");
		return;
	}
	memcpy(mine, ref, ISEC_SZ);
	*(void **)((char *)mine + 0x00) = ktool_inode;
	*(void **)((char *)mine + 0x04) = (char *)mine + 0x04;
	*(void **)((char *)mine + 0x08) = (char *)mine + 0x04;
	*(u32 *)((char *)mine + 0x0C) = 0;
	ktool_blob = mine;
	ktool_refresh_blob("init");
	printk(KERN_INFO "ktool: own blob %p (ref zero %p)\n", mine, ref);
}

static void ktool_lbl_one(const char *path)
{
	struct path p;
	void *blob;
	int i;

	if (kern_path(path, 0, &p)) {
		printk(KERN_INFO "ktool: lbl %s pathfail\n", path);
		return;
	}
	blob = *(void **)((char *)p.dentry->d_inode + offsetof(struct inode, i_security));
	printk(KERN_INFO "ktool: lbl %s inode=%p blob=%p\n", path,
	       p.dentry->d_inode, blob);
	if (blob) {
		for (i = 0; i < 8; i++)
			printk(KERN_INFO "ktool:   +%02x %08x\n", i * 4,
			       *(u32 *)((char *)blob + i * 4));
	}
	path_put(&p);
}

static int ktool_lbldbg(void)
{
	ktool_lbl_one("/dev/null");
	ktool_lbl_one("/dev/ktool");
	ktool_lbl_one("/dev/zero");
	return 0;
}

static int ktool_fixlbl(void)
{
	int r = ktool_refresh_blob("cmd");

	printk(KERN_INFO "ktool: fixlbl -> %d (sid now %u)\n", r,
	       ktool_blob ? *(u32 *)((char *)ktool_blob + ISEC_SID) : 0);
	return r;
}














static ssize_t ktool_read(struct file *file, char __user *buf, size_t len, loff_t *off)
{
	char msg[64];
	int n;

	/*
	 * 不打印 cred 字段：本模块的 .config 来自 ja3g_00_defconfig，
	 * 与设备内核实测 config 未必一致，current_cred() 的编译期偏移可能错位
	 * （实测 uid/sid 打印出 0xc86fad68 这类内核栈值）。
	 * cred 本身由 commit_creds 在内核内部处理，不受模块偏移影响，
	 * 所以 ish/ctx 功能正常，只是这里不能信 current_cred()。
	 * 域验证用 /proc/self/attr/current。
	 */
	n = snprintf(msg, sizeof(msg), "ktool: ready\n");
	if (*off > 0)
		return 0;
	if (copy_to_user(buf, msg, n))
		return -EFAULT;
	*off += n;
	return n;
}

static ssize_t ktool_write(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
	char kbuf[64];
	int pid;
	struct task_struct *task;
	struct cred *new, *old;

	if (len == 0 || len >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, len))
		return -EFAULT;
	kbuf[len] = 0;

	/*
	 * /dev/ktool 是 0666 + allow domain null_device:chr_file write，
	 * 意味着任何 app 都能直接 echo ish 拿 root，完全绕过 su 的授权弹窗。
	 * 这里是唯一的守门点。
	 */
	if (!ktool_allow(kbuf)) {
		printk(KERN_WARNING "ktool: denied cmd '%.24s'\n", kbuf);
		return -EACCES;
	}

	if (strncmp(kbuf, "root ", 5) == 0) {
		if (sscanf(kbuf + 5, "%d", &pid) != 1)
			return -EINVAL;

		new = prepare_kernel_cred(NULL);
		if (!new)
			return -ENOMEM;

		rcu_read_lock();
		task = pid_task(find_vpid(pid), PIDTYPE_PID);
		if (!task) {
			rcu_read_unlock();
			put_cred(new);
			return -ESRCH;
		}
		get_task_struct(task);
		rcu_read_unlock();

		old = *(struct cred **)((char *)task + TASK_CRED);
		*(struct cred **)((char *)task + TASK_CRED) = new;
		*(struct cred **)((char *)task + TASK_REAL_CRED) = new;
		smp_wmb();
		if (old)
			put_cred(old);
		put_task_struct(task);

		printk(KERN_INFO "ktool: root pid %d (old=%p)\n", pid, old);
	} else if (strncmp(kbuf, "root", 4) == 0) {
		new = prepare_kernel_cred(NULL);
		if (!new)
			return -ENOMEM;
		commit_creds(new);
		printk(KERN_INFO "ktool: root current\n");
	} else if (strncmp(kbuf, "avrestore", 9) == 0) {
		p4k_avrestore();
	} else if (strncmp(kbuf, "wfind16 ", 8) == 0) {
		int pid = 0;
		unsigned int pat = 0;
		int ret;

		if (sscanf(kbuf + 8, "%d %x", &pid, &pat) != 2)
			return -EINVAL;
		ret = ktool_wfind16(pid, (u16)pat);
		if (ret)
			return ret;
	} else if (strncmp(kbuf, "wfind ", 6) == 0) {
		int pid = 0;
		unsigned int pat = 0;
		int ret;

		if (sscanf(kbuf + 6, "%d %x", &pid, &pat) != 2)
			return -EINVAL;
		ret = ktool_wfind(pid, pat);
		if (ret)
			return ret;
	} else if (strncmp(kbuf, "wdump ", 6) == 0) {
		int pid = 0, ret;

		if (sscanf(kbuf + 6, "%d", &pid) != 1)
			return -EINVAL;
		ret = ktool_wdump(pid);
		if (ret)
			return ret;
	} else if (strncmp(kbuf, "ksym ", 5) == 0) {
		char nm[64];
		int ret;

		if (sscanf(kbuf + 5, "%63s", nm) != 1)
			return -EINVAL;
		ret = ktool_ksym(nm);
		if (ret)
			return ret;
	} else if (strncmp(kbuf, "kread ", 6) == 0) {
		unsigned long a = 0;
		int n = 0, ret;

		if (sscanf(kbuf + 6, "%lx %d", &a, &n) != 2)
			return -EINVAL;
		ret = ktool_kread(a, n);
		if (ret)
			return ret;
	} else if (strncmp(kbuf, "lbldbg", 6) == 0) {
		int ret = ktool_lbldbg();
		if (ret)
			return ret;
	} else if (strncmp(kbuf, "fixlbl", 6) == 0) {
		int ret = ktool_fixlbl();
		if (ret)
			return ret;
	} else if (strncmp(kbuf, "waiter ", 7) == 0) {
		int pid = 0, ret;

		if (sscanf(kbuf + 7, "%d", &pid) != 1)
			return -EINVAL;
		ret = ktool_waiter(pid);
		if (ret)
			return ret;
	} else if (strncmp(kbuf, "bugtest", 7) == 0) {
		int ret = ktool_bugtest();
		if (ret)
			return ret;
	} else if (strncmp(kbuf, "warntest", 8) == 0) {
		int ret = ktool_warntest();
		if (ret)
			return ret;
	} else if (strncmp(kbuf, "avruleq ", 8) == 0) {
		int a = 0, b = 0, c = 0, ret;

		if (sscanf(kbuf + 8, "%d %d %d", &a, &b, &c) != 3)
			return -EINVAL;
		ret = ktool_avruleq(a, b, c);
		if (ret)
			return ret;
	} else if (strncmp(kbuf, "avset ", 6) == 0) {
		int a = 0, b = 0, c = 0;
		unsigned int m = 0;
		int ret;

		if (sscanf(kbuf + 6, "%d %d %d %x", &a, &b, &c, &m) != 4)
			return -EINVAL;
		ret = ktool_avrule_ex(a, b, c, m, 0);
		if (ret)
			return ret;
	} else if (strncmp(kbuf, "avrule ", 7) == 0) {
		int a = 0, b = 0, c = 0;
		unsigned int m = 0;
		int ret;

		if (sscanf(kbuf + 7, "%d %d %d %x", &a, &b, &c, &m) != 4)
			return -EINVAL;
		ret = ktool_avrule(a, b, c, m);
		if (ret)
			return ret;
	} else if (strncmp(kbuf, "avcflush", 8) == 0) {
		int ret = ktool_avcflush();
		if (ret)
			return ret;
	} else if (strncmp(kbuf, "ish", 3) == 0) {
		int ret = ktool_ish();
		if (ret)
			return ret;
	} else if (strncmp(kbuf, "ctx ", 4) == 0) {
		char *s = kbuf + 4;
		int n = strlen(s);
		int ret;
		while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
			s[--n] = 0;
		if (!n)
			return -EINVAL;
		ret = ktool_setctx(s, n);
		if (ret)
			return ret;
	} else {
		return -EINVAL;
	}
	return len;
}

static int ktool_open(struct inode *inode, struct file *file)
{
	/* 策略重载会重映射 SID，这里每次 open 现算一次刷进去 */
	ktool_refresh_blob("open");
	return 0;
}

static const struct file_operations ktool_fops = {
	.owner = THIS_MODULE,
	.open = ktool_open,
	.read = ktool_read,
	.write = ktool_write,
};

static struct miscdevice ktool_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ktool",
	.fops = &ktool_fops,
	.mode = 0666,
};

/* 解析 "device:kernel" 并查表；失败返回 NULL */
static const struct ktool_target *ktool_pick_target(void)
{
	char dev[64], ker[96];
	const char *p;
	int n;

	if (!ktool_target || !ktool_target[0])
		goto fallback;

	p = strchr(ktool_target, ':');
	if (!p)
		goto fallback;
	n = p - ktool_target;
	if (n <= 0 || n >= (int)sizeof(dev))
		goto fallback;
	memcpy(dev, ktool_target, n);
	dev[n] = 0;
	strncpy(ker, p + 1, sizeof(ker) - 1);
	ker[sizeof(ker) - 1] = 0;

	return ktool_find_target(dev, ker);

fallback:
	/* 没给参数：只有表里恰好一个目标时才退回它，多个目标宁可不用 */
	if (KT_NTARGETS == 1) {
		printk(KERN_WARNING "ktool: no ktool_target=, fallback to %s/%s\n",
		       ktool_targets[0].device, ktool_targets[0].kernel);
		return &ktool_targets[0];
	}
	printk(KERN_ERR "ktool: no ktool_target= and %u targets in table, "
	       "address-based ops disabled\n", (unsigned)KT_NTARGETS);
	return 0;
}

static int __init ktool_init(void)
{
	int ret;

	tgt = ktool_pick_target();

	ret = misc_register(&ktool_miscdev);
	if (ret)
		return ret;

	ktool_relabel();	/* 给 /dev/ktool 装一个自己的 null_device blob */
	ktool_lbldbg();		/* 把三个节点的 blob 打进 dmesg，便于事后核对 */
	ktool_apply_ktool_mode();

	/* 门禁依赖的符号在 init 时解析（write 路径只做比较） */
	ktool_get_mm_exe_file =
		(void *)kallsyms_lookup_name("get_mm_exe_file");
	ktool_set_panic_on_oops();

	p4k_apply_su_rules();

	printk(KERN_INFO "ktool: loaded (/dev/ktool) enforce=%d su=%s exe_file_fn=%s\n",
	       ktool_enforce, ktool_su_path,
	       ktool_get_mm_exe_file ? "ok" : "MISSING");
	if (tgt)
		printk(KERN_INFO "ktool: target %s/%s build=%s\n", tgt->device,
		       tgt->kernel, tgt->build ? tgt->build : "-");
	else
		printk(KERN_ERR "ktool: NO TARGET -> patch/permissive 拒绝执行\n");
	return 0;
}

static void __exit ktool_exit(void)
{
	misc_deregister(&ktool_miscdev);
	printk(KERN_INFO "ktool: unloaded\n");
}

module_init(ktool_init);
module_exit(ktool_exit);
