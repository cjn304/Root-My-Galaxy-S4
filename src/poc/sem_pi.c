/* SPDX-License-Identifier: GPL-3.0-or-later */

/* 探测真实 pi_state->pi_mutex 的现场（P4.46）
 *
 * 目的：endgame 唯一现实的目标是「一个有等待者的真实 rt_mutex」。
 *       本程序让线程 C 真的阻塞在 u5 上，然后把 C->pi_blocked_on 和
 *       它指向的 rt_mutex 全部读出来，回答三个问题：
 *         1) C->pi_blocked_on 能不能拿到（waiter 地址）
 *         2) waiter->lock 指向的 rt_mutex 地址是多少
 *         3) 该 rt_mutex 的 wait_lock / wait_list / owner 是什么值 ——
 *            决定 trylock 能否成功、wait_list 是否非空（BUG_ON 能否通过）
 *
 * 零风险：不触发 rt_mutex_adjust_prio_chain，只读。
 *
 * 用法：/data/local/tmp/ktool root /data/local/tmp/sem_pi
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
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

#define FUTEX_LOCK_PI		6

static uint32_t u5;
static volatile int c_started, c_tid, c_done;
static volatile int c_ret = 999, c_err;
static FILE *lg;
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

/* 从 dmesg 里找最后一条 "key=<hex>" */
static int dmesg_hex(const char *key, uint32_t *out)
{
	char *p = g_kbuf, *last = NULL;
	size_t kl = strlen(key);

	if (klog_read() < 0) return -1;
	while ((p = strstr(p, key)) != NULL) { last = p; p++; }
	if (!last) return -1;
	last += kl;
	return (sscanf(last, "%x", out) == 1) ? 0 : -1;
}

/* 从 dmesg 里找 "ktool:   XXXXXXXX: YYYYYYYY" 中指定地址的值 */
static int dmesg_kread_val(uint32_t addr, uint32_t *out)
{
	char key[32];
	char *p = g_kbuf, *last = NULL;
	size_t kl;

	snprintf(key, sizeof key, "ktool:   %08x: ", addr);
	kl = strlen(key);
	if (klog_read() < 0) return -1;
	while ((p = strstr(p, key)) != NULL) { last = p; p++; }
	if (!last) return -1;
	last += kl;
	return (sscanf(last, "%x", out) == 1) ? 0 : -1;
}

static int kt_write(const char *cmd)
{
	int fd = open("/dev/ktool", O_WRONLY);
	int n = (int)strlen(cmd);
	int w;

	if (fd < 0) {
		logf_("[!] open /dev/ktool errno=%d\n", errno);
		return -1;
	}
	w = (int)write(fd, cmd, n);
	close(fd);
	if (w != n) {
		logf_("[!] write '%s' -> %d/%d errno=%d\n", cmd, w, n, errno);
		return -1;
	}
	return 0;
}

static int kread(uint32_t addr, int len)
{
	char cmd[64];

	snprintf(cmd, sizeof cmd, "kread %x %d", addr, len);
	return kt_write(cmd);
}

static void *thread_c(void *arg)
{
	(void)arg;
	pin_cpu(1);
	c_tid = (int)syscall(SYS_gettid);
	c_started = 1;
	__sync_synchronize();
	/* 主线程已持 u5 → 这里阻塞成 PI waiter */
	c_ret = (int)syscall(SYS_futex, &u5, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	c_err = errno;
	c_done = 1;
	return NULL;
}

int main(void)
{
	pthread_t tc;
	uint32_t stack = 0, pbo = 0, pmtx = 0, v;
	int i;

	setvbuf(stdout, NULL, _IONBF, 0);
	lg = fopen("/data/local/tmp/pi.log", "w");
	g_kbuf = malloc(1 << 20);
	if (!g_kbuf) return 1;

	/* 主线程先拿到 u5 */
	syscall(SYS_futex, &u5, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	pthread_create(&tc, NULL, thread_c, NULL);
	while (!c_started) usleep(1000);
	usleep(300000);		/* 等 C 真正阻塞 */

	logf_("=== sem_pi pid=%d c_tid=%d ===\n", getpid(), (int)c_tid);

	/* 1) 取 C 的 stack 与 pi_blocked_on */
	{
		char cmd[64];

		snprintf(cmd, sizeof cmd, "waiter %d", (int)c_tid);
		if (kt_write(cmd) != 0) { logf_("*** ABORT ***\n"); return 2; }
	}
	usleep(80000);
	if (dmesg_hex("ktool:   task->stack=", &stack) != 0) {
		logf_("[!] 没有 stack\n"); return 2;
	}
	if (dmesg_hex("ktool:   pi_blocked_on=", &pbo) != 0 || pbo == 0) {
		logf_("[!] pi_blocked_on 拿不到（C 没阻塞？）\n"); return 2;
	}
	logf_("[1] C: stack=%#x pi_blocked_on=%#x (off=%#x)\n",
	      stack, pbo, pbo - stack);

	/* 2) 读 waiter，拿 lock 字段（+0x2C） */
	kread(pbo, 0x40);
	usleep(80000);
	if (dmesg_kread_val(pbo + 0x2C, &pmtx) != 0) {
		logf_("[!] 读不到 waiter->lock\n"); return 2;
	}
	{
		uint32_t prio = 0, task = 0;

		dmesg_kread_val(pbo + 0x00, &prio);
		dmesg_kread_val(pbo + 0x28, &task);
		logf_("[2] waiter: prio=%#x task=%#x lock(pi_mutex)=%#x\n",
		      prio, task, pmtx);
	}

	/* 3) 读 rt_mutex 本体：wait_lock(+0) wait_list(+0x08) owner(+0x10) */
	if (kread(pmtx, 0x40) != 0) { logf_("*** ABORT ***\n"); return 2; }
	usleep(80000);
	{
		uint32_t wl = 0, wln = 0, wlp = 0, owner = 0, f0x28 = 0;

		dmesg_kread_val(pmtx + 0x00, &wl);
		dmesg_kread_val(pmtx + 0x08, &wln);
		dmesg_kread_val(pmtx + 0x0C, &wlp);
		dmesg_kread_val(pmtx + 0x10, &owner);
		dmesg_kread_val(pmtx + 0x28, &f0x28);

		logf_("[3] rt_mutex @%#x:\n", pmtx);
		logf_("    wait_lock(+0x00) = %08x %s\n", wl,
		      (wl == 0) ? "<== 未锁 trylock 可成功" : "<== 非 0，trylock 会失败");
		logf_("    wait_list.next   = %08x\n", wln);
		logf_("    wait_list.prev   = %08x\n", wlp);
		logf_("    self-ring?       %s\n",
		      (wln == pmtx + 0x08 && wlp == pmtx + 0x08) ?
		      "YES（空表，BUG_ON 会失败）" : "NO（非空，BUG_ON 可过）");
		logf_("    owner(+0x10)     = %08x\n", owner);
		logf_("    *(0x28)          = %08x  (空表要求 == %#x)\n",
		      f0x28, pmtx - 0x04);
		logf_("    first waiter     = %08x\n", wln - 0x0C);
	}

	/* 4) 如果 wait_list 非空，看第一个 waiter 的 lock 是否 == pi_mutex */
	{
		uint32_t fw = 0, fl = 0;

		if (dmesg_kread_val(pmtx + 0x08, &v) == 0 && v != pmtx + 0x08) {
			fw = v - 0x0C;
			kread(fw, 0x40);
			usleep(80000);
			if (dmesg_kread_val(fw + 0x2C, &fl) == 0)
				logf_("[4] first waiter @%#x: lock=%#x  %s\n",
				      fw, fl, (fl == pmtx) ?
				      "<== == pi_mutex，BUG_ON 通过" : "<== 不等于！");
		}
	}

	logf_("*** DONE (C 仍阻塞，程序退出时自动清理) ***\n");
	sleep(1);
	return 0;
}
