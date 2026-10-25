/* SPDX-License-Identifier: GPL-3.0-or-later */

/*
 * futex_pi_block — 让一个线程稳定阻塞在 PI futex 上，供外部测量
 *
 * 目的：验证「泄漏出的 stack limit → 预测 waiter 地址」这条链。
 *   base = stack_limit & ~0x1FFF
 *   waiter 预期 = base + 0x1DF8（lk_m3 寄存器实测值）
 *
 * 用法（uid0 或普通用户都行，只要别被 SELinux 拦）：
 *   ./fpb [秒数]      默认 20 秒
 * 输出 pid 与线程名，便于外部 ktool find。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <time.h>
#include <errno.h>
#include <sys/prctl.h>

#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7

static uint32_t u1;
static volatile int a_blocked;

static int futex(uint32_t *u, int op, uint32_t val, const struct timespec *to,
		 uint32_t *u2, uint32_t val3)
{
	return syscall(SYS_futex, u, op, val, to, u2, val3);
}

static void *thread_a(void *arg)
{
	(void)arg;
	/* 改个独立 comm，方便 ktool find 精确定位这个线程 */
	prctl(PR_SET_NAME, "fpbwait", 0, 0, 0);
	/* u1 已被 main 持有 → 这里阻塞成 PI waiter */
	int r = futex(&u1, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

	printf("[A] LOCK_PI returned %d errno=%d\n", r, errno);
	return NULL;
}

int main(int argc, char **argv)
{
	int secs = (argc > 1) ? atoi(argv[1]) : 20;
	pthread_t th;
	int r;

	if (secs < 1 || secs > 300)
		secs = 20;
	setvbuf(stdout, NULL, _IONBF, 0);

	r = futex(&u1, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
	printf("[main] hold u1: ret=%d errno=%d pid=%d\n", r, errno, getpid());

	pthread_create(&th, NULL, thread_a, NULL);
	sleep(1);
	a_blocked = 1;
	printf("[main] A should be blocked now; sleeping %ds (comm=%.15s)\n",
	       secs, program_invocation_short_name ? program_invocation_short_name : "fpb");

	sleep(secs);

	futex(&u1, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
	pthread_join(th, NULL);
	printf("[main] done\n");
	return 0;
}
