/*
 * statfs_leak —— 验证 statfs 的 f_spare 泄漏是否指向调用线程自己的内核栈
 *
 * 判据：
 *   1. 同一线程多次调用 → 值稳定
 *   2. 不同线程调用     → 值不同（各自栈）
 *   3. 8KB 对齐后落在该线程栈范围内
 *   4. 加深调用栈后值随之平移 → 确证是栈指针
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef SYS_statfs
#define SYS_statfs 99
#endif
#ifndef SYS_statfs64
#define SYS_statfs64 348
#endif

static void show(const char *who, const struct statfs *st)
{
	printf("%-14s f_spare = %08lx %08lx %08lx %08lx   base8k=%08lx  tid=%d\n",
	       who,
	       (unsigned long)st->f_spare[0], (unsigned long)st->f_spare[1],
	       (unsigned long)st->f_spare[2], (unsigned long)st->f_spare[3],
	       (unsigned long)st->f_spare[0] & ~0x1ffful,
	       (int)syscall(SYS_gettid));
}

static void probe(const char *who)
{
	struct statfs st;
	memset(&st, 0, sizeof st);
	if (statfs("/data", &st) < 0) {
		printf("%-14s statfs fail errno=%d\n", who, errno);
		return;
	}
	show(who, &st);
}

/* 深一层调用，观察值是否平移 */
static void probe_deep(int depth)
{
	char pad[256];
	memset(pad, 0x5a, sizeof pad);
	if (depth > 0) {
		probe_deep(depth - 1);
		return;
	}
	{
		struct statfs st;
		memset(&st, 0, sizeof st);
		statfs("/data", &st);
		printf("deep(%d)        f_spare = %08lx  pad=%02x  tid=%d\n",
		       depth, (unsigned long)st.f_spare[0], (unsigned char)pad[0],
		       (int)syscall(SYS_gettid));
	}
}

static void *thr(void *arg)
{
	char name[32];
	snprintf(name, sizeof name, "thread-%ld", (long)arg);
	probe(name);
	return NULL;
}

int main(void)
{
	int i;
	pthread_t t[3];

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== statfs f_spare leak probe  pid=%d ===\n", getpid());

	probe("main#1");
	probe("main#2");
	probe("main#3");

	for (i = 0; i < 3; i++)
		pthread_create(&t[i], NULL, thr, (void *)(long)i);
	for (i = 0; i < 3; i++)
		pthread_join(t[i], NULL);

	probe_deep(0);
	probe_deep(4);
	probe_deep(8);

	/* 对比 statfs 与 statfs64 两条 syscall 路径 */
	{
		struct statfs st;
		char buf64[256];
		memset(&st, 0, sizeof st);
		memset(buf64, 0, sizeof buf64);
		if (syscall(SYS_statfs, "/data", &st) == 0)
			printf("SYS_statfs     f_spare = %08lx\n", (unsigned long)st.f_spare[0]);
		else
			printf("SYS_statfs     errno=%d\n", errno);
		memset(buf64, 0, sizeof buf64);
		if (syscall(SYS_statfs64, "/data", (size_t)sizeof(buf64), buf64) == 0) {
			uint32_t *w = (uint32_t *)buf64;
			printf("SYS_statfs64   words[16..19] = %08x %08x %08x %08x\n",
			       w[16], w[17], w[18], w[19]);
		} else {
			printf("SYS_statfs64   errno=%d\n", errno);
		}
	}
	return 0;
}
