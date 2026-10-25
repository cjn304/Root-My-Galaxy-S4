/* SPDX-License-Identifier: GPL-3.0-or-later */

/*
 * kstack_reuse — 测「线程死后内核栈地址能否被新线程复用」
 *
 * 为什么要测：GhostLock 那条 infoleak 拿到的是**已经死掉的那个线程**的内核栈地址。
 * 要用它，必须满足：新建的线程/进程会落到同一个内核栈地址。
 * 无 KASLR 只是必要条件，不是充分条件——buddy 分配是不是确定性，得实测。
 *
 * 做法：每轮新建一个线程，让它写 "warntest" 到 /dev/ktool，模块的 WARN 会把
 *       该线程的内核栈地址打到 dmesg（stack=%p）。解析出来对比。
 *
 * 用法（必须 uid0，门禁要求）：
 *   ktool root /data/local/tmp/kstack_reuse [轮数]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/syscall.h>

struct slot {
	unsigned long kstack;	/* 解析到的内核栈地址 */
	unsigned long tid;
	int ok;
};

static volatile int g_serial;	/* 让每轮线程的标识不同，避免被内核合并 */

static void *worker(void *arg)
{
	struct slot *s = arg;
	int fd;

	s->tid = (unsigned long)pthread_self();
	fd = open("/dev/ktool", O_WRONLY);
	if (fd < 0) {
		s->ok = -1;
		return NULL;
	}
	if (write(fd, "warntest", 8) != 8) {
		close(fd);
		s->ok = -2;
		return NULL;
	}
	close(fd);
	s->ok = 0;
	return NULL;
}

/* 直接读内核日志缓冲区（Android 没有 /bin/sh，popen 用不了） */
#define SYSLOG_ACTION_READ_ALL 3
static char g_kbuf[1 << 20];

static unsigned long last_kstack(void)
{
	long n = syscall(SYS_syslog, SYSLOG_ACTION_READ_ALL, g_kbuf,
			 sizeof(g_kbuf) - 1);
	char *p = g_kbuf, *last = NULL;
	unsigned long val = 0;

	if (n <= 0)
		return 0;
	g_kbuf[n] = 0;
	while ((p = strstr(p, "ktool warntest: stack=")) != NULL) {
		last = p;
		p++;
	}
	if (!last)
		return 0;
	last += strlen("ktool warntest: stack=");
	sscanf(last, "%lx", &val);
	return val;
}

int main(int argc, char **argv)
{
	int n = (argc > 1) ? atoi(argv[1]) : 6;
	int i;
	unsigned long prev = 0;
	int repeat = 0;

	if (n < 2 || n > 40)
		n = 6;
	printf("=== kstack reuse test, %d rounds ===\n", n);

	for (i = 0; i < n; i++) {
		struct slot s;
		pthread_t th;

		memset(&s, 0, sizeof(s));
		g_serial++;
		if (pthread_create(&th, NULL, worker, &s) != 0) {
			printf("round %d: pthread_create failed\n", i);
			continue;
		}
		pthread_join(th, NULL);
		usleep(120000);		/* 等 WARN 落盘 */

		s.kstack = last_kstack();
		printf("round %d: thread=%08lx kstack=%08lx %s\n", i,
		       (unsigned long)s.tid, s.kstack,
		       (prev && s.kstack == prev) ? "<== SAME as prev" : "");
		if (prev && s.kstack == prev)
			repeat++;
		prev = s.kstack;
		usleep(80000);
	}

	printf("=== consecutive repeats: %d/%d ===\n", repeat, n - 1);
	printf("=== thread stacks freed then re-allocated: %s ===\n",
	       repeat > 0 ? "YES (reuse likely)" : "NO (reuse unproven)");
	return 0;
}
