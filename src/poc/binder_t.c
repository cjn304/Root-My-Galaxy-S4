/*
 * binder 回包延迟测量：
 *   N 个线程各发 1 条同步事务到 handle 0（每线程只能挂 1 条），
 *   然后主线程发自己的那条，用紧循环非阻塞读，测到「回包可见」的耗时。
 * 用法： bt <N>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <time.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define BINDER_WRITE_READ  0xc0186201UL
#define BINDER_VERSION     0xc0046209UL
#define BC_TRANSACTION     0x40286300UL

struct binder_write_read {
	int32_t  write_size, write_consumed;
	uint32_t write_buffer;
	int32_t  read_size, read_consumed;
	uint32_t read_buffer;
};
struct binder_transaction_data {
	union { uint32_t handle; uint32_t ptr; } target;
	uint32_t cookie, code, flags;
	int32_t  sender_pid;
	uint32_t sender_euid, data_size, offsets_size;
	union { struct { uint32_t buffer, offsets; } ptr; uint8_t buf[8]; } data;
};

static int g_fd = -1;
static volatile int g_start = 0;
static volatile long g_sent = 0;

static void pin(int c){ cpu_set_t s; CPU_ZERO(&s); CPU_SET(c,&s); sched_setaffinity(0,sizeof s,&s); }

static int bwr(void *wb, int ws, void *rb, int rs, int *rc)
{
	struct binder_write_read b;
	int r;
	memset(&b, 0, sizeof b);
	b.write_size = ws; b.write_buffer = (uint32_t)(uintptr_t)wb;
	b.read_size  = rs; b.read_buffer  = (uint32_t)(uintptr_t)rb;
	r = ioctl(g_fd, BINDER_WRITE_READ, &b);
	if (rc) *rc = b.read_consumed;
	return r;
}

static int send_txn(void)
{
	uint8_t wb[4 + sizeof(struct binder_transaction_data)];
	struct binder_transaction_data *tr = (void *)(wb + 4);
	memset(wb, 0, sizeof wb);
	*(uint32_t *)wb = BC_TRANSACTION;
	memset(tr, 0, sizeof *tr);
	tr->target.handle = 0;
	return bwr(wb, sizeof wb, NULL, 0, NULL);
}

static void *worker(void *a)
{
	long id = (long)a;
	pin(1 + (int)(id % 3));
	while (!g_start) __sync_synchronize();
	send_txn();
	__sync_fetch_and_add(&g_sent, 1);
	return NULL;
}

static long now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000L + ts.tv_nsec / 1000;
}

int main(int argc, char **argv)
{
	int n = (argc > 1) ? atoi(argv[1]) : 0;
	int i, rc;
	uint8_t rbuf[256];
	static pthread_t th[256];
	long t0, t1;
	int iters = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	pin(0);
	printf("=== bt flood=%d pid=%d ===\n", n, getpid());

	g_fd = open("/dev/binder", O_RDWR | O_NONBLOCK);
	if (g_fd < 0) { printf("open errno=%d\n", errno); return 1; }
	mmap(NULL, 0x100000, PROT_READ, MAP_PRIVATE, g_fd, 0);
	int ver = -1; ioctl(g_fd, BINDER_VERSION, &ver);
	printf("ver=%d\n", ver);

	if (n > 0) {
		int m = (n > 256) ? 256 : n;
		for (i = 0; i < m; i++) pthread_create(&th[i], NULL, worker, (void *)(long)i);
		usleep(3000);
		g_start = 1;
		long g = 0;
		while (g_sent < m && g++ < 200000000L) ;
		printf("flood sent=%ld\n", g_sent);
	}

	/* 主线程：发 + 紧循环轮询回包 */
	t0 = now_us();
	send_txn();
	t1 = now_us();
	for (;;) {
		rc = 0;
		bwr(NULL, 0, rbuf, 52, &rc);
		iters++;
		if (rc > 8) break;   /* 8 只是 NOOP+TRANSACTION_COMPLETE，>8 才是回包 */
		if (iters > 200000) break;
	}
	{
		long t2 = now_us();
		printf("send=%ld us  reply=%ld us  iters=%d rc=%d\n", t1 - t0, t2 - t1, iters, rc);
	}
	if (rc > 0) {
		printf("words:");
		for (i = 0; i + 4 <= rc && i < 20; i += 4) printf(" %08x", *(uint32_t*)(rbuf+i));
		printf("\n");
	}
	return 0;
}
