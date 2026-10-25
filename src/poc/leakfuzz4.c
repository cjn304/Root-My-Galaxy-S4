/*
 * leakfuzz4 —— 补齐用户点名的候选
 *
 * 覆盖：
 *   A. IPC_STAT / IPC_INFO（msgctl / semctl / shmctl 三族 × 两种命令）
 *   B. getdents64（/proc /sys /sys/kernel/debug /dev /data /system 等多个文件系统）
 *   C. statfs / fstatfs（各挂载点）
 *   D. 其它 syscall：sysinfo / getrusage / times / getcpu / clock_gettime(各 clock) /
 *      timerfd_gettime / eventfd read / inotify read / getxattr / listxattr
 *
 * 判据同 v3：0x00/0xFF 双跑差分 + 内核地址扫描 + 未写字节统计。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/times.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/xattr.h>

static int g_hits;
static int g_probes;
static int g_pad;

static int is_kaddr(uint32_t v)
{
	return v >= 0xc0000000u && v < 0xf8000000u;
}

static void analyze(const char *tag, const unsigned char *b0,
                    const unsigned char *b1, int len)
{
	int i, unwritten = 0;

	if (len > 512) len = 512;
	if (len <= 0) return;
	g_probes++;

	for (i = 0; i < len; i++)
		if (b0[i] == 0x00 && b1[i] == 0xff) unwritten++;

	for (i = 0; i + 4 <= len; i += 4) {
		uint32_t v0, v1;
		memcpy(&v0, b0 + i, 4);
		memcpy(&v1, b1 + i, 4);
		if (v0 != v1) continue;
		if (!is_kaddr(v0)) continue;
		/* 过滤明显是 MAC/IP 的低位组合：高字节 < 0x80 的视为数据 */
		if ((v0 >> 24) < 0x80) continue;
		printf("  *** LEAK %-30s off=0x%03x val=%08x base8k=%08x\n",
		       tag, i, v0, v0 & ~0x1fffu);
		g_hits++;
	}
	if (unwritten > 0 && unwritten < len) {
		int first = -1, last = -1;
		for (i = 0; i < len; i++) {
			if (b0[i] == 0x00 && b1[i] == 0xff) {
				if (first < 0) first = i;
				last = i;
			}
		}
		printf("  [pad] %-30s len=%d unwritten=%d range=0x%02x..0x%02x\n",
		       tag, len, unwritten, first, last);
		g_pad++;
	}
}

/* 通用双跑：fn 返回值 = 实际输出长度，<0 表示失败 */
typedef long (*dual_fn)(unsigned char *buf, int cap, void *ctx);

static void dual(const char *tag, dual_fn fn, void *ctx, int cap)
{
	unsigned char b0[1024], b1[1024];
	long l0, l1;

	if (cap > (int)sizeof(b0)) cap = sizeof(b0);
	memset(b0, 0x00, sizeof b0);
	memset(b1, 0xff, sizeof b1);
	l0 = fn(b0, cap, ctx);
	if (l0 < 0) return;
	l1 = fn(b1, cap, ctx);
	if (l1 < 0) return;
	analyze(tag, b0, b1, (int)(l0 < l1 ? l0 : l1));
}

/* ---------------- A. IPC ---------------- */
struct ipc_ctx { int id; int cmd; };

static long fn_msgctl(unsigned char *b, int cap, void *p)
{
	struct ipc_ctx *c = p;
	(void)cap;
	errno = 0;
	if (msgctl(c->id, c->cmd, (struct msqid_ds *)b) < 0) return -1;
	return (c->cmd == IPC_STAT) ? (long)sizeof(struct msqid_ds) : 256;
}

static long fn_semctl(unsigned char *b, int cap, void *p)
{
	struct ipc_ctx *c = p;
	(void)cap;
	errno = 0;
	if (semctl(c->id, 0, c->cmd, b) < 0) return -1;
	return (c->cmd == IPC_STAT) ? (long)sizeof(struct semid_ds) : 256;
}

static long fn_shmctl(unsigned char *b, int cap, void *p)
{
	struct ipc_ctx *c = p;
	(void)cap;
	errno = 0;
	if (shmctl(c->id, c->cmd, (struct shmid_ds *)b) < 0) return -1;
	return (c->cmd == IPC_STAT) ? (long)sizeof(struct shmid_ds) : 256;
}

static void test_ipc(void)
{
	int id;
	struct ipc_ctx c;
	int cmds[] = { IPC_STAT, IPC_INFO };
	const char *cn[] = { "STAT", "INFO" };
	int i;

	printf("== IPC ==\n");

	id = msgget(IPC_PRIVATE, 0666);
	if (id >= 0) {
		for (i = 0; i < 2; i++) {
			char tag[64];
			c.id = id; c.cmd = cmds[i];
			snprintf(tag, sizeof tag, "msgctl.%s", cn[i]);
			dual(tag, fn_msgctl, &c, 256);
		}
		msgctl(id, IPC_RMID, NULL);
	} else printf("[ipc] msgget errno=%d\n", errno);

	id = semget(IPC_PRIVATE, 1, 0666);
	if (id >= 0) {
		for (i = 0; i < 2; i++) {
			char tag[64];
			c.id = id; c.cmd = cmds[i];
			snprintf(tag, sizeof tag, "semctl.%s", cn[i]);
			dual(tag, fn_semctl, &c, 256);
		}
		semctl(id, 0, IPC_RMID, 0);
	} else printf("[ipc] semget errno=%d\n", errno);

	id = shmget(IPC_PRIVATE, 4096, 0666);
	if (id >= 0) {
		for (i = 0; i < 2; i++) {
			char tag[64];
			c.id = id; c.cmd = cmds[i];
			snprintf(tag, sizeof tag, "shmctl.%s", cn[i]);
			dual(tag, fn_shmctl, &c, 256);
		}
		shmctl(id, IPC_RMID, NULL);
	} else printf("[ipc] shmget errno=%d\n", errno);
}

/* ---------------- B. getdents64 ---------------- */
struct dir_ctx { const char *path; };

static long fn_getdents(unsigned char *b, int cap, void *p)
{
	struct dir_ctx *c = p;
	int fd;
	long r;

	fd = open(c->path, O_RDONLY | O_DIRECTORY);
	if (fd < 0) return -1;
	r = syscall(SYS_getdents64, fd, b, (size_t)cap);
	close(fd);
	return (r > 0) ? r : -1;
}

static void test_getdents(void)
{
	const char *dirs[] = {
		"/proc", "/proc/sys", "/sys", "/sys/kernel/debug",
		"/dev", "/data", "/system", "/data/local/tmp",
		"/proc/self", "/sys/class", NULL
	};
	int i;
	printf("== getdents64 ==\n");
	for (i = 0; dirs[i]; i++) {
		struct dir_ctx c = { dirs[i] };
		char tag[64];
		snprintf(tag, sizeof tag, "getdents%s", dirs[i]);
		dual(tag, fn_getdents, &c, 1024);
	}
}

/* ---------------- C. statfs ---------------- */
static long fn_statfs(unsigned char *b, int cap, void *p)
{
	const char *path = p;
	(void)cap;
	errno = 0;
	if (statfs(path, (struct statfs *)b) < 0) return -1;
	return sizeof(struct statfs);
}

static void test_statfs(void)
{
	const char *paths[] = {
		"/", "/proc", "/sys", "/data", "/cache", "/system",
		"/dev", "/data/local/tmp", "/mnt/asec", NULL
	};
	int i;
	printf("== statfs ==\n");
	for (i = 0; paths[i]; i++) {
		char tag[64];
		snprintf(tag, sizeof tag, "statfs%s", paths[i]);
		dual(tag, fn_statfs, (void *)paths[i], sizeof(struct statfs));
	}
}

/* ---------------- D. 其它 syscall ---------------- */
static long fn_sysinfo(unsigned char *b, int cap, void *p)
{
	(void)cap; (void)p;
	if (syscall(SYS_sysinfo, b) < 0) return -1;
	return sizeof(struct sysinfo);
}

static long fn_getrusage(unsigned char *b, int cap, void *p)
{
	int who = (int)(long)p;
	(void)cap;
	if (getrusage(who, (struct rusage *)b) < 0) return -1;
	return sizeof(struct rusage);
}

static long fn_times(unsigned char *b, int cap, void *p)
{
	(void)cap; (void)p;
	if (times((struct tms *)b) == (clock_t)-1) return -1;
	return sizeof(struct tms);
}

struct clock_ctx { clockid_t id; };

static long fn_clock_gettime(unsigned char *b, int cap, void *p)
{
	struct clock_ctx *c = p;
	(void)cap;
	if (clock_gettime(c->id, (struct timespec *)b) < 0) return -1;
	return sizeof(struct timespec);
}

static long fn_timerfd_gettime(unsigned char *b, int cap, void *p)
{
	int fd = (int)(long)p;
	(void)cap;
	if (timerfd_gettime(fd, (struct itimerspec *)b) < 0) return -1;
	return sizeof(struct itimerspec);
}

static long fn_getcpu(unsigned char *b, int cap, void *p)
{
	(void)cap; (void)p;
	if (syscall(SYS_getcpu, (unsigned *)b, (unsigned *)(b + 4), NULL) < 0)
		return -1;
	return 8;
}

struct path_ctx { const char *path; int which; };  /* which: 0=list, 1=get */

static long fn_xattr(unsigned char *b, int cap, void *p)
{
	struct path_ctx *c = p;
	if (c->which == 0) {
		ssize_t r = listxattr(c->path, (char *)b, cap);
		return (r > 0) ? r : -1;
	} else {
		ssize_t r = getxattr(c->path, "security.selinux", (char *)b, cap);
		return (r > 0) ? r : -1;
	}
}

static void test_misc(void)
{
	struct clock_ctx cc;
	int fd;

	printf("== misc syscalls ==\n");

	dual("sysinfo", fn_sysinfo, NULL, sizeof(struct sysinfo));
	dual("getrusage.SELF", fn_getrusage, (void *)RUSAGE_SELF, sizeof(struct rusage));
	dual("getrusage.CHILDREN", fn_getrusage, (void *)RUSAGE_CHILDREN, sizeof(struct rusage));
#ifdef RUSAGE_THREAD
	dual("getrusage.THREAD", fn_getrusage, (void *)RUSAGE_THREAD, sizeof(struct rusage));
#endif
	dual("times", fn_times, NULL, sizeof(struct tms));
	dual("getcpu", fn_getcpu, NULL, 8);

	{
		clockid_t ids[] = { CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
		                    CLOCK_THREAD_CPUTIME_ID, CLOCK_REALTIME_COARSE,
		                    CLOCK_MONOTONIC_COARSE };
		const char *nm[] = { "REALTIME", "MONOTONIC", "PROC_CPU", "THREAD_CPU",
		                     "REALTIME_COARSE", "MONOTONIC_COARSE" };
		int i;
		for (i = 0; i < 6; i++) {
			char tag[64];
			cc.id = ids[i];
			snprintf(tag, sizeof tag, "clock_gettime.%s", nm[i]);
			dual(tag, fn_clock_gettime, &cc, sizeof(struct timespec));
		}
	}

	fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (fd >= 0) {
		struct itimerspec its;
		memset(&its, 0, sizeof its);
		its.it_value.tv_sec = 100;
		timerfd_settime(fd, 0, &its, NULL);
		dual("timerfd_gettime", fn_timerfd_gettime, (void *)(long)fd,
		     sizeof(struct itimerspec));
		close(fd);
	} else printf("[misc] timerfd_create errno=%d\n", errno);

	{
		struct path_ctx pc;
		pc.path = "/system"; pc.which = 0;
		dual("listxattr./system", fn_xattr, &pc, 256);
		pc.path = "/system/bin/sh"; pc.which = 1;
		dual("getxattr.selinux", fn_xattr, &pc, 256);
	}
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== leakfuzz4  pid=%d ===\n", getpid());

	test_ipc();
	test_getdents();
	test_statfs();
	test_misc();

	printf("\n=== probes=%d  LEAK=%d  pad_evidence=%d ===\n",
	       g_probes, g_hits, g_pad);
	return 0;
}
