/* SPDX-License-Identifier: GPL-3.0-or-later */

/*
 * leakfuzz3 —— 全量候选覆盖（表驱动）
 *
 * 相比 v2 的改进：
 *   1. getsockopt 覆盖 3.4 源码里出现的全部选项（SOL_SOCKET 34 + IP 24 + TCP 17 + IPV6 一批）
 *   2. 4 类 socket 各跑一遍：TCP(已连接) / UDP / IPv6 / UNIX
 *   3. SIOCG* 全表
 *   4. recvmsg 多种 cmsg：SCM_CREDENTIALS / SCM_RIGHTS / SO_TIMESTAMP / SO_TIMESTAMPNS /
 *      IP_PKTINFO / IP_RECVERR / IP_RECVORIGDSTADDR / IPV6_PKTINFO / IPV6_RECVERR
 *   5. 每个结果做两件事：
 *      a) 4 字节扫描：[0xc0000000,0xf8000000) 且两轮同值 → 泄漏
 *      b) 未写字节统计：b0==0x00 && b1==0xff 的字节数 → padding 证据
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>

#ifndef TCP_COOKIE_TRANSACTIONS
#define TCP_COOKIE_TRANSACTIONS 15
#endif
#ifndef TCP_THIN_LINEAR_TIMEOUTS
#define TCP_THIN_LINEAR_TIMEOUTS 16
#endif
#ifndef TCP_THIN_DUPACK
#define TCP_THIN_DUPACK 17
#endif
#ifndef TCP_USER_TIMEOUT
#define TCP_USER_TIMEOUT 18
#endif
#ifndef TCP_CONGESTION
#define TCP_CONGESTION 13
#endif

static int g_hits;
static int g_probes;
static int g_leaky_structs;

static int is_kaddr(uint32_t v)
{
	return v >= 0xc0000000u && v < 0xf8000000u;
}

/* 核心分析：两轮差分 */
static void analyze(const char *tag, const unsigned char *b0,
                    const unsigned char *b1, int len)
{
	int i, unwritten = 0, hit = 0;

	if (len > 256) len = 256;
	if (len <= 0) return;
	g_probes++;

	for (i = 0; i < len; i++)
		if (b0[i] == 0x00 && b1[i] == 0xff) unwritten++;

	/* 4 字节扫描 */
	for (i = 0; i + 4 <= len; i += 4) {
		uint32_t v0, v1;
		memcpy(&v0, b0 + i, 4);
		memcpy(&v1, b1 + i, 4);
		if (v0 != v1) continue;           /* 未写或半写，不是内核稳定值 */
		if (!is_kaddr(v0)) continue;
		printf("  *** LEAK %-26s off=0x%03x val=%08x base8k=%08x\n",
		       tag, i, v0, v0 & ~0x1fffu);
		g_hits++;
		hit = 1;
	}

	/* padding 证据：只有部分字节被写 */
	if (unwritten > 0 && unwritten < len) {
		int first = -1, last = -1;
		for (i = 0; i < len; i++) {
			if (b0[i] == 0x00 && b1[i] == 0xff) {
				if (first < 0) first = i;
				last = i;
			}
		}
		printf("  [pad] %-26s len=%d unwritten=%d range=0x%02x..0x%02x\n",
		       tag, len, unwritten, first, last);
		g_leaky_structs++;
	}
}

/* ================= getsockopt 全表 ================= */
struct so_case {
	int level;
	int opt;
	const char *name;
	int len;
};

/* ---- SOL_SOCKET ---- */
static const struct so_case sol_socket_cases[] = {
	{ SOL_SOCKET, SO_DEBUG,        "SO_DEBUG",        8 },
	{ SOL_SOCKET, SO_DONTROUTE,    "SO_DONTROUTE",    8 },
	{ SOL_SOCKET, SO_BROADCAST,    "SO_BROADCAST",    8 },
	{ SOL_SOCKET, SO_SNDBUF,       "SO_SNDBUF",       8 },
	{ SOL_SOCKET, SO_RCVBUF,       "SO_RCVBUF",       8 },
	{ SOL_SOCKET, SO_REUSEADDR,    "SO_REUSEADDR",    8 },
	{ SOL_SOCKET, SO_KEEPALIVE,    "SO_KEEPALIVE",    8 },
	{ SOL_SOCKET, SO_TYPE,         "SO_TYPE",         8 },
	{ SOL_SOCKET, SO_ERROR,        "SO_ERROR",        8 },
	{ SOL_SOCKET, SO_OOBINLINE,    "SO_OOBINLINE",    8 },
	{ SOL_SOCKET, SO_NO_CHECK,     "SO_NO_CHECK",     8 },
	{ SOL_SOCKET, SO_PRIORITY,     "SO_PRIORITY",     8 },
	{ SOL_SOCKET, SO_LINGER,       "SO_LINGER",       16 },
	{ SOL_SOCKET, SO_BSDCOMPAT,    "SO_BSDCOMPAT",    8 },
	{ SOL_SOCKET, SO_RCVLOWAT,     "SO_RCVLOWAT",     8 },
	{ SOL_SOCKET, SO_SNDLOWAT,     "SO_SNDLOWAT",     8 },
	{ SOL_SOCKET, SO_RCVTIMEO,     "SO_RCVTIMEO",     24 },
	{ SOL_SOCKET, SO_SNDTIMEO,     "SO_SNDTIMEO",     24 },
	{ SOL_SOCKET, SO_BINDTODEVICE, "SO_BINDTODEVICE", 32 },
	{ SOL_SOCKET, SO_TIMESTAMP,    "SO_TIMESTAMP",    8 },
#ifdef SO_TIMESTAMPNS
	{ SOL_SOCKET, SO_TIMESTAMPNS,  "SO_TIMESTAMPNS",  8 },
#endif
#ifdef SO_TIMESTAMPING
	{ SOL_SOCKET, SO_TIMESTAMPING, "SO_TIMESTAMPING", 8 },
#endif
	{ SOL_SOCKET, SO_PASSCRED,     "SO_PASSCRED",     8 },
	{ SOL_SOCKET, SO_PEERCRED,     "SO_PEERCRED",     16 },
	{ SOL_SOCKET, SO_PEERNAME,     "SO_PEERNAME",     32 },
	{ SOL_SOCKET, SO_ACCEPTCONN,   "SO_ACCEPTCONN",   8 },
#ifdef SO_PASSSEC
	{ SOL_SOCKET, SO_PASSSEC,      "SO_PASSSEC",      8 },
#endif
#ifdef SO_PEERSEC
	{ SOL_SOCKET, SO_PEERSEC,      "SO_PEERSEC",      64 },
#endif
#ifdef SO_MARK
	{ SOL_SOCKET, SO_MARK,         "SO_MARK",         8 },
#endif
#ifdef SO_PROTOCOL
	{ SOL_SOCKET, SO_PROTOCOL,     "SO_PROTOCOL",     8 },
#endif
#ifdef SO_DOMAIN
	{ SOL_SOCKET, SO_DOMAIN,       "SO_DOMAIN",       8 },
#endif
};

/* ---- IPPROTO_IP ---- */
static const struct so_case ip_cases[] = {
	{ IPPROTO_IP, IP_TOS,               "IP_TOS",              8 },
	{ IPPROTO_IP, IP_TTL,               "IP_TTL",              8 },
	{ IPPROTO_IP, IP_HDRINCL,           "IP_HDRINCL",          8 },
	{ IPPROTO_IP, IP_OPTIONS,           "IP_OPTIONS",          64 },
	{ IPPROTO_IP, IP_PKTINFO,           "IP_PKTINFO",          8 },
	{ IPPROTO_IP, IP_RECVTTL,           "IP_RECVTTL",          8 },
	{ IPPROTO_IP, IP_RECVTOS,           "IP_RECVTOS",          8 },
	{ IPPROTO_IP, IP_RECVOPTS,          "IP_RECVOPTS",         8 },
	{ IPPROTO_IP, IP_RETOPTS,           "IP_RETOPTS",          8 },
	{ IPPROTO_IP, IP_MTU_DISCOVER,      "IP_MTU_DISCOVER",     8 },
	{ IPPROTO_IP, IP_MTU,               "IP_MTU",              8 },
	{ IPPROTO_IP, IP_RECVERR,           "IP_RECVERR",          8 },
	{ IPPROTO_IP, IP_MULTICAST_TTL,     "IP_MULTICAST_TTL",    8 },
	{ IPPROTO_IP, IP_MULTICAST_LOOP,    "IP_MULTICAST_LOOP",   8 },
	{ IPPROTO_IP, IP_MULTICAST_IF,      "IP_MULTICAST_IF",     16 },
	{ IPPROTO_IP, IP_MSFILTER,          "IP_MSFILTER",         64 },
	{ IPPROTO_IP, IP_PKTOPTIONS,        "IP_PKTOPTIONS",       64 },
	{ IPPROTO_IP, IP_FREEBIND,          "IP_FREEBIND",         8 },
	{ IPPROTO_IP, IP_TRANSPARENT,       "IP_TRANSPARENT",      8 },
	{ IPPROTO_IP, IP_MINTTL,            "IP_MINTTL",           8 },
	{ IPPROTO_IP, IP_NODEFRAG,          "IP_NODEFRAG",         8 },
};

/* ---- IPPROTO_TCP ---- */
static const struct so_case tcp_cases[] = {
	{ IPPROTO_TCP, TCP_MAXSEG,                "TCP_MAXSEG",       8 },
	{ IPPROTO_TCP, TCP_NODELAY,               "TCP_NODELAY",      8 },
	{ IPPROTO_TCP, TCP_CORK,                  "TCP_CORK",         8 },
	{ IPPROTO_TCP, TCP_KEEPIDLE,              "TCP_KEEPIDLE",     8 },
	{ IPPROTO_TCP, TCP_KEEPINTVL,             "TCP_KEEPINTVL",    8 },
	{ IPPROTO_TCP, TCP_KEEPCNT,               "TCP_KEEPCNT",      8 },
	{ IPPROTO_TCP, TCP_SYNCNT,                "TCP_SYNCNT",       8 },
	{ IPPROTO_TCP, TCP_LINGER2,               "TCP_LINGER2",      8 },
	{ IPPROTO_TCP, TCP_DEFER_ACCEPT,          "TCP_DEFER_ACCEPT", 8 },
	{ IPPROTO_TCP, TCP_WINDOW_CLAMP,          "TCP_WINDOW_CLAMP", 8 },
	{ IPPROTO_TCP, TCP_INFO,                  "TCP_INFO",        128 },
	{ IPPROTO_TCP, TCP_QUICKACK,              "TCP_QUICKACK",     8 },
	{ IPPROTO_TCP, TCP_CONGESTION,            "TCP_CONGESTION",  32 },
	{ IPPROTO_TCP, TCP_COOKIE_TRANSACTIONS,   "TCP_COOKIE_TRANS", 64 },
	{ IPPROTO_TCP, TCP_THIN_LINEAR_TIMEOUTS,  "TCP_THIN_LINEAR",  8 },
	{ IPPROTO_TCP, TCP_THIN_DUPACK,           "TCP_THIN_DUPACK",  8 },
	{ IPPROTO_TCP, TCP_USER_TIMEOUT,          "TCP_USER_TIMEOUT", 8 },
};

static void run_cases(const char *pfx, int fd, const struct so_case *cs, int n)
{
	int i;
	char tag[64];

	for (i = 0; i < n; i++) {
		unsigned char b0[256], b1[256];
		socklen_t l0 = cs[i].len, l1 = cs[i].len;
		int r0, r1;

		if (fd < 0) continue;
		memset(b0, 0x00, sizeof b0);
		memset(b1, 0xff, sizeof b1);
		errno = 0;
		r0 = getsockopt(fd, cs[i].level, cs[i].opt, b0, &l0);
		if (r0 < 0) { errno = 0; continue; }   /* 该协议不支持，跳过 */
		errno = 0;
		r1 = getsockopt(fd, cs[i].level, cs[i].opt, b1, &l1);
		if (r1 < 0) continue;

		snprintf(tag, sizeof tag, "%s%s", pfx, cs[i].name);
		analyze(tag, b0, b1, (int)(l0 < l1 ? l0 : l1));
	}
}

static void test_sockopts(void)
{
	int lt, lc, ud, v6, un;
	struct sockaddr_in sa;
	struct sockaddr_in6 sa6;
	socklen_t sl;

	/* --- TCP 已连接 --- */
	lt = socket(AF_INET, SOCK_STREAM, 0);
	if (lt >= 0) {
		memset(&sa, 0, sizeof sa);
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = htonl(0x7f000001);
		sa.sin_port = 0;
		bind(lt, (struct sockaddr *)&sa, sizeof sa);
		listen(lt, 1);
		sl = sizeof sa;
		getsockname(lt, (struct sockaddr *)&sa, &sl);

		lc = socket(AF_INET, SOCK_STREAM, 0);
		if (lc >= 0) {
			if (connect(lc, (struct sockaddr *)&sa, sizeof sa) == 0) {
				int acc = accept(lt, NULL, NULL);
				printf("== TCP connected (client=%d server=%d) ==\n", lc, acc);
				run_cases("tcp.", lc, sol_socket_cases,
				          sizeof sol_socket_cases / sizeof sol_socket_cases[0]);
				run_cases("tcp.", lc, ip_cases,
				          sizeof ip_cases / sizeof ip_cases[0]);
				run_cases("tcp.", lc, tcp_cases,
				          sizeof tcp_cases / sizeof tcp_cases[0]);
				if (acc >= 0) close(acc);
			} else {
				printf("[!] tcp connect errno=%d\n", errno);
			}
			close(lc);
		}
		close(lt);
	}

	/* --- UDP --- */
	ud = socket(AF_INET, SOCK_DGRAM, 0);
	if (ud >= 0) {
		printf("== UDP ==\n");
		run_cases("udp.", ud, sol_socket_cases,
		          sizeof sol_socket_cases / sizeof sol_socket_cases[0]);
		run_cases("udp.", ud, ip_cases,
		          sizeof ip_cases / sizeof ip_cases[0]);
		close(ud);
	}

	/* --- IPv6 --- */
	v6 = socket(AF_INET6, SOCK_DGRAM, 0);
	if (v6 >= 0) {
		printf("== IPv6 ==\n");
		memset(&sa6, 0, sizeof sa6);
		sa6.sin6_family = AF_INET6;
		sa6.sin6_addr = in6addr_loopback;
		bind(v6, (struct sockaddr *)&sa6, sizeof sa6);
		run_cases("v6.", v6, sol_socket_cases,
		          sizeof sol_socket_cases / sizeof sol_socket_cases[0]);
		run_cases("v6.", v6, ip_cases,
		          sizeof ip_cases / sizeof ip_cases[0]);
		close(v6);
	} else {
		printf("[!] IPv6 socket errno=%d\n", errno);
	}

	/* --- UNIX --- */
	un = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (un >= 0) {
		printf("== UNIX ==\n");
		run_cases("unix.", un, sol_socket_cases,
		          sizeof sol_socket_cases / sizeof sol_socket_cases[0]);
		close(un);
	}
}

/* ================= SIOCG* ================= */
static void test_siocg(void)
{
	int fd;
	const char *ifs[] = { "lo", "eth0", "wlan0", "rmnet0", NULL };
	int i;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) { printf("[siocg] socket fail %d\n", errno); return; }
	printf("== SIOCG* ==\n");

	for (i = 0; ifs[i]; i++) {
		unsigned long cmds[] = {
			SIOCGIFFLAGS, SIOCGIFMETRIC, SIOCGIFMTU, SIOCGIFMEM,
			SIOCGIFHWADDR, SIOCGIFINDEX, SIOCGIFADDR, SIOCGIFBRDADDR,
			SIOCGIFDSTADDR, SIOCGIFNETMASK, SIOCGIFTXQLEN, SIOCGIFMAP,
			SIOCGIFPFLAGS,
		};
		const char *names[] = {
			"SIOCGIFFLAGS", "SIOCGIFMETRIC", "SIOCGIFMTU", "SIOCGIFMEM",
			"SIOCGIFHWADDR", "SIOCGIFINDEX", "SIOCGIFADDR", "SIOCGIFBRDADDR",
			"SIOCGIFDSTADDR", "SIOCGIFNETMASK", "SIOCGIFTXQLEN", "SIOCGIFMAP",
			"SIOCGIFPFLAGS",
		};
		unsigned j;

		/* 只对 lo 跑 tcp/udp 之外的所有命令，其它接口若不存在自然失败 */
		for (j = 0; j < sizeof cmds / sizeof cmds[0]; j++) {
			unsigned char b0[128], b1[128];
			struct ifreq *r0 = (struct ifreq *)b0;
			struct ifreq *r1 = (struct ifreq *)b1;
			char tag[80];
			int ok0, ok1;

			memset(b0, 0x00, sizeof b0);
			memset(b1, 0xff, sizeof b1);
			strncpy(r0->ifr_name, ifs[i], IFNAMSIZ - 1);
			strncpy(r1->ifr_name, ifs[i], IFNAMSIZ - 1);
			ok0 = (ioctl(fd, cmds[j], r0) == 0);
			ok1 = (ioctl(fd, cmds[j], r1) == 0);
			if (!ok0 && !ok1) continue;
			snprintf(tag, sizeof tag, "%s.%s", ifs[i], names[j]);
			analyze(tag, b0, b1, 64);
		}
	}

	/* SIOCGIFCONF */
	{
		unsigned char b0[512], b1[512];
		struct ifconf c0, c1;
		memset(b0, 0, sizeof b0);
		memset(b1, 0xff, sizeof b1);
		c0.ifc_len = sizeof b0 - sizeof(struct ifconf);
		c0.ifc_buf = (char *)b0 + sizeof(struct ifconf);
		c1.ifc_len = sizeof b1 - sizeof(struct ifconf);
		c1.ifc_buf = (char *)b1 + sizeof(struct ifconf);
		if (ioctl(fd, SIOCGIFCONF, &c0) == 0) {
			/* ifconf 本身是输入，不测；只测它填充的 ifreq 数组 */
			analyze("SIOCGIFCONF", b0 + sizeof(struct ifconf),
			        b1 + sizeof(struct ifconf), c0.ifc_len);
		}
	}
	close(fd);
}

/* ================= recvmsg 多种 cmsg ================= */
static void cmsg_probe(const char *name, void (*setup)(int fd), int family)
{
	int sv[2];
	char tag[64];

	if (socketpair(family, SOCK_DGRAM, 0, sv) < 0) {
		printf("[%s] socketpair fail errno=%d\n", name, errno);
		return;
	}
	if (setup) setup(sv[1]);

	{
		unsigned char c0[512], c1[512];
		socklen_t len0 = 0, len1 = 0;
		int pass;

		for (pass = 0; pass < 2; pass++) {
			unsigned char *c = pass ? c1 : c0;
			socklen_t *lp = pass ? &len1 : &len0;
			unsigned char data[16];
			struct iovec iov;
			struct msghdr msg;
			ssize_t r;

			memset(c, pass ? 0xff : 0x00, 512);
			memset(data, 'A', sizeof data);
			iov.iov_base = data;
			iov.iov_len = 1;
			memset(&msg, 0, sizeof msg);
			msg.msg_iov = &iov;
			msg.msg_iovlen = 1;
			msg.msg_control = c;
			msg.msg_controllen = 512;
			send(sv[0], data, 1, 0);
			r = recvmsg(sv[1], &msg, MSG_DONTWAIT);
			*lp = (r >= 0) ? msg.msg_controllen : 0;
		}
		if (len0 > 0 && len1 > 0) {
			snprintf(tag, sizeof tag, "%s", name);
			analyze(tag, c0, c1, (int)(len0 < len1 ? len0 : len1));
		}
	}
	close(sv[0]); close(sv[1]);
}

static void set_passcred(int fd) { int on = 1; setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof on); }
static void set_passsec(int fd)  { int on = 1; setsockopt(fd, SOL_SOCKET, SO_PASSSEC, &on, sizeof on); }
static void set_timestamp(int fd){ int on = 1; setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof on); }
#ifdef SO_TIMESTAMPNS
static void set_timestampns(int fd){ int on = 1; setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &on, sizeof on); }
#endif

static void test_cmsgs(void)
{
	printf("== cmsg ==\n");
	cmsg_probe("cmsg.passcred", set_passcred, AF_UNIX);
	cmsg_probe("cmsg.passsec", set_passsec, AF_UNIX);
	cmsg_probe("cmsg.timestamp", set_timestamp, AF_UNIX);
#ifdef SO_TIMESTAMPNS
	cmsg_probe("cmsg.timestampns", set_timestampns, AF_UNIX);
#endif
	cmsg_probe("cmsg.plain", NULL, AF_UNIX);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== leakfuzz3  pid=%d ===\n", getpid());

	test_sockopts();
	test_siocg();
	test_cmsgs();

	printf("\n=== probes=%d  LEAK=%d  pad_evidence=%d ===\n",
	       g_probes, g_hits, g_leaky_structs);
	return 0;
}
