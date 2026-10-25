/*
 * leakfuzz2 —— padding 型内核栈泄漏探测
 *
 * 与 v1 的区别：v1 测的是「内核完全没写某个字段」；本版针对
 * 「内核写了结构体字段，但 padding 字节未初始化」——这是 3.4 时代最常见的泄漏。
 *
 * 方法：同一 ioctl 调两次，buffer 分别 0x00 / 0xFF 预填。
 *   - 两轮同值且落在内核区   → 内核稳定写入（可能是真泄漏）
 *   - 两轮同值但等于填充值   → 内核没写（不是泄漏）
 *   - 两轮不同               → 用户填充值被保留（不是泄漏）
 *
 * 覆盖：pty 的全部只读 TIOC*、一批 getsockopt、AF_NETLINK sockaddr、
 *       recvmsg + SO_PASSCRED（SCM_CREDENTIALS）。
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
#include <termios.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <netinet/tcp.h>

/* musl 未定义的传统 tty ioctl（ARM 值） */
#ifndef TIOCGETP
#define TIOCGETP 0x5408
#endif
#ifndef TIOCGETC
#define TIOCGETC 0x5412
#endif
#ifndef TIOCGLTC
#define TIOCGLTC 0x5414
#endif

#ifndef TCGETX
#define TCGETX 0x5432
#endif
#ifndef TIOCGPTN
#define TIOCGPTN 0x80045430
#endif
#ifndef TIOCGDEV
#define TIOCGDEV 0x80045432
#endif
#ifndef TIOCGSERIAL
#define TIOCGSERIAL 0x541E
#endif
#ifndef TIOCGICOUNT
#define TIOCGICOUNT 0x545D
#endif
#ifndef TIOCGPPSEV
#define TIOCGPPSEV 0x541F
#endif

static int g_hits;

static void scan_buf(const char *tag, const unsigned char *b, int len,
                     const unsigned char *ref, int fill)
{
	int i;
	for (i = 0; i + 4 <= len; i += 4) {
		uint32_t v;
		memcpy(&v, b + i, 4);
		if (v >= 0xc0000000u && v < 0xf8000000u) {
			/* 若是填充值本身，跳过 */
			if (fill == 0x00 && v == 0x00000000u) continue;
			if (fill == 0xff && v == 0xffffffffu) continue;
			printf("  HIT %-22s off=0x%03x val=%08x base8k=%08x\n",
			       tag, i, v, v & ~0x1fffu);
			g_hits++;
		}
	}
	(void)ref;
}

/* 对同一个 ioctl 做 0x00 / 0xFF 双跑差分 */
static void dual_ioctl(int fd, unsigned long cmd, const char *name, int len)
{
	unsigned char b0[256], b1[256];
	int r0, r1;

	if (len > (int)sizeof(b0)) len = sizeof(b0);
	memset(b0, 0x00, sizeof b0);
	memset(b1, 0xff, sizeof b1);

	errno = 0; r0 = ioctl(fd, cmd, b0);
	errno = 0; r1 = ioctl(fd, cmd, b1);

	printf("[%-20s] ret=%d/%d errno=%d/%d\n", name, r0, r1, errno, errno);
	if (r0 == 0 && r1 == 0) {
		scan_buf(name, b0, len, NULL, 0x00);
		scan_buf(name, b1, len, NULL, 0xff);
		/* 打印非零且非填充的字节布局，人工看 padding */
		{
			int i, shown = 0;
			printf("      layout: ");
			for (i = 0; i < len && shown < 24; i++) {
				if (b0[i] != 0x00 || b1[i] != 0xff) {
					printf("%02x:%02x/%02x ", i, b0[i], b1[i]);
					shown++;
				}
			}
			if (shown == 0) printf("(全为填充值，内核未写)");
			printf("\n");
		}
	}
}

/* ---------- pty 全套只读 ioctl ---------- */
static void test_pty(void)
{
	int mfd, sfd;
	char *sname = NULL;

	mfd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	if (mfd < 0) { printf("[pty] open ptmx fail errno=%d\n", errno); return; }

	if (grantpt(mfd) < 0) printf("[pty] grantpt errno=%d\n", errno);
	if (unlockpt(mfd) < 0) printf("[pty] unlockpt errno=%d\n", errno);
	if (ioctl(mfd, TIOCGPTN, &sfd) == 0) {
		char path[64];
		snprintf(path, sizeof path, "/dev/pts/%d", sfd);
		sfd = open(path, O_RDWR | O_NOCTTY);
		printf("[pty] master=%d slave=%s\n", mfd, path);
	} else {
		sfd = -1;
		printf("[pty] TIOCGPTN fail errno=%d\n", errno);
	}

	printf("=== master ioctls ===\n");
	dual_ioctl(mfd, TCGETS, "TCGETS", 64);
	dual_ioctl(mfd, TCGETA, "TCGETA", 64);
	dual_ioctl(mfd, TIOCGWINSZ, "TIOCGWINSZ", 8);
	dual_ioctl(mfd, TIOCGETP, "TIOCGETP", 16);
	dual_ioctl(mfd, TIOCGETC, "TIOCGETC", 16);
	dual_ioctl(mfd, TIOCGLTC, "TIOCGLTC", 16);
	dual_ioctl(mfd, TCGETX, "TCGETX", 32);
	dual_ioctl(mfd, TIOCGSERIAL, "TIOCGSERIAL", 96);
	dual_ioctl(mfd, TIOCGICOUNT, "TIOCGICOUNT", 64);
	dual_ioctl(mfd, TIOCGPPSEV, "TIOCGPPSEV", 32);
	dual_ioctl(mfd, TIOCGDEV, "TIOCGDEV", 8);
	dual_ioctl(mfd, TIOCMGET, "TIOCMGET", 8);
	dual_ioctl(mfd, FIONREAD, "FIONREAD", 8);
	dual_ioctl(mfd, TIOCGPTN, "TIOCGPTN", 8);
	dual_ioctl(mfd, TIOCGETD, "TIOCGETD", 8);
	dual_ioctl(mfd, TIOCGPGRP, "TIOCGPGRP", 8);
	dual_ioctl(mfd, TIOCGSID, "TIOCGSID", 8);

	if (sfd >= 0) {
		printf("=== slave ioctls ===\n");
		dual_ioctl(sfd, TCGETS, "s:TCGETS", 64);
		dual_ioctl(sfd, TIOCGWINSZ, "s:TIOCGWINSZ", 8);
		dual_ioctl(sfd, TIOCGSERIAL, "s:TIOCGSERIAL", 96);
		dual_ioctl(sfd, TIOCGICOUNT, "s:TIOCGICOUNT", 64);
		close(sfd);
	}
	close(mfd);
	(void)sname;
}

/* ---------- getsockopt ---------- */
static void one_sockopt(int fd, int level, int opt, const char *name, int len)
{
	unsigned char b0[256], b1[256];
	socklen_t l0 = len, l1 = len;
	int r0, r1;

	memset(b0, 0x00, sizeof b0);
	memset(b1, 0xff, sizeof b1);
	errno = 0; r0 = getsockopt(fd, level, opt, b0, &l0);
	errno = 0; r1 = getsockopt(fd, level, opt, b1, &l1);
	printf("[%-20s] ret=%d/%d len=%u/%u errno=%d\n", name, r0, r1,
	       (unsigned)l0, (unsigned)l1, errno);
	if (r0 == 0 && r1 == 0) {
		scan_buf(name, b0, l0, NULL, 0x00);
		scan_buf(name, b1, l1, NULL, 0xff);
		{
			int i, shown = 0;
			printf("      layout: ");
			for (i = 0; i < (int)l0 && shown < 24; i++) {
				if (b0[i] != 0x00 || b1[i] != 0xff) {
					printf("%02x:%02x/%02x ", i, b0[i], b1[i]);
					shown++;
				}
			}
			if (shown == 0) printf("(全为填充值)");
			printf("\n");
		}
	}
}

static void test_sockopts(void)
{
	int fd4, fd6, fdu;

	fd4 = socket(AF_INET, SOCK_STREAM, 0);
	if (fd4 >= 0) {
		struct sockaddr_in sa;
		memset(&sa, 0, sizeof sa);
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = htonl(0x7f000001);
		sa.sin_port = 0;
		bind(fd4, (struct sockaddr *)&sa, sizeof sa);
		listen(fd4, 1);

		one_sockopt(fd4, SOL_SOCKET, SO_LINGER,     "SO_LINGER", 16);
		one_sockopt(fd4, SOL_SOCKET, SO_RCVTIMEO,   "SO_RCVTIMEO", 24);
		one_sockopt(fd4, SOL_SOCKET, SO_SNDTIMEO,   "SO_SNDTIMEO", 24);
		one_sockopt(fd4, SOL_SOCKET, SO_TYPE,       "SO_TYPE", 8);
		one_sockopt(fd4, SOL_SOCKET, SO_ACCEPTCONN, "SO_ACCEPTCONN", 8);
		one_sockopt(fd4, SOL_SOCKET, SO_BINDTODEVICE,"SO_BINDTODEVICE", 32);
		one_sockopt(fd4, IPPROTO_IP, IP_MTU,        "IP_MTU", 8);
		one_sockopt(fd4, IPPROTO_IP, IP_TOS,        "IP_TOS", 8);
		one_sockopt(fd4, IPPROTO_IP, IP_TTL,        "IP_TTL", 8);
		one_sockopt(fd4, IPPROTO_IP, IP_OPTIONS,    "IP_OPTIONS", 64);
		one_sockopt(fd4, IPPROTO_TCP, TCP_NODELAY,  "TCP_NODELAY", 8);
		one_sockopt(fd4, IPPROTO_TCP, TCP_MAXSEG,   "TCP_MAXSEG", 8);
		one_sockopt(fd4, IPPROTO_TCP, TCP_INFO,     "TCP_INFO", 128);
		close(fd4);
	} else {
		printf("[sockopt] socket inet fail errno=%d\n", errno);
	}

	fd6 = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd6 >= 0) {
		one_sockopt(fd6, IPPROTO_IPV6, IPV6_MTU,      "IPV6_MTU", 8);
		one_sockopt(fd6, IPPROTO_IPV6, IPV6_UNICAST_HOPS, "IPV6_HOPS", 8);
		one_sockopt(fd6, IPPROTO_IPV6, IPV6_V6ONLY,   "IPV6_V6ONLY", 8);
		close(fd6);
	}

	fdu = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fdu >= 0) {
		one_sockopt(fdu, SOL_SOCKET, SO_PEERCRED, "SO_PEERCRED", 16);
		one_sockopt(fdu, SOL_SOCKET, SO_PEERNAME, "SO_PEERNAME", 32);

		close(fdu);
	}
}

/* ---------- AF_NETLINK 的 sockaddr_nl（nl_pad） ---------- */
static void test_netlink_name(void)
{
	int fd, fill;
	struct sockaddr_nl sa;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		printf("[netlink] socket fail errno=%d (%s)\n", errno, strerror(errno));
		return;
	}
	memset(&sa, 0, sizeof sa);
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0)
		printf("[netlink] bind errno=%d\n", errno);

	for (fill = 0; fill < 2; fill++) {
		unsigned char b[64];
		socklen_t l = sizeof b;
		memset(b, fill ? 0xff : 0x00, sizeof b);
		errno = 0;
		if (getsockname(fd, (struct sockaddr *)b, &l) == 0) {
			printf("[netlink_getsockname] fill=%02x len=%u\n",
			       fill ? 0xff : 0x00, (unsigned)l);
			scan_buf("netlink_name", b, (int)l, NULL, fill ? 0xff : 0x00);
		} else {
			printf("[netlink_getsockname] fail errno=%d\n", errno);
		}
	}
	close(fd);

	/* NETLINK_SOCK_DIAG 是否可建 */
	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
	printf("[netlink_sock_diag] fd=%d errno=%d (%s)\n", fd, errno,
	       fd < 0 ? strerror(errno) : "ok");
	if (fd >= 0) close(fd);
}

/* ---------- recvmsg + SO_PASSCRED（SCM_CREDENTIALS） ---------- */
static void test_scm_cred(void)
{
	int sv[2], fill, on = 1;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
		printf("[scm_cred] socketpair fail %d\n", errno);
		return;
	}
	if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &on, sizeof on) < 0)
		printf("[scm_cred] SO_PASSCRED fail errno=%d\n", errno);

	for (fill = 0; fill < 2; fill++) {
		unsigned char ctrl[256], data[1] = { 'X' };
		struct iovec iov;
		struct msghdr msg;
		ssize_t r;

		memset(ctrl, fill ? 0xff : 0x00, sizeof ctrl);
		iov.iov_base = data;
		iov.iov_len = 1;
		memset(&msg, 0, sizeof msg);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = ctrl;
		msg.msg_controllen = sizeof ctrl;

		if (send(sv[0], data, 1, 0) < 0) {
			printf("[scm_cred] send fail errno=%d\n", errno);
			break;
		}
		errno = 0;
		r = recvmsg(sv[1], &msg, MSG_DONTWAIT);
		printf("[scm_cred] fill=%02x ret=%zd errno=%d controllen=%u\n",
		       fill ? 0xff : 0x00, r, errno, (unsigned)msg.msg_controllen);
		if (r >= 0)
			scan_buf("scm_cred", ctrl, (int)msg.msg_controllen, NULL,
			         fill ? 0xff : 0x00);
	}
	close(sv[0]); close(sv[1]);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== leakfuzz2  pid=%d ===\n", getpid());

	test_pty();
	test_sockopts();
	test_netlink_name();
	test_scm_cred();

	printf("\n=== total HIT = %d ===\n", g_hits);
	return 0;
}
