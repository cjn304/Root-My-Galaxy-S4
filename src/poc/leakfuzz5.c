/* SPDX-License-Identifier: GPL-3.0-or-later */

/*
 * leakfuzz5 —— 最后一批 syscall 输出结构体
 *
 * uname / gethostname / getdomainname / fstatfs / fstat / stat / lstat /
 * readlink / getcwd / getlogin_r / ttyname_r / inotify read / eventfd read /
 * epoll_wait / getpeername / accept / recvfrom 的地址结构
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
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/utsname.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int g_hits, g_probes, g_pad;

static int is_kaddr(uint32_t v)
{
	return v >= 0xc0000000u && v < 0xe7800000u && (v >> 24) >= 0x80;
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
		if (v0 != v1 || !is_kaddr(v0)) continue;
		printf("  *** LEAK %-28s off=0x%03x val=%08x\n", tag, i, v0);
		g_hits++;
	}
	if (unwritten > 0 && unwritten < len) {
		int first = -1, last = -1;
		for (i = 0; i < len; i++)
			if (b0[i] == 0x00 && b1[i] == 0xff) {
				if (first < 0) first = i;
				last = i;
			}
		printf("  [pad] %-28s len=%d unwritten=%d range=0x%02x..0x%02x\n",
		       tag, len, unwritten, first, last);
		g_pad++;
	}
}

typedef long (*fn_t)(unsigned char *b, int cap, void *ctx);

static void dual(const char *tag, fn_t fn, void *ctx, int cap)
{
	unsigned char b0[1024], b1[1024];
	long l0, l1;

	if (cap > (int)sizeof b0) cap = sizeof b0;
	memset(b0, 0x00, sizeof b0);
	memset(b1, 0xff, sizeof b1);
	l0 = fn(b0, cap, ctx);
	if (l0 < 0) { return; }
	l1 = fn(b1, cap, ctx);
	if (l1 < 0) return;
	analyze(tag, b0, b1, (int)(l0 < l1 ? l0 : l1));
}

/* ---- 各种 ---- */
static long fn_uname(unsigned char *b, int cap, void *p)
{ (void)cap; (void)p; return (uname((struct utsname *)b) == 0) ? (long)sizeof(struct utsname) : -1; }

static long fn_hostname(unsigned char *b, int cap, void *p)
{ (void)p; return (gethostname((char *)b, cap) == 0) ? (long)strlen((char *)b) + 1 : -1; }

static long fn_domainname(unsigned char *b, int cap, void *p)
{ (void)p; return (getdomainname((char *)b, cap) == 0) ? (long)strlen((char *)b) + 1 : -1; }

static long fn_statfs(unsigned char *b, int cap, void *p)
{ (void)cap; return (statfs((const char *)p, (struct statfs *)b) == 0) ? (long)sizeof(struct statfs) : -1; }

static long fn_fstatfs64(unsigned char *b, int cap, void *p)
{ (void)cap; return (fstatfs((int)(long)p, (struct statfs *)b) == 0) ? (long)sizeof(struct statfs) : -1; }

static long fn_stat(unsigned char *b, int cap, void *p)
{ (void)cap; return (stat((const char *)p, (struct stat *)b) == 0) ? (long)sizeof(struct stat) : -1; }

static long fn_lstat(unsigned char *b, int cap, void *p)
{ (void)cap; return (lstat((const char *)p, (struct stat *)b) == 0) ? (long)sizeof(struct stat) : -1; }

static long fn_readlink(unsigned char *b, int cap, void *p)
{ ssize_t r = readlink((const char *)p, (char *)b, cap); return (r > 0) ? (long)r : -1; }

static long fn_getcwd(unsigned char *b, int cap, void *p)
{ (void)p; return (getcwd((char *)b, cap) != NULL) ? (long)strlen((char *)b) + 1 : -1; }

static long fn_getlogin(unsigned char *b, int cap, void *p)
{ (void)p; return (getlogin_r((char *)b, cap) == 0) ? (long)strlen((char *)b) + 1 : -1; }

static long fn_eventfd_read(unsigned char *b, int cap, void *p)
{
	int fd = (int)(long)p;
	uint64_t v = 1;
	(void)cap;
	if (write(fd, &v, sizeof v) != (ssize_t)sizeof v) return -1;
	{
		ssize_t r = read(fd, b, 8);
		return (r == 8) ? 8 : -1;
	}
}

static long fn_inotify_read(unsigned char *b, int cap, void *p)
{
	int fd = (int)(long)p;
	ssize_t r;
	(void)cap;
	r = read(fd, b, 512);
	return (r > 0) ? (long)r : -1;
}

struct ep_ctx { int epfd; int target; };
static long fn_epoll_wait(unsigned char *b, int cap, void *p)
{
	struct ep_ctx *c = p;
	int n;
	(void)cap;
	n = epoll_wait(c->epfd, (struct epoll_event *)b, 8, 0);
	return (n >= 0) ? (long)(n * sizeof(struct epoll_event)) : -1;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== leakfuzz5  pid=%d ===\n", getpid());

	printf("-> %s\n", "uname");
	dual("uname", fn_uname, NULL, sizeof(struct utsname));
	printf("-> %s\n", "gethostname");
	dual("gethostname", fn_hostname, NULL, 256);
	printf("-> %s\n", "getdomainname");
	dual("getdomainname", fn_domainname, NULL, 256);
	printf("-> %s\n", "statfs./data");
	dual("statfs./data", fn_statfs, (void *)"/data", sizeof(struct statfs));
	printf("-> %s\n", "statfs./proc");
	dual("statfs./proc", fn_statfs, (void *)"/proc", sizeof(struct statfs));
	printf("-> %s\n", "stat./data");
	dual("stat./data", fn_stat, (void *)"/data", sizeof(struct stat));
	printf("-> %s\n", "stat./system/bin/sh");
	dual("stat./system/bin/sh", fn_stat, (void *)"/system/bin/sh", sizeof(struct stat));
	printf("-> %s\n", "lstat./system/bin/sh");
	dual("lstat./system/bin/sh", fn_lstat, (void *)"/system/bin/sh", sizeof(struct stat));
	printf("-> %s\n", "readlink./proc/self/exe");
	dual("readlink./proc/self/exe", fn_readlink, (void *)"/proc/self/exe", 256);
	printf("-> %s\n", "readlink./system/bin/sh");
	dual("readlink./system/bin/sh", fn_readlink, (void *)"/system/bin/sh", 256);
	printf("-> %s\n", "getcwd");
	dual("getcwd", fn_getcwd, NULL, 256);
	printf("-> %s\n", "getlogin_r");
	dual("getlogin_r", fn_getlogin, NULL, 64);

	{
		int fd = open("/data", O_RDONLY | O_DIRECTORY);
		if (fd >= 0) {
	printf("-> %s\n", "fstatfs64./data");
			dual("fstatfs64./data", fn_fstatfs64, (void *)(long)fd, sizeof(struct statfs));
			close(fd);
		}
	}

	{
		int efd = eventfd(0, 0);
		if (efd >= 0) {
	printf("-> %s\n", "eventfd.read");
			dual("eventfd.read", fn_eventfd_read, (void *)(long)efd, 8);
			close(efd);
		}
	}

	{
		int ifd = inotify_init1(IN_NONBLOCK);
		if (ifd >= 0) {
			int wd = inotify_add_watch(ifd, "/data/local/tmp", IN_ALL_EVENTS);
			if (wd >= 0) {
				int t = open("/data/local/tmp/.ino_probe", O_CREAT | O_RDWR, 0600);
				if (t >= 0) { close(t); unlink("/data/local/tmp/.ino_probe"); }
				usleep(50000);
			}
	printf("-> %s\n", "inotify.read");
			dual("inotify.read", fn_inotify_read, (void *)(long)ifd, 512);
			close(ifd);
		}
	}

	{
		int ep = epoll_create(8);
		int pfd[2];
		if (ep >= 0 && pipe(pfd) == 0) {
			struct epoll_event ev;
			struct ep_ctx c;
			memset(&ev, 0, sizeof ev);
			ev.events = EPOLLIN;
			ev.data.fd = pfd[0];
			epoll_ctl(ep, EPOLL_CTL_ADD, pfd[0], &ev);
			if (write(pfd[1], "x", 1) == 1) {
				c.epfd = ep; c.target = pfd[0];
	printf("-> %s\n", "epoll_wait");
				dual("epoll_wait", fn_epoll_wait, &c, 8 * sizeof(struct epoll_event));
			}
			close(pfd[0]); close(pfd[1]);
			close(ep);
		}
	}

	printf("\n=== probes=%d  LEAK=%d  pad=%d ===\n", g_probes, g_hits, g_pad);
	return 0;
}
