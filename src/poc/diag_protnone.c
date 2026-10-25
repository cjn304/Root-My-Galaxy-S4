/* SPDX-License-Identifier: GPL-3.0-or-later */

/* diag_protnone.c — PROT_NONE 页对内核 copy_from_user/copy_to_user 是否真的不可访问 */
#define _GNU_SOURCE
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

static sigjmp_buf jb;
static void segv(int s) { (void)s; siglongjmp(jb, 1); }

int main(void)
{
	unsigned char *p;
	int fd[2];
	ssize_t n;
	struct iovec iov[2];

	p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	memset(p, 0xDD, 4096);
	if (mprotect(p, 4096, PROT_NONE) != 0)
		perror("mprotect");

	signal(SIGSEGV, segv);
	if (sigsetjmp(jb, 1) == 0) {
		printf("user read: %02x (NO FAULT!)\n", p[0]);
	} else {
		printf("user read: SIGSEGV (expected)\n");
	}

	pipe(fd);
	n = write(fd[1], p, 100);          /* 内核 copy_from_user 读 PROT_NONE 页 */
	printf("write(pipe, protnone, 100) = %zd errno=%d\n", n, errno);
	if (n > 0) {
		unsigned char buf[128];
		read(fd[0], buf, n);
		printf("  content[0]=%02x\n", buf[0]);
	}

	/* 内核写 PROT_NONE 页：readv from pipe */
	write(fd[1], "abcdefgh", 8);
	iov[0].iov_base = p;
	iov[0].iov_len = 8;
	n = readv(fd[0], iov, 1);
	printf("readv(pipe, protnone) = %zd errno=%d\n", n, errno);

	/* 再确认一次：单 iovec 的 writev */
	{
		unsigned char t[16];
		iov[0].iov_base = p;
		iov[0].iov_len = 100;
		n = writev(fd[1], iov, 1);
		printf("writev(pipe, protnone, 100) = %zd errno=%d\n", n, errno);
		if (n > 0) {
			read(fd[0], t, n);
			printf("  content[0]=%02x\n", t[0]);
		}
	}
	return 0;
}
