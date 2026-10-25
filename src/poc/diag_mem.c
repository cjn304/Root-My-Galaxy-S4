/* SPDX-License-Identifier: GPL-3.0-or-later */

/* diag_mem.c — 验证 MADV_DONTNEED / mprotect(PROT_READ) 在本机的真实行为 */
#define _GNU_SOURCE
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static sigjmp_buf jb;
static void segv(int s) { (void)s; siglongjmp(jb, 1); }

int main(void)
{
	unsigned char *p, *q;
	unsigned char vec[8];
	int r;

	p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	memset(p, 'N', 4096);
	r = mincore(p, 4096, vec);
	printf("before madvise: mincore=%d res=%d\n", r, vec[0] & 1);

	r = madvise(p, 4096, MADV_DONTNEED);
	printf("madvise ret=%d errno=%d\n", r, errno);

	r = mincore(p, 4096, vec);
	printf("after  madvise: mincore=%d res=%d\n", r, vec[0] & 1);

	q = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	memset(q, 'R', 4096);
	r = mprotect(q, 4096, PROT_READ);
	printf("mprotect(PROT_READ) ret=%d errno=%d\n", r, errno);

	signal(SIGSEGV, segv);
	if (sigsetjmp(jb, 1) == 0) {
		q[0] = 'X';
		printf("user write to PROT_READ page: NO FAULT (bad)\n");
	} else {
		printf("user write to PROT_READ page: SIGSEGV (good)\n");
	}

	/* 再确认一下 madvise 之后读出来是不是 0 */
	printf("read after madvise: first byte = %d (expect 0)\n", p[0]);
	return 0;
}
