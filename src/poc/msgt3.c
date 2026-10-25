/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
static uint32_t buf[16] __attribute__((aligned(8)));
int main(void)
{
	int i, id; long r; int e;
	for (i = 0; i < 16; i++) buf[i] = 0xcafe0000u + (uint32_t)i * 4u;
	printf("nr msgget=%d msgsnd=%d msgrcv=%d msgctl=%d\n",
	       (int)SYS_msgget, (int)SYS_msgsnd, (int)SYS_msgrcv, (int)SYS_msgctl);
	errno = 0; id = (int)syscall(SYS_msgget, 0 /*IPC_PRIVATE*/, 0666);
	printf("msgget -> %d errno=%d\n", id, errno);
	errno = 0; r = syscall(SYS_msgctl, id, 1, buf);
	e = errno;
	printf("msgctl(I_SET,id=%d) -> %ld errno=%d\n", id, r, e);
	fflush(stdout);
	return 0;
}
