#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
static uint32_t buf[16] __attribute__((aligned(8)));
int main(void)
{
	int i; long r; int e; long r64;
	for (i = 0; i < 16; i++) buf[i] = 0xcafe0000u + (uint32_t)i * 4u;
	errno = 0;
	r = syscall(SYS_msgctl, 0, 1, buf);
	e = errno;
	errno = 0;
	r64 = syscall(SYS_msgctl, 0, 1 | 0x100, buf);
	printf("SYS_msgctl=%d\n", (int)SYS_msgctl);
	printf("IPC_OLD: r=%ld errno=%d\n", r, e);
	printf("IPC_64 : r=%ld errno=%d\n", r64, errno);
	printf("sizeof check done\n");
	return 0;
}
