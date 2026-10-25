/* msgctl 栈拷贝隔离实验
 * 关键纪律：msgctl 之后**不发任何 syscall**（printf 放在前面并 flush），
 * 否则 pause/print 的新帧会把 msgctl 的栈帧覆盖掉，实验就看不到东西了。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/syscall.h>

static uint32_t buf[16] __attribute__((aligned(8)));

int main(void)
{
	int i;

	for (i = 0; i < 16; i++)
		buf[i] = 0xcafe0000u + (uint32_t)i * 4u;

	printf("msgt pid=%d tid=%ld\n", getpid(), (long)syscall(SYS_gettid));
	fflush(stdout);

	syscall(SYS_msgctl, 0, 1, buf);

	/* 之后绝不 syscall */
	for (;;)
		__sync_synchronize();

	return 0;
}
