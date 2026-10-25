/* 正向验证：poll() 会把 nfds<=32 的 pollfd 数组拷到内核栈（POLL_STACK_ALLOC=256） */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <poll.h>

static struct pollfd pfd[32];

int main(void)
{
	int i;

	for (i = 0; i < 32; i++) {
		pfd[i].fd = (int)(0xcafe0000u + (uint32_t)i * 4u);
		pfd[i].events = 0;
		pfd[i].revents = 0;
	}
	printf("polltest pid=%d\n", getpid());
	fflush(stdout);

	poll(pfd, 32, 0);          /* 之后不再 syscall */

	for (;;)
		__sync_synchronize();
	return 0;
}
