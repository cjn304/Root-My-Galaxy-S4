/* 让 poll 停在 syscall 内部：pollfd 数组按 N_STACK_PPS=31 拷到内核栈后阻塞 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <poll.h>

static struct pollfd pfd[30];
static int p[2];

int main(void)
{
	int i;

	for (i = 0; i < 30; i++) {
		pfd[i].fd = (int)(0xcafe0000u + (uint32_t)i * 4u);
		pfd[i].events = 0;
		pfd[i].revents = 0;
	}
	pipe(p);
	pfd[0].fd = p[0];          /* 有效 fd，保证真的阻塞住 */
	pfd[0].events = POLLIN;

	printf("pollblock pid=%d\n", getpid());
	fflush(stdout);

	poll(pfd, 30, -1);         /* 永远阻塞：栈上 240 字节一直活着 */

	for (;;)
		__sync_synchronize();
	return 0;
}
