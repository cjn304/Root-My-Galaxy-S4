/* 对比 IPC_OLD(1) 与 IPC_64(1|0x100) 的栈拷贝是否能留到 syscall 之后 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
static uint32_t buf[32] __attribute__((aligned(8)));
int main(int argc, char **argv)
{
	int i, id; long r;
	int cmd = (argc > 1 && argv[1][0] == '6') ? (1 | 0x100) : 1;

	for (i = 0; i < 32; i++) buf[i] = 0xcafe0000u + (uint32_t)i * 4u;

	id = (int)syscall(SYS_msgget, 0, 0666);
	printf("msgt4 cmd=%#x msqid=%d pid=%d\n", cmd, id, getpid());
	fflush(stdout);

	r = syscall(SYS_msgctl, id, cmd, buf);
	/* 不再 syscall：结果靠外部 wfind */
	(void)r;
	for (;;)
		__sync_synchronize();
	return 0;
}
