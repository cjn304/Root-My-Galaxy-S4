/* 用 semop 阻塞：sembuf[32] 走 fast_sops(栈)，blocked 期间数据常驻 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/sem.h>

static struct sembuf ops[32];

int main(void)
{
	int i, id;

	id = semget(IPC_PRIVATE, 1, 0666 | IPC_CREAT);
	if (id < 0) { perror("semget"); return 1; }
	semctl(id, 0, SETVAL, 0);

	memset(ops, 0, sizeof ops);
	ops[0].sem_num = 0;
	ops[0].sem_op = -1;
	ops[0].sem_flg = 0;
	/* 全部用合法 sem_num=0：sem_num 越界会被内核判 EINVAL 立即返回。
	 * 标记放在 sem_op：entry i 的 sem_op = 0x0100+i（u16 at base+6i+2） */
	for (i = 1; i < 32; i++) {
		ops[i].sem_num = 0;
		ops[i].sem_op  = (short)(0x0100 + i);
		ops[i].sem_flg = 0;
	}

	printf("semblk pid=%d semid=%d\n", getpid(), id);
	fflush(stdout);

	syscall(SYS_semop, id, ops, 32);   /* 阻塞 */

	for (;;)
		__sync_synchronize();
	return 0;
}
