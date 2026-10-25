/* SPDX-License-Identifier: GPL-3.0-or-later */

/* semtimedop 阻塞态测量：entry0 阻塞，entry1 放唯一标记，其余填充
 * 标记 u32 = 0xBEEFDEAD（sem_num=0xDEAD, sem_op=0xBEEF）→ 命中点 - 6 = 数组基址
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
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
	ops[0].sem_op = -1;        /* sem=0 -> 阻塞 */
	ops[0].sem_flg = 0;

	ops[1].sem_num = 0xDEAD;   /* 唯一标记 */
	ops[1].sem_op  = 0xBEEF;
	ops[1].sem_flg = 0x1234;

	for (i = 2; i < 32; i++) {
		ops[i].sem_num = 0xAAAA;
		ops[i].sem_op  = 0xBBBB;
		ops[i].sem_flg = 0xCCCC;
	}

	printf("semtest pid=%d semid=%d\n", getpid(), id);
	fflush(stdout);

	{
		struct timespec ts;
		ts.tv_sec = 600;
		ts.tv_nsec = 0;
		syscall(SYS_semtimedop, id, ops, 32, &ts);
	}
	for (;;)
		__sync_synchronize();
	return 0;
}
