#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/sem.h>
static struct sembuf ops[32];
int main(void)
{
	int i, id, rc; long r;
	struct timespec ts = {0, 0};

	printf("nr semget=%d semctl=%d semop=%d semtimedop=%d\n",
	       (int)SYS_semget, (int)SYS_semctl, (int)SYS_semop, (int)SYS_semtimedop);

	errno = 0;
	id = semget(IPC_PRIVATE, 1, 0666 | IPC_CREAT);
	printf("semget=%d errno=%d\n", id, errno);

	errno = 0;
	rc = semctl(id, 0, SETVAL, 0);
	printf("semctl SETVAL rc=%d errno=%d\n", rc, errno);

	memset(ops, 0, sizeof ops);
	ops[0].sem_num = 0; ops[0].sem_op = -1; ops[0].sem_flg = 0;

	errno = 0;
	r = syscall(SYS_semtimedop, id, ops, 1, &ts);
	printf("semtimedop(tv=0) r=%ld errno=%d\n", r, errno);

	errno = 0;
	r = syscall(SYS_semop, id, ops, 1);
	printf("semop r=%ld errno=%d\n", r, errno);
	return 0;
}
