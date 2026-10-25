/* 测 semtimedop 路径下 fast_sops 的栈深度 D（P4.45）
 *
 * 目的：semop 路径实测 D = 0x1DE8（mod 6 = 0），所以 waiter+0x2C（数组+0x3C）
 *       正好落在 ops[10] 起始，被 sem_num=0 钉死成 64KB 对齐。
 *       semtimedop 的帧不同，若 D ≡ 2 (mod 6)，则 +0x3C 落在 ops[k].sem_op
 *       位置 ⇒ lock 32 位全可控。
 *
 * 标记方式：ops[i].sem_op = 0x0100 + i（sem_num 全 0，否则阻塞前就 EINVAL）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/sem.h>

static struct sembuf ops[32];
static volatile int g_tid;

/* 主线程阻塞在 semtimedop 时，由本线程去问模块：数组到底落在哪 */
static void *reporter(void *arg)
{
	char cmd[64];
	int fd, n, w;

	(void)arg;
	sleep(3);

	fd = open("/dev/ktool", O_WRONLY);
	if (fd < 0) {
		printf("reporter: open /dev/ktool fail errno=%d（需要 uid0）\n", errno);
		return NULL;
	}
	n = snprintf(cmd, sizeof cmd, "wfind16 %d 0101", g_tid);
	w = (int)write(fd, cmd, n);
	close(fd);
	printf("reporter: wfind16(tid=%d) -> %d/%d errno=%d\n", g_tid, w, n, errno);
	return NULL;
}

int main(void)
{
	int i, id;
	struct timespec ts;
	pthread_t t;

	setvbuf(stdout, NULL, _IONBF, 0);

	id = semget(IPC_PRIVATE, 1, 0666 | IPC_CREAT);
	if (id < 0) { perror("semget"); return 1; }
	semctl(id, 0, SETVAL, 0);

	memset(ops, 0, sizeof ops);
	ops[0].sem_num = 0;
	ops[0].sem_op = -1;		/* sem 值 0 -> 阻塞 */
	ops[0].sem_flg = 0;
	for (i = 1; i < 32; i++) {
		ops[i].sem_num = 0;	/* 必须 < nsems */
		ops[i].sem_op = (short)(0x0100 + i);
		ops[i].sem_flg = 0;
	}

	ts.tv_sec = 600;
	ts.tv_nsec = 0;

	g_tid = (int)getpid();		/* 主线程 tid == pid */
	printf("sem_time pid=%d semid=%d  (标记 0x0101 在数组基址+8)\n",
	       g_tid, id);

	pthread_create(&t, NULL, reporter, NULL);

	/* 阻塞在 semtimedop 里；fast_sops 常驻栈上 */
	syscall(SYS_semtimedop, id, ops, 32, &ts);

	printf("semtimedop returned errno=%d\n", errno);
	return 0;
}
