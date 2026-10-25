/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <errno.h>

int main(void)
{
	void *pg, *fnode;
	int sid;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("A: start pid=%d\n", getpid());

	pg = mmap((void *)0x8000, 0x8000, PROT_READ | PROT_WRITE,
		  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	printf("B: mmap(0x8000)=%p errno=%d\n", pg, errno);
	if (pg == MAP_FAILED) return 1;

	memset(pg, 0, 0x8000);
	printf("C: memset ok\n");

	*(unsigned *)0x9000 = 1;
	*(unsigned *)0xA000 = 2;
	*(unsigned *)0xB000 = 3;
	printf("D: fake page writes ok\n");

	pg = mmap(NULL, 0x20000, PROT_READ | PROT_WRITE,
		  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	printf("E: mmap(0x20000)=%p\n", pg);
	if (pg == MAP_FAILED) return 1;
	fnode = (void *)(((unsigned long)pg + 0xFFFFULL) & ~0xFFFFULL);
	memset((char *)fnode - 0x1000, 0, 0x2000);
	printf("F: fnode=%p\n", fnode);

	sid = semget(IPC_PRIVATE, 1, 0666 | IPC_CREAT);
	printf("G: semget=%d errno=%d\n", sid, errno);
	if (sid >= 0) printf("H: semctl=%d\n", semctl(sid, 0, SETVAL, 0));
	printf("Z: done\n");
	return 0;
}
