/* SPDX-License-Identifier: GPL-3.0-or-later */

/* P4.50 二分探针：只做与 sem_canary7 相同的早期内存布局动作就退出。
 * 用于区分 execvp 之后的卡死是 (a) mmap(0x4FFF0000) MAP_FIXED，
 * 还是 (b) sem_canary7 更后面的 futex/semtimedop 链。
 *
 * 用法：ktool root /data/local/tmp/mmprobe
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

int main(void)
{
	void *pg;

	write(2, "MPRE_BOOT\n", 10);
	setvbuf(stdout, NULL, _IONBF, 0);

	pg = mmap((void *)0x8000, 0x8000, PROT_READ | PROT_WRITE,
		  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (pg == MAP_FAILED || (unsigned long)pg != 0x8000) {
		write(2, "MPRE: mmap 0x8000 FAIL\n", 23);
		return 1;
	}
	memset(pg, 0, 0x8000);
	write(2, "MPRE: low mmap ok\n", 18);

	pg = mmap((void *)0x4FFF0000, 0x50000, PROT_READ | PROT_WRITE,
		  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (pg == MAP_FAILED || (unsigned long)pg != 0x4FFF0000) {
		write(2, "MPRE: mmap 0x4FFF0000 FAIL\n", 27);
		return 1;
	}
	memset((char *)0x4FFF0000, 0, 0x50000);
	write(2, "MPRE: high mmap ok\n", 19);

	/* 1MB malloc，与 sem_canary 的 g_kbuf 同量级 */
	{
		void *big = malloc(1 << 20);
		if (!big) { write(2, "MPRE: malloc FAIL\n", 18); return 1; }
		memset(big, 0, 1 << 20);
		write(2, "MPRE: malloc ok\n", 16);
	}

	write(2, "MPRE_DONE\n", 10);
	return 0;
}
