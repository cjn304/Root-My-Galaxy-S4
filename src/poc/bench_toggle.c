/* SPDX-License-Identifier: GPL-3.0-or-later */

/* bench_toggle.c — 测 munmap/mmap 与 mprotect 翻转一页的耗时 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>

#define A ((void *)0x60000000UL)
#define PG 4096

static double now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
	int n = argc > 1 ? atoi(argv[1]) : 20000;
	int mode = argc > 2 ? atoi(argv[2]) : 0;
	double t0, dt;
	int i;

	if (mmap(A, PG, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) != A) {
		perror("mmap");
		return 1;
	}
	t0 = now();
	for (i = 0; i < n; i++) {
		if (mode == 0) {
			munmap(A, PG);
			mmap(A, PG, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		} else {
			mprotect(A, PG, PROT_NONE);
			mprotect(A, PG, PROT_READ | PROT_WRITE);
		}
	}
	dt = now() - t0;
	printf("mode=%d n=%d total=%.3fs per_cycle=%.2f us\n",
	       mode, n, dt, dt * 1e6 / n);
	return 0;
}
