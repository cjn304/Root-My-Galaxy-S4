/*
 * ion_spray.c —— ION 作为 kmalloc-32 spray 工具的可行性实测
 *
 * 要回答三个问题：
 *   Q1 连续 ALLOC 的 ion_handle 是否落在同一 slab、间距是否 32（确认 kmalloc-32）
 *   Q2 FREE 后重新 ALLOC 是否 LIFO 复用（决定能否精确控制 freelist 顺序）
 *   Q3 heap 0(SYSTEM/vmalloc) 与 heap 1(SYSTEM_CONTIG/kmalloc) 是否都只污染 kmalloc-32
 *
 * 方法：只打印地址，不做任何破坏性操作。地址序列本身就够判断。
 *   阶段 S1：一次性 alloc 32 个（不 free），打印全部地址与间距直方图
 *   阶段 S2：free 全部，再 alloc 32 个，比较两轮地址集合（LIFO ⇒ 顺序反）
 *   阶段 S3：只 free 偶数索引，再 alloc 8 个，看是否填回被释放的槽（不是新页）
 */
#include <stdio.h>
#include <stdlib.h>
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

#define N 32
#define ADDRF "/data/local/tmp/ion_spray_addr.txt"

static int fd_ion;
static struct ion_handle *hs[N];

static struct ion_handle *a1(unsigned int heap, size_t len)
{
	struct ion_allocation_data d;

	memset(&d, 0, sizeof d);
	d.len = len;
	d.align = 0;
	d.heap_mask = 1u << heap;
	d.flags = 0;
	if (ioctl(fd_ion, ION_IOC_ALLOC, &d) != 0)
		return NULL;
	return d.handle;
}

static void fr(struct ion_handle *h)
{
	struct ion_handle_data hd;

	memset(&hd, 0, sizeof hd);
	hd.handle = h;
	ioctl(fd_ion, ION_IOC_FREE, &hd);
}

/* 打印地址序列 + 相邻间距直方图（间距 32 = 同 slab 连续 kmalloc-32 对象） */
static void show(const char *tag)
{
	int i, same_slab = 0, d32 = 0;

	printf("%s:\n", tag);
	for (i = 0; i < N; i++)
		printf("  [%2d] %p\n", i, (void *)hs[i]);
	for (i = 1; i < N; i++) {
		uintptr_t a = (uintptr_t)hs[i - 1], b = (uintptr_t)hs[i];
		long d = (long)(b - a);
		long ad = d < 0 ? -d : d;

		if (ad == 32)
			d32++;
		if (!((a ^ b) & ~0xFFFUL))
			same_slab++;
	}
	printf("  >> 相邻间距==32 的个数: %d/%d\n", d32, N - 1);
	printf("  >> 相邻同 4K 页的个数: %d/%d\n", same_slab, N - 1);
}

int main(void)
{
	int i;
	FILE *f;

	setvbuf(stdout, NULL, _IONBF, 0);
	unlink(ADDRF);
	fd_ion = open("/dev/ion", O_RDWR);
	if (fd_ion < 0) {
		printf("[!] open: %s\n", strerror(errno));
		return 1;
	}

	/* S1：heap0（SYSTEM = vmalloc 后端，理论上不污染 kmalloc 大块） */
	printf("=== S1 heap0 len=4096 x%d ===\n", N);
	for (i = 0; i < N; i++)
		hs[i] = a1(0, 4096);
	show("S1 addresses");

	f = fopen(ADDRF, "a");
	if (f) {
		for (i = 0; i < N; i++)
			fprintf(f, "S1 %#x\n", (unsigned int)(uintptr_t)hs[i]);
		fclose(f);
	}
	printf("S1 sleeping 10s for ktool dump of the whole slab page...\n");
	sleep(10);

	/* S2：全部 free，再 alloc 一轮，看是否 LIFO */
	for (i = 0; i < N; i++)
		if (hs[i])
			fr(hs[i]);
	printf("=== S2 freed all, re-alloc ===\n");
	for (i = 0; i < N; i++)
		hs[i] = a1(0, 4096);
	show("S2 addresses");
	printf("S2 sleeping 6s...\n");
	sleep(6);

	/* S3：只 free 偶数，再 alloc 8 个 —— 若能精确回收，新地址应落在偶数槽 */
	for (i = 0; i < N; i += 2)
		if (hs[i])
			fr(hs[i]);
	printf("=== S3 freed even idx, alloc 8 more ===\n");
	for (i = 0; i < 8; i++) {
		struct ion_handle *h = a1(0, 4096);
		printf("  new[%d] %p\n", i, (void *)h);
	}

	/* S4：heap1（SYSTEM_CONTIG = kmalloc 后端）对比 */
	printf("=== S4 heap1 len=4096 x8 ===\n");
	for (i = 0; i < 8; i++)
		printf("  heap1[%d] %p\n", i, (void *)a1(1, 4096));

	printf("DONE\n");
	return 0;
}
