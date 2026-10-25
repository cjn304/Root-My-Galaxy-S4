/* 测试低地址 mmap：0 页需要 CAP_SYS_RAWIO，0x8000+ 正常 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>

int main(void)
{
	void *p, *q, *r;
	volatile uint32_t *z;

	setvbuf(stdout, NULL, _IONBF, 0);

	errno = 0;
	p = mmap(0, 0x1000, PROT_READ | PROT_WRITE,
		 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	printf("mmap(0x0)     -> %p errno=%d\n", p, errno);
	if (p == MAP_FAILED) {
		printf("  (0 page blocked; PF_SUPERPRIV / mmap_zero ?)\n");
	} else {
		z = (volatile uint32_t *)0;
		z[0] = 0xfeedface;
		printf("  write [0]=%08x read=%08x\n", 0xfeedface, z[0]);
	}

	errno = 0;
	q = mmap((void *)0x8000, 0x8000, PROT_READ | PROT_WRITE,
		 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	printf("mmap(0x8000)  -> %p errno=%d\n", q, errno);

	errno = 0;
	r = mmap((void *)0x10000, 0x1000, PROT_READ | PROT_WRITE,
		 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	printf("mmap(0x10000) -> %p errno=%d (expect fail/overwrite text)\n",
	       r, errno);
	return 0;
}
