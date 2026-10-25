/*
 * cowtest —— dirtycow (CVE-2016-5195) 前置能力测试
 * 只测权限和原语可用性，不执行真正的竞态利用（不会修改任何文件）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== dirtycow capability test ===\n");
	printf("uid=%d euid=%d gid=%d\n", getuid(), geteuid(), getgid());

	/* 1. /proc/self/mem O_RDWR */
	errno = 0;
	int mfd = open("/proc/self/mem", O_RDWR);
	printf("[1] open(/proc/self/mem, O_RDWR)  = %d  errno=%d (%s)\n",
	       mfd, errno, strerror(errno));

	/* 2. /proc/self/mem O_RDONLY */
	errno = 0;
	int mfd2 = open("/proc/self/mem", O_RDONLY);
	printf("[2] open(/proc/self/mem, O_RDONLY)= %d  errno=%d (%s)\n",
	       mfd2, errno, strerror(errno));

	/* 3. mmap 只读系统文件 */
	errno = 0;
	int fd = open("/system/build.prop", O_RDONLY);
	printf("[3] open(/system/build.prop)      = %d  errno=%d (%s)\n",
	       fd, errno, strerror(errno));

	if (fd >= 0) {
		errno = 0;
		void *map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
		printf("[4] mmap(PROT_READ, MAP_PRIVATE)  = %p  errno=%d (%s)\n",
		       map, errno, strerror(errno));

		if (map != MAP_FAILED && mfd >= 0) {
			/* 单次 pwrite 会走正常 COW，不会改文件；只验权限 */
			errno = 0;
			ssize_t w = pwrite(mfd, "A", 1, (off_t)(uintptr_t)map);
			printf("[5] pwrite(/proc/self/mem,@map)   = %zd  errno=%d (%s)\n",
			       w, errno, strerror(errno));
			/* 把私有副本还原：卸载映射即可 */
		}
		if (map != MAP_FAILED) {
			errno = 0;
			int r = madvise(map, 4096, MADV_DONTNEED);
			printf("[6] madvise(MADV_DONTNEED)        = %d  errno=%d (%s)\n",
			       r, errno, strerror(errno));
			munmap(map, 4096);
		}
		close(fd);
	}

	/* 7. ptrace 自己的子进程（dirtycow 的另一个变体） */
	pid_t pid = fork();
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		raise(SIGSTOP);
		_exit(0);
	} else if (pid > 0) {
		int st = 0;
		waitpid(pid, &st, 0);
		errno = 0;
		long p = ptrace(PTRACE_PEEKDATA, pid, (void *)(uintptr_t)0x10000, NULL);
		printf("[7] ptrace(PEEKDATA, child)       = %ld  errno=%d (%s)\n",
		       p, errno, strerror(errno));
		errno = 0;
		long q = ptrace(PTRACE_POKEDATA, pid, (void *)(uintptr_t)0x10000, (void *)0);
		printf("[8] ptrace(POKEDATA, child)       = %ld  errno=%d (%s)\n",
		       q, errno, strerror(errno));
		kill(pid, SIGKILL);
		waitpid(pid, &st, 0);
	}

	if (mfd >= 0) close(mfd);
	if (mfd2 >= 0) close(mfd2);
	printf("=== done ===\n");
	return 0;
}
