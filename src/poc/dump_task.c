/* dump init_task 前 N 字节，用于校准 task_struct 偏移（P4.48） */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	int fd, n, w;
	char cmd[64];
	unsigned long addr = 0xc0b79be0UL;	/* init_task */
	int len = 64;

	if (argc > 1) addr = strtoul(argv[1], NULL, 0);
	if (argc > 2) len = atoi(argv[2]);

	setvbuf(stdout, NULL, _IONBF, 0);
	fd = open("/dev/ktool", O_WRONLY);
	if (fd < 0) { printf("open fail errno=%d\n", errno); return 1; }
	n = snprintf(cmd, sizeof cmd, "kread %lx %d", addr, len);
	w = (int)write(fd, cmd, n);
	close(fd);
	printf("kread %#lx len=%d -> %d/%d errno=%d\n", addr, len, w, n, errno);
	return 0;
}
