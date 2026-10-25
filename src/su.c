/*
 * su.c — GT-I9500 minimal su（ktool 后端）
 *
 *   su            交互 shell
 *   su -c "cmd"   执行单条命令
 *   su cmd args   直接执行
 *
 * 提权原语是 /dev/ktool 的 "ish" 命令：把写它的进程切成 uid0 + u:r:init_shell:s0。
 * 授权目前用白名单文件（每行一个 uid，# 开头忽略）。
 * 后续接 phh Superuser APK 时，只需把 is_allowed() 换成读 sqlite 的 uid_policy。
 *
 * 部署：/system/xbin/su，标签 su_exec，mode 755
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define KTOOL       "/dev/ktool"
#define ALLOW_FILE  "/data/system/su_allow"
#define SHELL       "/system/bin/sh"

static int is_allowed(int uid)
{
	FILE *f = fopen(ALLOW_FILE, "r");
	char line[64];

	if (!f)
		return 0;

	while (fgets(line, sizeof(line), f)) {
		char *p = line;
		int u;

		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n' || *p == 0)
			continue;
		u = atoi(p);
		if (u == uid) {
			fclose(f);
			return 1;
		}
	}
	fclose(f);
	return 0;
}

int main(int argc, char **argv)
{
	int caller = getuid();
	int fd, i;

	if (caller == 0)
		goto run;

	fd = open(KTOOL, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "su: open %s: %s\n", KTOOL, strerror(errno));
		return 1;
	}
	if (write(fd, "ish", 3) != 3) {
		fprintf(stderr, "su: ish failed\n");
		close(fd);
		return 1;
	}
	close(fd);

	if (!is_allowed(caller)) {
		fprintf(stderr, "su: uid %d not in %s\n", caller, ALLOW_FILE);
		return 1;
	}

run:
	/* 别把父进程（app/zygote）的 fd 带进 shell */
	for (i = 3; i < 256; i++)
		close(i);

	if (argc >= 3 && strcmp(argv[1], "-c") == 0)
		execl(SHELL, "sh", "-c", argv[2], (char *)NULL);
	else if (argc >= 2)
		execvp(argv[1], argv + 1);
	else
		execl(SHELL, "sh", (char *)NULL);

	fprintf(stderr, "su: exec: %s\n", strerror(errno));
	return 127;
}
