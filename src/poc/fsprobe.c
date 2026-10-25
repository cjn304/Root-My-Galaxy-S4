/* SPDX-License-Identifier: GPL-3.0-or-later */

/*
 * fsprobe — 打印凭据与各路径写入的精确 errno（P4.27 排查用）
 * 注意：不要用 setfsuid(-1) 读 fsuid——CAP_SETUID 生效时它会把 fsuid 真的设成 -1，
 *       后续 open 全部 EACCES。改从 /proc/self/status 的 Uid 第四列读。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

static void show_ids(void)
{
	char line[256];
	FILE *f;

	printf("uid=%d euid=%d gid=%d egid=%d\n",
	       (int)getuid(), (int)geteuid(), (int)getgid(), (int)getegid());
	f = fopen("/proc/self/status", "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			if (!strncmp(line, "Uid:", 4) || !strncmp(line, "Gid:", 4) ||
			    !strncmp(line, "CapEff:", 7) || !strncmp(line, "CapPrm:", 7) ||
			    !strncmp(line, "CapBnd:", 7))
				printf("%s", line);
		}
		fclose(f);
	}
}

static void try_create(const char *dir)
{
	char p[256];
	int fd;

	snprintf(p, sizeof(p), "%s/_probe", dir);
	fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		printf("  create %-22s errno=%d (%s)\n", dir, errno, strerror(errno));
		return;
	}
	if (write(fd, "x", 1) != 1)
		printf("  create %-22s write errno=%d\n", dir, errno);
	else
		printf("  create %-22s OK\n", dir);
	close(fd);
	unlink(p);
}

static void try_overwrite(const char *file)
{
	int fd = open(file, O_WRONLY);

	if (fd < 0)
		printf("  overwrite %-19s errno=%d (%s)\n", file, errno, strerror(errno));
	else {
		printf("  overwrite %-19s OK (open only)\n", file);
		close(fd);
	}
}

int main(void)
{
	static const char *dirs[] = {
		"/system/xbin", "/system/etc", "/system/bin",
		"/data/system", "/data/local/tmp", "/efs", "/cache", NULL
	};
	int i;

	show_ids();
	printf("--- tests ---\n");
	try_overwrite("/system/lib/modules/ktool_mod.ko");
	for (i = 0; dirs[i]; i++) {
		struct stat st;

		if (stat(dirs[i], &st) != 0) {
			printf("  %-24s stat errno=%d\n", dirs[i], errno);
			continue;
		}
		printf("  %-24s mode=%o uid=%u gid=%u\n", dirs[i],
		       st.st_mode & 07777, (unsigned)st.st_uid, (unsigned)st.st_gid);
		try_create(dirs[i]);
	}
	return 0;
}
