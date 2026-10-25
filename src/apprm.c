/* SPDX-License-Identifier: GPL-3.0-or-later */

/*
 * apprm — 用「目标 app 的 fsuid + untrusted_app 域」删除文件/目录（P4.28）
 *
 * 和 appwrite 同一套两只钥匙：
 *   DAC 钥匙     fsuid = 目标目录 owner（内核直写，不走 setfsuid 的 capable 检查）
 *   SELinux 钥匙 ctx -> u:r:untrusted_app:s0（策略给 dir create/add_name/remove_name）
 *
 * 为什么不直接用 init_shell + permissive：
 *   那条路依赖 permissive，等于关掉 SELinux；本工具不碰 permissive。
 *
 * 用法:
 *   apprm [-r] [-f] <path>...
 *      -r  递归删除目录
 *      -f  忽略不存在的路径，不报错
 *
 * 权限要求：700 root:root。普通 app 执行会卡在 ctx 那步（门禁只认 su 和 uid0）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>

#define KTOOL "/dev/ktool"

/* ctx 之后必须闭嘴：任何 stdio 写都是一次 security_file_permission，
 * 被拒会触发本内核审计路径的 oops。 */
static int quiet;

static int write_ctx(const char *ctx, uid_t uid, gid_t gid)
{
	char msg[128];
	int fd, n;
	ssize_t w;

	n = snprintf(msg, sizeof(msg), "%s %u %u", ctx, (unsigned)uid,
		     (unsigned)gid);
	if (n <= 0 || n >= (int)sizeof(msg))
		return -1;

	fd = open(KTOOL, O_WRONLY);
	if (fd < 0) {
		if (!quiet) fprintf(stderr, "apprm: open %s: %s\n", KTOOL, strerror(errno));
		return -1;
	}
	w = write(fd, msg, n);
	close(fd);
	if (w != n) {
		if (!quiet) fprintf(stderr, "apprm: ctx write '%s': %s\n", msg,
			w < 0 ? strerror(errno) : "short write");
		return -1;
	}
	return 0;
}

/* 切到「目标目录 owner + untrusted_app」，之后本进程就有删权限 */
static int enter_target(const char *path)
{
	char *tmp, *dir;
	struct stat st;
	int rc;

	tmp = strdup(path);
	if (!tmp)
		return -1;
	dir = dirname(tmp);
	if (stat(dir, &st) != 0) {
		if (!quiet) fprintf(stderr, "apprm: stat %s: %s\n", dir, strerror(errno));
		free(tmp);
		return -1;
	}
	quiet = 1;	/* 从这里开始不许再碰 stdio */
	rc = write_ctx("ctx u:r:untrusted_app:s0", st.st_uid, st.st_gid);
	free(tmp);
	return rc;
}

static int rm_one(const char *path, int recursive, int force, int is_top);

static int rm_dir(const char *path, int recursive, int force)
{
	DIR *d;
	struct dirent *e;
	int rc = 0;

	d = opendir(path);
	if (!d) {
		if (force && errno == ENOENT)
			return 0;
		if (!quiet) fprintf(stderr, "apprm: opendir %s: %s\n", path, strerror(errno));
		return -1;
	}
	if (!recursive) {
		closedir(d);
		if (!quiet) fprintf(stderr, "apprm: %s is a directory (use -r)\n", path);
		return -1;
	}
	while ((e = readdir(d))) {
		char child[4096];

		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		if (snprintf(child, sizeof(child), "%s/%s", path, e->d_name) >=
		    (int)sizeof(child)) {
			if (!quiet) fprintf(stderr, "apprm: path too long under %s\n", path);
			rc = -1;
			continue;
		}
		if (rm_one(child, recursive, force, 0) != 0)
			rc = -1;
	}
	closedir(d);
	if (rc == 0) {
		if (rmdir(path) != 0) {
			if (!quiet) fprintf(stderr, "apprm: rmdir %s: %s\n", path, strerror(errno));
			rc = -1;
		}
	}
	return rc;
}

static int rm_one(const char *path, int recursive, int force, int is_top)
{
	struct stat st;

	if (lstat(path, &st) != 0) {
		if (force && errno == ENOENT)
			return 0;
		if (!quiet) fprintf(stderr, "apprm: lstat %s: %s\n", path, strerror(errno));
		return -1;
	}
	if (S_ISDIR(st.st_mode))
		return rm_dir(path, recursive, force);

	if (unlink(path) != 0) {
		if (force && errno == ENOENT)
			return 0;
		return -1;
	}
	(void)is_top;
	return 0;
}

int main(int argc, char **argv)
{
	int recursive = 0, force = 0, i = 1, rc = 0, n = 0;

	while (i < argc && argv[i][0] == '-' && argv[i][1]) {
		if (!strcmp(argv[i], "-r")) {
			recursive = 1;
		} else if (!strcmp(argv[i], "-f")) {
			force = 1;
		} else {
			fprintf(stderr, "usage: apprm [-r] [-f] <path>...\n");
			return 2;
		}
		i++;
	}
	if (i >= argc) {
		fprintf(stderr, "usage: apprm [-r] [-f] <path>...\n");
		return 2;
	}

	/* 一次性切到目标 owner+域：同一目录下的多个文件共用一次切换。
	 * 不同 owner 的路径各自再切一次（代价很小，只需一次 write）。
	 *
	 * 注意：ctx 之后不再向 stdout/stderr 输出——那是 security_file_permission
	 * 检查，untrusted_app 写不了 shell 的 pty/pipe，拒绝会触发本内核审计路径的
	 * oops（实测打挂进程）。结果只用退出码表达。 */
	{
		uid_t cur_uid = (uid_t)-1;
		gid_t cur_gid = (gid_t)-1;

		for (; i < argc; i++) {
			char *tmp = strdup(argv[i]);
			struct stat st;

			if (!tmp)
				_exit(1);
			if (stat(dirname(tmp), &st) != 0) {
				free(tmp);
				rc = 1;
				continue;
			}
			free(tmp);
			if (st.st_uid != cur_uid || st.st_gid != cur_gid) {
				if (enter_target(argv[i]) != 0)
					_exit(1);
				cur_uid = st.st_uid;
				cur_gid = st.st_gid;
			}
			if (rm_one(argv[i], recursive, force, 1) != 0)
				rc = 1;
			else
				n++;
		}
	}
	_exit(rc);
}
