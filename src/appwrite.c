/*
 * appwrite — 用「目标 app 的 fsuid + untrusted_app 域」写文件（P4.27）
 *
 * 背景：写别人的 app 数据需要两把钥匙，但没有任何单一域同时拥有：
 *   init_shell    有 DAC 钥匙（uid0 + caps）
 *                 但没有 SELinux 钥匙（app_data_file:file 无 write，dir 无 create）
 *   untrusted_app 有 SELinux 钥匙（file write/create、dir create/add_name）
 *                 但 capability 规则为空（无 dac_override）
 *
 * 本工具把两把钥匙拼在同一个进程里：
 *   1. 先读源文件（此时还在 init_shell 域，能读任意路径）
 *   2. 写 /dev/ktool 的 "ctx u:r:untrusted_app:s0 <uid> <gid>"
 *      —— 模块换 security->sid，并**在内核里**直接写 cred->fsuid/fsgid
 *   3. 写目标文件（fsuid=owner 过 DAC，untrusted_app 过 SELinux）
 *
 * 为什么不由用户态 setfsuid（P4.27 实测踩坑）：
 *   sys_setfsuid() 第一步是 capable(CAP_SETUID)，该检查走 SELinux
 *   capability class；策略里 init_shell 的 capability 规则可能不含 setuid，
 *   被拒后 syscall **静默返回旧值、不设 errno**，用户态完全看不出来。
 *   内核侧写 cred 字段不经过任何检查，结论稳定。
 *
 * 用法: appwrite <src|-> <dst>
 *   目标 uid/gid 由 dst 的父目录 stat 得到；父目录必须已存在。
 *   src 为 "-" 时从 stdin 读。
 *
 * 权限要求：700 root:root（只有 root 能执行）。就算模式被改坏成 755，
 * 普通 app 执行也会在 ctx 那步被门禁拒（门只认 su 和 uid0 进程）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>

#define KTOOL "/dev/ktool"

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
		fprintf(stderr, "appwrite: open %s: %s\n", KTOOL, strerror(errno));
		return -1;
	}
	w = write(fd, msg, n);
	close(fd);
	if (w != n) {
		fprintf(stderr, "appwrite: ctx write '%s': %s\n", msg,
			w < 0 ? strerror(errno) : "short write");
		return -1;
	}
	return 0;
}

static char *read_all(const char *src, size_t *out_len)
{
	size_t cap = 1 << 20, len = 0;
	char *buf = malloc(cap);
	int fd;

	if (!buf)
		return NULL;
	fd = (strcmp(src, "-") == 0) ? 0 : open(src, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "appwrite: open %s: %s\n", src, strerror(errno));
		free(buf);
		return NULL;
	}
	for (;;) {
		ssize_t n;

		if (len == cap) {
			char *nb;

			cap *= 2;
			nb = realloc(buf, cap);
			if (!nb) {
				free(buf);
				if (fd)
					close(fd);
				return NULL;
			}
			buf = nb;
		}
		n = read(fd, buf + len, cap - len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "appwrite: read %s: %s\n", src, strerror(errno));
			free(buf);
			if (fd)
				close(fd);
			return NULL;
		}
		if (n == 0)
			break;
		len += n;
	}
	if (fd)
		close(fd);
	*out_len = len;
	return buf;
}

int main(int argc, char **argv)
{
	const char *src, *dst;
	char *buf, *tmp, *dir;
	size_t len = 0;
	struct stat st;
	int fd;
	size_t off;

	if (argc != 3) {
		fprintf(stderr, "usage: appwrite <src|-> <dst>\n");
		return 2;
	}
	src = argv[1];
	dst = argv[2];

	/* 1. 读源（init_shell 域，任意路径） */
	buf = read_all(src, &len);
	if (!buf)
		return 1;

	/* 2. 目标目录的 owner */
	tmp = strdup(dst);
	if (!tmp)
		return 1;
	dir = dirname(tmp);
	if (stat(dir, &st) != 0) {
		fprintf(stderr, "appwrite: stat %s: %s\n", dir, strerror(errno));
		return 1;
	}
	printf("appwrite: dst dir %s owner uid=%u gid=%u, src %zu bytes\n",
	       dir, (unsigned)st.st_uid, (unsigned)st.st_gid, len);

	/* 3. 两把钥匙一起拿：域换 untrusted_app，fsuid/fsgid 由内核写成 owner */
	if (write_ctx("ctx u:r:untrusted_app:s0", st.st_uid, st.st_gid) != 0)
		return 1;

	/* 4. 写目标（此刻 fsuid=owner + untrusted_app） */
	/* ctx 之后不许再碰 stdio（见文件末尾说明），失败一律 _exit */
	fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		_exit(3);
	for (off = 0; off < len;) {
		ssize_t n = write(fd, buf + off, len - off);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			_exit(4);
		}
		off += n;
	}
	if (close(fd) != 0)
		_exit(5);

	/*
	 * 注意：切到 untrusted_app 之后**不要**再写 stdout/stderr。
	 * 那是一次 security_file_permission 检查，对方是 shell 建的 pty/pipe，
	 * untrusted_app 拿不到写权限 → 拒绝 → 本内核的审计路径会 oops
	 * （avc_audit_pre_callback 里 strnlen 野指针，实测打挂进程）。
	 * 成功/失败一律用退出码表达。
	 */
	_exit(0);
}
