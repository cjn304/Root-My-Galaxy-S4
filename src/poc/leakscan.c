/* SPDX-License-Identifier: GPL-3.0-or-later */

/*
 * leakscan —— 在设备上遍历 /proc /sys，抓所有落在内核线性映射区
 *             (0xc0000000 - 0xe7800000) 的 8 位十六进制地址
 *
 * 用法: leakscan <root> <depth>
 * 输出: path|addr|原始行(截断)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

#define MAXBUF  (256 * 1024)
#define MAXLINE 220

#define LO_ADDR 0xc0000000UL
#define HI_ADDR 0xe7800000UL

static char buf[MAXBUF];
static long n_files, n_read, n_hits;

static int is_hex(int c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
	       (c >= 'A' && c <= 'F');
}

static unsigned long parse_hex(const char *s)
{
	unsigned long v = 0;
	int i;
	for (i = 0; i < 8; i++) {
		int c = s[i], d;
		if (c >= '0' && c <= '9') d = c - '0';
		else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
		else return 0;
		v = (v << 4) | (unsigned long)d;
	}
	return v;
}

static void emit(const char *path, unsigned long addr, const char *ls, int len)
{
	int i;
	n_hits++;
	fputs(path, stdout);
	printf("|%08lx|", addr);
	if (len > MAXLINE) len = MAXLINE;
	for (i = 0; i < len; i++) {
		char c = ls[i];
		if (c < 0x20 || c > 0x7e) c = '.';
		putchar(c);
	}
	putchar('\n');
}

static void scan_file(const char *path)
{
	int fd, n, i;
	char *ls;

	/* 这些读不得：会崩 / 会挂 / 无意义 */
	if (strstr(path, "/mem") || strstr(path, "/pagemap") ||
	    strstr(path, "/kpagecount") || strstr(path, "/kpageflags") ||
	    strstr(path, "/kmsg") || strstr(path, "/sysrq-trigger") ||
	    strstr(path, "/clear_refs"))
		return;

	n_files++;
	fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return;
	n = read(fd, buf, MAXBUF - 1);
	close(fd);
	if (n <= 0)
		return;
	n_read++;
	buf[n] = 0;

	ls = buf;
	for (i = 0; i <= n; i++) {
		if (i == n || buf[i] == '\n') {
			int len = (int)(buf + i - ls);
			int j;
			for (j = 0; j + 8 <= len; j++) {
				int k, ok = 1;
				for (k = 0; k < 8; k++)
					if (!is_hex(ls[j + k])) { ok = 0; break; }
				if (!ok)
					continue;
				if (j > 0 && is_hex(ls[j - 1]))
					continue;
				if (j + 8 < len && is_hex(ls[j + 8]))
					continue;
				unsigned long v = parse_hex(ls + j);
				if (v >= LO_ADDR && v < HI_ADDR)
					emit(path, v, ls, len);
				j += 7;
			}
			ls = buf + i + 1;
		}
	}
}

static void scan_dir(const char *path, int depth)
{
	DIR *d = opendir(path);
	struct dirent *de;

	if (!d)
		return;
	while ((de = readdir(d))) {
		char p[512];
		struct stat st;

		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (snprintf(p, sizeof p, "%s/%s", path, de->d_name) >= (int)sizeof p)
			continue;
		if (stat(p, &st) != 0)
			continue;
		if (S_ISDIR(st.st_mode)) {
			if (depth > 0)
				scan_dir(p, depth - 1);
		} else if (S_ISREG(st.st_mode)) {
			scan_file(p);
		}
	}
	closedir(d);
}

int main(int argc, char **argv)
{
	const char *root = argc > 1 ? argv[1] : "/proc";
	int depth = argc > 2 ? atoi(argv[2]) : 1;

	setvbuf(stdout, NULL, _IOFBF, 1 << 16);
	scan_dir(root, depth);
	fflush(stdout);
	fprintf(stderr, "=== %s depth=%d files=%ld read=%ld hits=%ld ===\n",
		root, depth, n_files, n_read, n_hits);
	return 0;
}
