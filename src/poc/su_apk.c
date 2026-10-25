/*
 * su.c — GT-I9500 su（ktool + phh Superuser APK 授权）
 *
 *   su            交互 shell
 *   su -c "cmd"   执行单条命令
 *   su cmd args   直接执行
 *
 * 授权顺序：
 *   1. 白名单 /data/system/su_allow 命中 → 直接给 root（不弹窗）
 *   2. 否则拉起 APK 的 RequestActivity，按 phh 的 socket 协议交互
 *      [4B BE nameLen][name][4B BE dataLen][data] ... 直到 name="eof"
 *      APK 回写 "socket:ALLOW" 或 "socket:DENY"
 *   3. 超时/拒绝 → 退出
 *
 * 注意：am start 的目标 Activity 是 android:exported=false，
 * 只有 uid 0 能拉起（AMS checkComponentPermission 对 uid 0 直接 GRANTED），
 * 所以必须在 ish 提权之后再做。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <arpa/inet.h>
#include <sqlite3.h>

#define KTOOL       "/dev/ktool"
#define ALLOW_FILE  "/data/system/su_allow"
#define DB_PATH     "/data/data/me.phh.superuser/databases/su.sqlite"
#define SHELL       "/system/bin/sh"
#define SOCK_PATH   "/data/local/tmp/.su_sock"
#define APK_ACT     "me.phh.superuser/com.koushikdutta.superuser.RequestActivity"
#define APK_TIMEOUT 60

static int is_allowed(int uid)
{
	FILE *f = fopen(ALLOW_FILE, "r");
	char line[64];

	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		char *p = line;
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n' || *p == 0)
			continue;
		if (atoi(p) == uid) {
			fclose(f);
			return 1;
		}
	}
	fclose(f);
	return 0;
}

/* 返回 1=allow -1=deny 0=无记录（需要弹窗） */
static int db_check(int uid, const char *cmd)
{
	sqlite3 *db = NULL;
	sqlite3_stmt *st = NULL;
	int ret = 0;

	if (sqlite3_open_v2(DB_PATH, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
		if (db)
			sqlite3_close(db);
		return 0;
	}
	if (sqlite3_prepare_v2(db, "select policy, until, command from uid_policy where uid=?",
			       -1, &st, NULL) == SQLITE_OK) {
		time_t now = time(NULL);
		sqlite3_bind_int(st, 1, uid);
		while (sqlite3_step(st) == SQLITE_ROW) {
			const char *pol = (const char *)sqlite3_column_text(st, 0);
			int until = sqlite3_column_int(st, 1);
			const char *c = (const char *)sqlite3_column_text(st, 2);
			int match = (!c || !*c || (cmd && !strcmp(c, cmd)));

			if (!match)
				continue;
			if (until != 0 && until <= (int)now)
				continue;
			if (pol && !strcmp(pol, "allow")) { ret = 1; break; }
			if (pol && !strcmp(pol, "deny")) { ret = -1; break; }
		}
		sqlite3_finalize(st);
	}
	sqlite3_close(db);
	return ret;
}

static int write_frame(int fd, const char *name, const char *data)
{
	uint32_t l;
	size_t nl = strlen(name), dl = strlen(data);

	l = htonl((uint32_t)nl);
	if (write(fd, &l, 4) != 4) return -1;
	if (nl && write(fd, name, nl) != (ssize_t)nl) return -1;
	l = htonl((uint32_t)dl);
	if (write(fd, &l, 4) != 4) return -1;
	if (dl && write(fd, data, dl) != (ssize_t)dl) return -1;
	return 0;
}

#define W(n, d) do { if (write_frame(cfd, n, d)) goto fail; } while (0)

/* 返回 1=允许 0=拒绝 -1=出错 */
static int ask_apk(int caller, const char *cmd)
{
	int sfd, cfd = -1, ret = -1;
	struct sockaddr_un sa;
	pid_t p;
	char buf[64];
	ssize_t n = 0;

	unlink(SOCK_PATH);
	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd < 0)
		return -1;
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, SOCK_PATH, sizeof(sa.sun_path) - 1);
	if (bind(sfd, (struct sockaddr *)&sa, sizeof(sa))) {
		close(sfd);
		return -1;
	}
	chmod(SOCK_PATH, 0777);
	listen(sfd, 1);

	p = fork();
	if (p == 0) {
		close(sfd);
		execl("/system/bin/am", "am", "start", "-n", APK_ACT,
		      "--es", "socket", SOCK_PATH, (char *)NULL);
		_exit(127);
	}
	waitpid(p, NULL, 0);

	cfd = accept(sfd, NULL, NULL);
	close(sfd);
	if (cfd < 0)
		goto out;

	snprintf(buf, sizeof(buf), "%d", caller);
	{
		char pidbuf[32];
		snprintf(pidbuf, sizeof(pidbuf), "%d", getppid());
		W("version", "1");
		W("binary.version", "17");
		W("pid", pidbuf);
		W("from.name", "app");
		W("to.name", "root");
		W("from.uid", buf);
		W("to.uid", "0");
		W("from.bin", "/system/xbin/su");
		W("bind.from", "");
		W("bind.to", "");
		W("init", "");
		W("command", cmd ? cmd : "sh");
		W("eof", "");
	}

	memset(buf, 0, sizeof(buf));
	{
		char *q = buf;
		int left = sizeof(buf) - 1;
		while (left > 0 && (n = read(cfd, q, left)) > 0) {
			q += n;
			left -= n;
		}
	}
	close(cfd);
	ret = strstr(buf, "ALLOW") ? 1 : 0;
	goto out;

fail:
	close(cfd);
out:
	unlink(SOCK_PATH);
	return ret;
}

int main(int argc, char **argv)
{
	int caller = getuid();
	int fd, i;
	const char *cmd = NULL;

	if (argc >= 3 && strcmp(argv[1], "-c") == 0)
		cmd = argv[2];
	else if (argc >= 2)
		cmd = argv[1];

	if (caller != 0) {
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
			int d = db_check(caller, cmd);

			if (d == 1) {
				/* APK 已记住：直接放行 */
			} else if (d == -1) {
				fprintf(stderr, "su: denied by policy (uid %d)\n", caller);
				return 1;
			} else {
				int ok = ask_apk(caller, cmd);
				if (ok != 1) {
					fprintf(stderr, "su: denied (uid %d)\n", caller);
					return 1;
				}
			}
		}
	}

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
