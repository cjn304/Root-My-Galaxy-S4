/*
 * su.c — GT-I9500 su（ktool + phh Superuser APK 授权，fork 版）
 *
 * 与 su_apk.c 的区别：socket 由「保持 app 域的子进程」持有，
 * 这样即使父进程提权到 init_shell，APK 也能连上 socket。
 *
 * 域关系（策略依据）：
 *   untrusted_app -> untrusted_app:unix_stream_socket = 全套（connectto/read/write）
 *   init_shell    -> untrusted_app:fifo_file = append,read,write   ← 管道可以跨界
 *   init_shell    -> untrusted_app:unix_stream_socket = 无
 *
 * 所以：socket 必须由 app 域的进程建；提权后的父进程只通过 pipe 与它通信。
 *
 * 预建目录：/data/local/tmp/sud（0777），部署时创建一次即可。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <signal.h>
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
/*
 * settings 表（含 superuser_access）在**另一个**库里：su.sqlite 只有 uid_policy，
 * superuser.sqlite 才有 settings（dex 里两套 create table 语句就是两个 helper）。
 * 用 immutable=1 打开：这两个库经常带着未回滚的 `-journal`，只读打开会触发回滚
 * （需要 unlink/写，init_shell 没有权限）→ 打开失败 → 读不到值。
 * immutable 让 sqlite 完全跳过锁与日志，纯读页。
 */
#define DB_URI "file:/data/data/me.phh.superuser/databases/su.sqlite?immutable=1"
#define SETTINGS_DB "file:/data/data/me.phh.superuser/databases/superuser.sqlite?immutable=1"
#define SETTINGS_DB_NAME "/data/data/me.phh.superuser/databases/superuser.sqlite"
#define SHELL       "/system/bin/sh"
#define SOCK_DIR    "/data/local/tmp/sud"
#define SOCK_FMT    SOCK_DIR "/s%d"
#define APK_ACT     "me.phh.superuser/com.koushikdutta.superuser.RequestActivity"
#define ASK_TIMEOUT 90

static int g_cfd = -1;

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

/* 1=allow -1=deny 0=无记录 */
static int db_check(int uid, const char *cmd)
{
	sqlite3 *db = NULL;
	sqlite3_stmt *st = NULL;
	int ret = 0;

	if (sqlite3_open_v2(DB_URI, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI,
			    NULL) != SQLITE_OK) {
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

#define AID_ROOT	0
#define SU_PKG_UID	10198	/* 兜底值：me.phh.superuser 正常安装时的 uid */
/*
 * 管理 App 的 uid 不写死：重装会重新分配（u0_aXXX）。
 * 直接 stat 它的数据目录拿 st_uid —— su 此时已在 init_shell，能读 app 目录。
 * 两个包名都试，覆盖 phh 版和 Koush 版。
 */
static int su_pkg_uid(void)
{
	static int cached = -1;
	static const char *dirs[] = {
		"/data/data/me.phh.superuser",
		"/data/data/com.koushikdutta.superuser"
	};
	struct stat st;
	unsigned i;

	if (cached >= 0)
		return cached;
	for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
		if (stat(dirs[i], &st) == 0 && st.st_uid > 0) {
			cached = (int)st.st_uid;
			return cached;
		}
	}
	cached = SU_PKG_UID;
	return cached;
}
/*
 * 「超级用户访问权限」真正的落点是**系统属性**，不是数据库。
 * 反编译 Settings.getSuperuserAccess()：
 *   SystemProperties.get("persist.sys.root_access")，默认 3
 * 四档语义（Koush 原版）：
 *   0 = 禁用  1 = 仅限于应用程序  2 = 仅限于 ADB  3 = 应用程序和 ADB
 * 改设置时 App 会 exec("su") 然后把 "setprop persist.sys.root_access N"
 * 写进 su 的 stdin —— 这一点决定了 su 在禁用档下必须留一条"只许 setprop"的缝，
 * 否则用户永远没法从 UI 改回来。
 */
#define PROP_PATH "/data/property/persist.sys.root_access"

static int read_access_code(void)
{
	char buf[16];
	int fd, n, v;

	fd = open(PROP_PATH, O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	v = atoi(buf);
	if (v < 0 || v > 3)
		return -1;
	return v;
}

#define AID_SHELL	2000
#define ACCESS_OVERRIDE	"/data/local/tmp/su_access_mode"

/* 读 settings 表的一个键；读不到就当空串（调用方走默认值） */
static void db_setting(const char *key, char *out, size_t n)
{
	sqlite3 *db = NULL;
	sqlite3_stmt *st = NULL;

	out[0] = 0;
	if (sqlite3_open_v2(SETTINGS_DB, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI,
			    NULL) != SQLITE_OK) {
		if (db)
			sqlite3_close(db);
		return;
	}
	if (sqlite3_prepare_v2(db, "select value from settings where key=?",
			       -1, &st, NULL) == SQLITE_OK) {
		sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC);
		if (sqlite3_step(st) == SQLITE_ROW) {
			const char *v = (const char *)sqlite3_column_text(st, 0);

			if (v)
				snprintf(out, n, "%s", v);
		}
		sqlite3_finalize(st);
	}
	sqlite3_close(db);
}

/*
 * 现读「超级用户访问权限」：先看 /data/local/tmp/su_access_mode
 * （只有 shell/root 建得出来——/data/local/tmp 是 shell:shell 0771），
 * 没有再读 APK 的 settings 表。值与原版一致：
 *   access_disabled / apps_only / adb_only / apps_and_adb
 */
static void read_access_mode(char *out, size_t n)
{
	FILE *f;

	out[0] = 0;
	f = fopen(ACCESS_OVERRIDE, "r");
	if (f) {
		if (fgets(out, (int)n, f)) {
			char *p = out, *q;

			while (*p == ' ' || *p == '\t')
				p++;
			if (p != out)
				memmove(out, p, strlen(p) + 1);
			q = out + strlen(out);
			while (q > out && (q[-1] == '\n' || q[-1] == '\r' ||
					   q[-1] == ' ' || q[-1] == '\t'))
				*--q = 0;
		}
		fclose(f);
		if (out[0])
			return;
	}
	{
		int code = read_access_code();

		if (code >= 0) {
			static const char *names[4] = {
				"access_disabled", "apps_only", "adb_only",
				"apps_and_adb"
			};

			snprintf(out, n, "%s", names[code]);
			return;
		}
	}
	db_setting("superuser_access", out, n);
}

/* 1=这次调用允许 0=拒绝。root 自己在 main 里就绕过了，不会进来 */
static int access_allows(int caller)
{
	char mode[64];

	read_access_mode(mode, sizeof(mode));
	if (!mode[0] || !strcmp(mode, "apps_and_adb"))
		return 1;			/* 默认，保持旧行为 */
	if (!strcmp(mode, "access_disabled"))
		return 0;
	if (!strcmp(mode, "apps_only"))
		return caller != AID_SHELL;	/* 2000 是 adb shell */
	if (!strcmp(mode, "adb_only"))
		return caller == AID_SHELL;
	return 1;				/* 不认识的值：不锁死 */
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

static void write_all(int fd, const char *s)
{
	size_t n = strlen(s), off = 0;
	while (off < n) {
		ssize_t w = write(fd, s + off, n - off);
		if (w <= 0) return;
		off += w;
	}
}

/*
 * 子进程：保持 app 域，独占 socket。
 * 参数：p2c[0] 读父进程指令，c2p[1] 写结果给父进程。
 *   "go"  → 建 socket / listen / accept / 收发协议
 *   其它  → 直接退出
 */
static void child_sock(int p2c_r, int c2p_w, int caller, int admin_uid,
		       const char *cmd, const char *sock_path)
{
	char cmd_buf[8];
	int sfd, cfd = -1, n, i;
	struct sockaddr_un sa;
	char buf[128];

	signal(SIGALRM, SIG_DFL);
	alarm(ASK_TIMEOUT);

	n = read(p2c_r, cmd_buf, sizeof(cmd_buf) - 1);
	if (n <= 0 || strncmp(cmd_buf, "go", 2) != 0)
		_exit(2);

	unlink(sock_path);
	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd < 0)
		_exit(3);
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, sock_path, sizeof(sa.sun_path) - 1);
	if (bind(sfd, (struct sockaddr *)&sa, sizeof(sa))) {
		write_all(c2p_w, "ERR:BIND");
		_exit(4);
	}
	chmod(sock_path, 0777);
	listen(sfd, 1);

	/* 告诉父进程 socket 已就绪，可以去 am start 了 */
	write_all(c2p_w, "READY");

	/*
	 * socket 在 /data/local/tmp/sud 下、权限 0777，同目录任何应用都进得来。
	 * 不校验连接方的话，**任何 app 都能抢先连上 su 的 socket 发一个 "ALLOW"**，
	 * 等于完全绕过授权弹窗。这里用 SO_PEERCRED 只认管理 App 的 uid；
	 * 别的连接直接关掉，继续等真 APK（最多 3 次）。
	 */
	for (i = 0; i < 3; i++) {
		struct ucred cr;
		socklen_t cl = sizeof(cr);

		cfd = accept(sfd, NULL, NULL);
		if (cfd < 0)
			continue;
		if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) == 0 &&
		    (int)cr.uid == admin_uid)
			break;
		close(cfd);
		cfd = -1;
	}
	close(sfd);
	if (cfd < 0) {
		write_all(c2p_w, "ERR:PEER");
		_exit(5);
	}

	{
		char uidbuf[32], pidbuf[32];
		snprintf(uidbuf, sizeof(uidbuf), "%d", caller);
		snprintf(pidbuf, sizeof(pidbuf), "%d", getppid());
		if (write_frame(cfd, "version", "1") ||
		    write_frame(cfd, "binary.version", "17") ||
		    write_frame(cfd, "pid", pidbuf) ||
		    write_frame(cfd, "from.name",
				caller == AID_SHELL ? "adb" : "app") ||
		    write_frame(cfd, "to.name", "root") ||
		    write_frame(cfd, "from.uid", uidbuf) ||
		    write_frame(cfd, "to.uid", "0") ||
		    write_frame(cfd, "from.bin", "/system/xbin/su") ||
		    write_frame(cfd, "bind.from", "") ||
		    write_frame(cfd, "bind.to", "") ||
		    write_frame(cfd, "init", "") ||
		    write_frame(cfd, "command", cmd ? cmd : "sh") ||
		    write_frame(cfd, "eof", "")) {
			write_all(c2p_w, "ERR:FRAME");
			_exit(6);
		}
	}

	memset(buf, 0, sizeof(buf));
	n = read(cfd, buf, sizeof(buf) - 1);
	close(cfd);
	unlink(sock_path);
	if (n <= 0) {
		write_all(c2p_w, "ERR:READ");
		_exit(7);
	}
	buf[n] = 0;
	write_all(c2p_w, strstr(buf, "ALLOW") ? "ALLOW" : "DENY");
	_exit(0);
}

int main(int argc, char **argv)
{
	int caller = getuid();
	int p2c[2], c2p[2];
	pid_t pid;
	int fd, i, d;
	const char *cmd = NULL;
	char msg[64];
	char sock_path[64];
	ssize_t n;

	/*
	 * -v / --version：纯查询，不提权、不弹窗。
	 *
	 * phh Superuser 的开机自检（SuCheckerReceiver → BOOT_COMPLETED →
	 * SuHelper.checkSu）会跑 `su -v`，要求：
	 *   ① 退出码 0  ② 有输出  ③ 输出含 APK 包名  ④ 第一个空格分词 == "17"
	 * 任一条不满足就弹 "su binary outdated" 通知（划掉后静默 3 次开机，
	 * 所以表现为"有时候提示"）。phh 原版的输出是
	 *   "17 me.phh.superuser cm-su subind suinit"
	 * （VERSION = "17 " REQUESTOR）。这里两个包名都带上，
	 * 兼容 me.phh / com.koushikdutta 两种 APK。
	 */
	if (argc == 2 && (strcmp(argv[1], "-v") == 0 ||
			  strcmp(argv[1], "--version") == 0)) {
		printf("17 me.phh.superuser com.koushikdutta.superuser\n");
		return 0;
	}

	if (argc >= 3 && strcmp(argv[1], "-c") == 0)
		cmd = argv[2];
	else if (argc >= 2)
		cmd = argv[1];

	/* 每个 su 进程独立的 socket 路径，避免并发互相踩 */
	snprintf(sock_path, sizeof(sock_path), SOCK_FMT, (int)getpid());

	if (caller != 0) {
		int admin_uid = su_pkg_uid();

		if (pipe(p2c) || pipe(c2p))
			return 1;

		pid = fork();
		if (pid == 0) {                 /* A：保持 app 域 */
			close(p2c[1]);
			close(c2p[0]);
			child_sock(p2c[0], c2p[1], caller, admin_uid, cmd,
				   sock_path);
			_exit(9);
		}
		close(p2c[0]);
		close(c2p[1]);

		/* 父进程提权 */
		fd = open(KTOOL, O_WRONLY);
		if (fd < 0) {
			/* 跨域写管道会被 fd use 拒，用 close 让子进程读到 EOF 自行退出 */
			close(p2c[1]);
			fprintf(stderr, "su: open %s: %s\n", KTOOL, strerror(errno));
			return 1;
		}
		if (write(fd, "ish", 3) != 3) {
			close(fd);
			close(p2c[1]);
			fprintf(stderr, "su: ish failed\n");
			return 1;
		}
		close(fd);

		/*
		 * 超级用户访问权限（phh 那四档）。
		 * 必须放在 ish 之后：settings 表在 APK 的私有目录里，
		 * 以 app 身份读不到（DAC + SELinux 都不行），init_shell 才能读。
		 */
		/*
		 * 管理 App（phh Superuser）改「超级用户访问权限」的做法是：
		 *   Runtime.exec("su")  →  往 stdin 写 "setprop persist.sys.root_access N"
		 * 它既没有 -c 也不是白名单调用，走正常流程会去弹窗（而它自己就是弹窗的
		 * 提供方），必须在这里单独处理：
		 *   - 命中 setprop 行 → 直接以 init_shell 执行（模块已给 init_shell
		 *     system_prop:property_service set，否则属性写不进去）；
		 *   - 不命中 → 保持旧行为（允许就执行这一行，禁用就拒）。
		 * 只对管理 App 的 uid 生效，别的应用拿不到这条缝。
		 */
		if (caller == su_pkg_uid() && cmd == NULL) {
			char line[128] = "";
			int v = -1;

			if (fgets(line, sizeof(line), stdin) &&
			    sscanf(line, "setprop persist.sys.root_access %d", &v) == 1 &&
			    v >= 0 && v <= 3) {
				/* 让 A 读到 EOF 自行退出，别留一个等 90s 的子进程 */
				close(p2c[1]);
				close(c2p[0]);
				waitpid(pid, NULL, 0);
				execl(SHELL, "sh", "-c", line, (char *)NULL);
				_exit(127);
			}
			/* 空行（EOF 立即到达）不要 exec 空命令：直接按拒绝处理，
			 * 免得 App 的 waitFor 拿到 0 却什么都没发生。 */
			if (access_allows(caller) && line[0]) {
				close(p2c[1]);
				close(c2p[0]);
				waitpid(pid, NULL, 0);
				execl(SHELL, "sh", "-c", line, (char *)NULL);
				_exit(127);
			}
			fprintf(stderr, "su: denied\n");
			return 1;
		}

		if (!access_allows(caller)) {
			char mode[64];

			read_access_mode(mode, sizeof(mode));
			close(p2c[1]);
			waitpid(pid, NULL, 0);
			fprintf(stderr, "su: %s, deny uid %d (admin %d)\n",
				mode[0] ? mode : "disabled", caller, su_pkg_uid());
			return 1;
		}

		/* 白名单 / 数据库：命中就不弹窗，通知 A 退出 */
		/*
		 * adb 的请求不该经过弹窗：APK 收到 uid=2000 会按普通 "app" 处理
		 * 并秒回 DENY（实测），于是 adb root 在这些档位下完全不可用。
		 *
		 *   adb_only   语义就是"ADB 可以、应用不行"，直接放行。
		 *   apps_and_adb 语义同样是"应用和 ADB 都行"，也直接放行；
		 *               应用侧仍然走 allowlist / 弹窗（不走这个分支）。
		 *   空值       等同 apps_and_adb（read_access_mode 的既定行为）。
		 *
		 * 只有 apps_only / access_disabled 会落到这里且 caller==2000，
		 * 但那时 access_allows() 已经把它们拒掉了，走不到这一步。
		 */
		if (caller == AID_SHELL) {
			char m2[64];

			read_access_mode(m2, sizeof(m2));
			if (!m2[0] || !strcmp(m2, "adb_only") ||
			    !strcmp(m2, "apps_and_adb")) {
				close(p2c[1]);
				waitpid(pid, NULL, 0);
				goto run;
			}
		}

		if (is_allowed(caller)) {
			/* P4.91: 不能 write_all —— 父进程已切 init_shell，
			 * 写 untrusted_app 域创建的管道会触发 fd use 拒绝。
			 * close() 不受 SELinux 管辖，子进程读到 EOF 立即 _exit。 */
			close(p2c[1]);
			waitpid(pid, NULL, 0);
			goto run;
		}
		d = db_check(caller, cmd);
		if (d == 1) {
			/* P4.91: 不能 write_all —— 父进程已切 init_shell，
			 * 写 untrusted_app 域创建的管道会触发 fd use 拒绝。
			 * close() 不受 SELinux 管辖，子进程读到 EOF 立即 _exit。 */
			close(p2c[1]);
			waitpid(pid, NULL, 0);
			goto run;
		}
		if (d == -1) {
			/* P4.91: 不能 write_all —— 父进程已切 init_shell，
			 * 写 untrusted_app 域创建的管道会触发 fd use 拒绝。
			 * close() 不受 SELinux 管辖，子进程读到 EOF 立即 _exit。 */
			close(p2c[1]);
			waitpid(pid, NULL, 0);
			fprintf(stderr, "su: denied by policy (uid %d)\n", caller);
			return 1;
		}

		/* 需要弹窗：让 A 建 socket */
		write_all(p2c[1], "go");

		memset(msg, 0, sizeof(msg));
		n = read(c2p[0], msg, sizeof(msg) - 1);
		if (n <= 0 || strncmp(msg, "READY", 5) != 0) {
			fprintf(stderr, "su: socket not ready (%s)\n", msg);
			if (strstr(msg, "PEER"))
				fprintf(stderr,
					"    连接方不是管理 App（uid %d），已丢弃\n",
					su_pkg_uid());
			if (strstr(msg, "BIND"))
				fprintf(stderr,
					"    检查 socket 目录：ls -ld %s\n"
					"    缺失时用 shell 身份建：mkdir -p %s && chmod 777 %s\n",
					SOCK_DIR, SOCK_DIR, SOCK_DIR);
			return 1;
		}

		/* uid 0 才能拉起 exported=false 的 RequestActivity */
		{
			pid_t p2 = fork();
			int st2 = 0;

			if (p2 == 0) {
				execl("/system/bin/am", "am", "start", "-n", APK_ACT,
				      "--es", "socket", sock_path, (char *)NULL);
				_exit(127);
			}
			waitpid(p2, &st2, 0);
			/*
			 * am 起不来（被 SELinux 拒 / 没有 am）时不能继续等：
			 * 子进程的 alarm 是 90s，父进程会一直阻塞在下面的 read，
			 * 表现为 su 卡死一分半。直接收尾。
			 */
			if (!WIFEXITED(st2) || WEXITSTATUS(st2) != 0) {
				close(p2c[1]);
				kill(pid, SIGKILL);
				waitpid(pid, NULL, 0);
				fprintf(stderr,
					"su: am start failed (exit %d)\n",
					WIFEXITED(st2) ? WEXITSTATUS(st2) : -1);
				return 1;
			}
		}

		memset(msg, 0, sizeof(msg));
		n = read(c2p[0], msg, sizeof(msg) - 1);
		waitpid(pid, NULL, 0);
		if (n <= 0 || strncmp(msg, "ALLOW", 5) != 0) {
			fprintf(stderr, "su: denied (uid %d, %s)\n", caller, msg);
			return 1;
		}
	}

run:
	for (i = 3; i < 256; i++)
		close(i);

	if (argc >= 3 && strcmp(argv[1], "-c") == 0) {
		execl(SHELL, "sh", "-c", argv[2], (char *)NULL);
	} else if (argc >= 2) {
		execvp(argv[1], argv + 1);
	} else {
		execl(SHELL, "sh", (char *)NULL);
	}

	fprintf(stderr, "su: exec: %s\n", strerror(errno));
	return 127;
}
