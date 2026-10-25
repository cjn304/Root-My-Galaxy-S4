/* fstest — 判定 setfsgid/setfsuid 失败的确切原因（P4.27 诊断） */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/fsuid.h>
#include <sys/types.h>

static void show(const char *tag)
{
	FILE *f = fopen("/proc/self/status", "r");
	char line[256];

	printf("--- %s ---\n", tag);
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "Uid:", 4) || !strncmp(line, "Gid:", 4) ||
		    !strncmp(line, "CapEff:", 7) || !strncmp(line, "CapPrm:", 7))
			printf("  %s", line);
	}
	fclose(f);
}

int main(void)
{
	gid_t want = 10199;
	uid_t wu = 10199;
	int r;

	show("before");

	errno = 0;
	r = setfsgid(want);
	printf("setfsgid(%u) -> ret=%d errno=%d (%s)\n", (unsigned)want, r,
	       errno, strerror(errno));
	errno = 0;
	r = setfsgid(want);
	printf("setfsgid(%u) #2 -> ret=%d errno=%d (%s)  [ret should be %u]\n",
	       (unsigned)want, r, errno, strerror(errno), (unsigned)want);

	errno = 0;
	r = setfsuid(wu);
	printf("setfsuid(%u) -> ret=%d errno=%d (%s)\n", (unsigned)wu, r,
	       errno, strerror(errno));
	errno = 0;
	r = setfsuid(wu);
	printf("setfsuid(%u) #2 -> ret=%d errno=%d (%s)  [ret should be %u]\n",
	       (unsigned)wu, r, errno, strerror(errno), (unsigned)wu);

	show("after");

	/* 校验：fsuid 生效时，开 0700 的 app 目录应当成功 */
	errno = 0;
	if (access("/data/data/com.amaze.filemanager", R_OK | X_OK) == 0)
		printf("access(app dir) OK\n");
	else
		printf("access(app dir) FAIL errno=%d (%s)\n", errno, strerror(errno));

	errno = 0;
	{
		FILE *f = fopen("/data/data/com.amaze.filemanager/_probe", "w");
		if (f) {
			fputs("x", f);
			fclose(f);
			printf("create probe file OK\n");
			unlink("/data/data/com.amaze.filemanager/_probe");
		} else {
			printf("create probe file FAIL errno=%d (%s)\n", errno,
			       strerror(errno));
		}
	}
	return 0;
}
