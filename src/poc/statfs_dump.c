/*
 * statfs_dump —— 逐字段打印 statfs 返回值，判定 d3609fe8 属于哪个字段
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/statfs.h>
#include <sys/types.h>

int main(void)
{
	struct statfs st;
	uint32_t *w = (uint32_t *)&st;
	int i;
	const char *paths[] = { "/data", "/cache", "/system", "/", "/proc", "/dev" };

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("sizeof(struct statfs) = %zu\n\n", sizeof(struct statfs));

	for (i = 0; i < 6; i++) {
		memset(&st, 0xAA, sizeof st);      /* 全 0xAA，便于看哪些字节被内核改 */
		if (statfs(paths[i], &st) < 0) {
			printf("%-10s statfs fail\n", paths[i]);
			continue;
		}
		printf("%-10s type=%#x bsize=%u namelen=%u frsize=%u flags=%#x\n",
		       paths[i], (unsigned)st.f_type, (unsigned)st.f_bsize,
		       (unsigned)st.f_namelen, (unsigned)st.f_frsize,
		       (unsigned)st.f_flags);
		printf("           f_fsid = %08x %08x\n",
		       (unsigned)st.f_fsid.__val[0], (unsigned)st.f_fsid.__val[1]);
		printf("           f_spare= %08x %08x %08x %08x\n",
		       (unsigned)st.f_spare[0], (unsigned)st.f_spare[1],
		       (unsigned)st.f_spare[2], (unsigned)st.f_spare[3]);
		printf("           raw:");
		{
			int k;
			for (k = 0; k < (int)(sizeof(st) / 4); k++)
				printf(" %02x:%08x", k * 4, w[k]);
		}
		printf("\n\n");
	}
	return 0;
}
