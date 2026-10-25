/* SPDX-License-Identifier: GPL-3.0-or-later */

/*
 * targets.h — 机型/build 适配表（P4.29）
 *
 * 为什么主键是「机型 + 内核 version 串」而不是 ROM build id：
 *   下面这些地址全部来自 **内核镜像**（vmlinux 的 .text/.data/.bss 布局），
 *   同一个内核被不同 ROM 复用时地址完全一样；反过来同一个 ROM build id
 *   在不同内核上地址必然不同。所以：
 *     机型(ro.product.device)  用于确认是同一颗 SoC / 同一套 defconfig
 *     内核(/proc/version)      用于确认是同一个镜像布局  ← 主键
 *     build(ro.build.display.id) 只作记录和人工对照
 *
 * 字段分三类，换目标时只有第一类必须重新推导：
 *   [A] build 相关（每个内核镜像都不同）—— 必须逐个推导
 *   [B] 内核配置相关（同一 defconfig 内通用）—— 通常照抄，除非内核选项变了
 *   [C] 代码逻辑 —— 不需要动
 *
 * 加新目标的步骤见 P4.29_机型build适配表.md。
 */
#ifndef KTOOL_TARGETS_H
#define KTOOL_TARGETS_H

struct ktool_target {
	/* ---------- 身份 ---------- */
	const char *model;	/* ro.product.model，如 GT-I9500 */
	const char *device;	/* ro.product.device，如 ja3g */
	const char *build;	/* ro.build.display.id */
	const char *kernel;	/* /proc/version 的 version 段，如 3.4.5-6264821 */
	const char *sepf;	/* SEPF 版本串，可选交叉校验 */

	/* ---------- [A] build 相关地址：换内核就要重推 ---------- */
	unsigned long init_task;	/* init_task（task 链表锚点） */
	unsigned long modprobe_path;	/* modprobe_path，256 字节可写 .data，
					 * 借来当假 ebitmap 节点的暂存区 */
	unsigned long permissive_map;	/* policydb.permissive_map（struct ebitmap） */
	unsigned long avc_slots;	/* avc_cache.slots[512]，仅调试命令用 */
	unsigned long exec_br;		/* sys_execve 里 KNOX 检查块的 beq */
	unsigned long lkmauth_bootmode;	/* lkmauth_bootmode（BSS，每启动归零） */
	unsigned int  exec_br_orig;	/* 原始指令（beq） */
	unsigned int  exec_br_patch;	/* 打成的指令（b do_execve） */

	/* ---------- [B] 内核配置相关偏移：同 defconfig 通用 ---------- */
	unsigned int off_task_tasks;		/* task_struct.tasks（list_head） */
	unsigned int off_task_real_cred;	/* task_struct.real_cred */
	unsigned int off_task_cred;		/* task_struct.cred */
	unsigned int off_task_comm;		/* task_struct.comm */
	unsigned int off_cred_uid;		/* cred.uid */
	unsigned int off_cred_caps;		/* cred.cap_inheritable（后跟 3 组 cap） */
	unsigned int off_cred_security;		/* cred.security（task_security_struct*） */

	/* ---------- [A2] 策略相关 ---------- */
	unsigned int perm_bit;	/* init_shell 的 **type value**（不是 SID！），
				 * min permissive 就设这一位。从策略里数出来，
				 * 换机型/换策略必变。 */

	/* ---------- 状态 ---------- */
	unsigned char verified;	/* 1 = 真机跑通过完整链路 */
	const char *note;
};

static const struct ktool_target ktool_targets[] = {
	{
		.model  = "GT-I9500",
		.device = "ja3g",
		.build  = "LRX22C.I9500ZSSHQD1",
		.kernel = "3.4.5-6264821",
		.sepf   = "SEPF_GT-I9500_5.0.1-1_0039",

		.init_task        = 0xc0b79be0UL,
		.modprobe_path    = 0xc0b9ec3cUL,
		.permissive_map   = 0xc0c4efccUL,
		.avc_slots        = 0xc0c4bc70UL,
		.exec_br          = 0xc0012164UL,
		.lkmauth_bootmode = 0xc0c0ae28UL,
		.exec_br_orig     = 0x0a000002U,
		.exec_br_patch    = 0xea000047U,

		.off_task_tasks     = 0x1d0,
		.off_task_real_cred = 0x2f8,
		.off_task_cred      = 0x2fc,
		.off_task_comm      = 0x304,
		.off_cred_uid       = 0x04,
		.off_cred_caps      = 0x28,
		.off_cred_security  = 0x58,

		.perm_bit = 986,	/* init_shell（sepolicy_parse.py 数出来的） */

		.verified = 1,
		.note = "本机验证：root/ctx/ish/门禁/permissive/restore/appwrite/apprm 全通",
	},
	/*
	 * 加新目标：按 P4.29 推 6 个 [A] 地址 + 核对 3 个 [B] 偏移，
	 * 逻辑一行不用改。偏移现在可以用 ktool 直接在设备上标定
	 * （sym 拿符号 → scan4 找引用 → walk 顺指针 → fld 读字段，见 P4.85）。
	 */
};

#define KT_NTARGETS (sizeof(ktool_targets) / sizeof(ktool_targets[0]))

/*
 * 匹配规则：device 与 kernel 都必须相等。
 * 只按 device 匹配是危险的——同机型换内核后地址全变，照旧用会写坏内核内存。
 * 返回 NULL 表示「表里没有这个目标」，调用方应当拒绝执行地址类操作。
 */
static inline const struct ktool_target *
ktool_find_target(const char *device, const char *kernel)
{
	unsigned int i;

	if (!device || !kernel)
		return 0;
	for (i = 0; i < KT_NTARGETS; i++) {
		const struct ktool_target *t = &ktool_targets[i];

		if (t->device && t->kernel && !strcmp(t->device, device) &&
		    !strcmp(t->kernel, kernel))
			return t;
	}
	return 0;
}

#endif /* KTOOL_TARGETS_H */
