# Root My Galaxy S4

**English** | [中文](README.zh-CN.md)

Runtime root + surgical SELinux policy patching on the Samsung Galaxy S4 (GT-I9500 / Exynos 5410).
No boot image flashing, no recovery, no writes to `selinuxfs` — so the **KNOX Warranty Bit is never tripped**.

With the boot script installed, root survives reboots. KNOX apps keep working normally. Smart
Manager occasionally reports "unauthorized actions have been detected" — that is its integrity
check noticing the `/system` changes, not the e-fuse, and it is purely cosmetic.

---

## How to use

### 1. Prerequisites

- Samsung Galaxy S4 **GT-I9500** on `LRX22C.I9500ZSSHQD1` / kernel `3.4.5-6264821`
  (other devices and builds: see [Porting](#porting-to-another-device))
- `adb` on your PC, device connected over USB

### 2. Install and uninstall

```sh
./scripts/install.sh      # persistent
./scripts/install.sh -t   # temporary, gone after a reboot
./scripts/install.sh -u   # uninstall
```

| Mode | Writes to `/system` | Notes |
|---|---|---|
| persistent | `ktool`, `su`, module, boot hook | Builds what is missing; prebuilt binaries in `src/` mean no toolchain needed |
| `-t` | nothing | Leaves only `/data/local/tmp/ktool_temp`; `ish`, `ctx` and the avtab rules are unavailable |
| `-u` | removes all of it | Revokes the 8 rules, restores the boot script, deletes the files, wipes `/data` |

It probes the device first and prints what it found: `clean`, `temp`, `persistent` or `mixed`
(an install that was interrupted halfway). Command-line root only, no `su`:
`./scripts/deploy_ktool.sh`.

Root prompts on the app side are handled by
[phh's Superuser 1.0.3.3](https://fxedel.gitlab.io/fdroid-website/en/packages/me.phh.superuser/) — install it before granting root.

Source: [phhusson/Superuser](https://github.com/phhusson/Superuser)

The `su` binary this project ships (`src/su_fork.c`) is an independent implementation of the same
socket protocol.

| `persist.sys.root_access` | Meaning | `adb shell su` | App requests |
|---|---|---|---|
| `0` | deny all | refused | refused |
| `1` | apps only | refused | allowlist + prompt |
| `2` | ADB only | let through | refused |
| `3` | apps + ADB | let through | allowlist + prompt |

Change the tier from the Superuser settings screen, or write `/data/local/tmp/su_access_mode` with
`access_disabled` / `apps_only` / `adb_only` / `apps_and_adb` — that file takes precedence over the
property. `setprop persist.sys.root_access N` from `adb shell` reports success but is silently
dropped: the `shell` domain has no write permission on `system_prop`.

### 3. Verify

```sh
adb shell '/data/local/tmp/ktool_new target'    # must say "verified: yes"
adb shell 'getenforce'                          # Enforcing
adb shell 'su -c id'                            # uid=0 (tiers 2 and 3)
```

The first line uses the copy in `/data/local/tmp` on purpose: `/system/bin/ktool` is
`0700 root:root`, and the `shell` domain cannot execute it. Once `su` is installed you can use
`su -c "/system/bin/ktool target"` instead.

### 4. Building

```sh
./scripts/build_ktool.sh                              # ktool
TOOLCHAIN=/opt/arm/bin ./scripts/build_su.sh    # su (static, bundled sqlite3)
```

Kernel module:

```sh
cd kmod
make KDIR=/path/to/kernel_i9500 CROSS_COMPILE=arm-none-linux-gnueabihf-
```

`KDIR` must point at a configured GT-I9500 tree (with `.config` and `Module.symvers`).

One caveat before trusting that tree: `vermagic` is a **string**, and it comes straight from
`EXTRAVERSION` in the kernel `Makefile`. Typing the device's build number there is enough to make
`insmod` accept a module built from a tree the firmware was never built from — and with
`CONFIG_MODVERSIONS` unset (as on this kernel) nothing checks struct layouts afterwards. The tree
in this project came from a community repo and needed exactly that one-line edit, which is why
`cred` sits at `+0x2EC` there but `+0x2FC` on the device. Every offset in `targets.h` was measured
on hardware, not derived from source.

#### What each build needs

| Target | Inputs | Toolchain |
|---|---|---|
| `ktool` | `src/ktool.c`, `src/targets.h` | cross gcc, `-static`, no external libs |
| `su` | `src/su_fork.c`, `src/sqlite3.c` + `.h` (bundled amalgamation) | same cross gcc, `-static`, `-lpthread` |
| `ktool_mod.ko` | `kmod/ktool_mod.c` | same cross gcc + GNU make + a configured kernel tree |

Versions this was built and tested with:

| Tool | Version |
|---|---|
| Arm GNU Toolchain `arm-none-linux-gnueabihf-` | 13.3.Rel1 (gcc 13.3.1, 20240614) |
| GNU Make | 4.4.1 (MSYS2 — Git Bash ships without make) |
| adb | 1.0.41 |
| bash | 5.x (Git Bash on Windows; the scripts assume `cygpath` exists) |

The device side needs nothing extra: everything there is written against
`/system/bin/sh` plus `grep` and `echo`. That is not caution, it is measured —
this firmware has **no `sed`, no `awk`, no `printf`, no `tail`**, so any script
that uses them silently does nothing (or half its job).

#### Kernel sources

Samsung's open source site no longer publishes packages for this generation, so
there is no canonical tree to point at. What exists, and what each is good for:

| Tree | Kernel | Use |
|---|---|---|
| [somadsul/kernel_i9500](https://github.com/somadsul/kernel_i9500) | 3.4.5 | what this repo was built against; `EXTRAVERSION` was edited to `-6264821` so the module would load |
| [LineageOS/android_kernel_samsung_exynos5410](https://github.com/LineageOS/android_kernel_samsung_exynos5410) (`cm-11.0-old`) | 3.4.5 | same base version as the above, so it can stand in for it |

None of these is the tree the firmware was compiled from. The `cred` offset
differs by 16 bytes between the first one and the device, which is the whole
argument for measuring every offset instead of computing it.

---

## Status

| Item | Result |
|---|---|
| Arbitrary kernel R/W | CVE-2015-1805 (pipe iovec OOB), both directions |
| Escalation | Overwrites uid/gid/caps in the current `cred` in place; `cred->security` is untouched, so the SID does not change |
| SELinux end state | `Enforcing`, `permissive_map` = 0, no leftover permissive triples |
| Policy changes | 8 allow rules inserted into the in-memory `te_avtab`; nothing written to disk |
| Root policy | `persist.sys.root_access`: `0` deny all, `1` apps only, `2` ADB only, `3` apps + ADB. ADB is let through without a prompt in tiers 2 and 3; app requests always go through the allowlist and the phh prompt |
| `/system` writes | remount rw → modify → back to ro, cold boot verified |
| KNOX | Warranty Bit intact, `RST_STAT` normal |

Baseline device:

```
model : GT-I9500
device: ja3g
build : LRX22C.I9500ZSSHQD1
kernel: 3.4.5-6264821
sepf  : SEPF_GT-I9500_5.0.1-1_0039
```

---

## How it works

```
1. Arbitrary read    CVE-2015-1805 pipe_read iovec OOB. 8-byte aligned, 2000 B per call.
2. Arbitrary write   Same bug, writev direction. kwrite() ALWAYS returns 0, so every
                     write is read back and compared; only 8-byte chunks are trusted.
3. Escalation        Walk task list -> task->real_cred/cred -> overwrite uid/gid/caps in place.
                     cred->security is left alone, so the SELinux SID does not change.
4. SELinux           a) set permissive_map (in-memory ebitmap, never selinuxfs)
                     b) avc_ss_reset(0) — otherwise cached denies keep winning
                     c) insert 8 allow rules into policydb->te_avtab
                     d) clear permissive_map + flush again -> Enforcing
5. Authorization     /system/xbin/su (fork-based, phh protocol) + Superuser APK
```

**`kwrite` lies about its length.** Every call returns 0 regardless of outcome. Landing rate over 5 independent tries: 8 B → 5/5, 16 B → 1/5, 32 B → 0/5, 48 B → 0/5, 72 B → 1/5. Hence fixed 8-byte chunks with read-back verification and an undo log. It is slow — a megabyte takes minutes — which is why `kread_file` exists for pulling bulk data and writes stay small.

### The 8 avtab rules

Type values on this policy: `untrusted_app 809`, `init_shell 986`, `shell 1178`, `shell_data_file 200`, `su_exec 161`, `system_prop 342`.

```
init_shell    -> system_prop  : property_service { set }                    # write persist.sys.root_access
init_shell    -> untrusted_app: fd { use }                                  # hand prompt socket to the app
untrusted_app -> init_shell   : process { sigchld }                         # app waits for su
untrusted_app -> shell_data   : sock_file { create write setattr unlink }   # create prompt socket
untrusted_app -> shell_data   : dir { add_name remove_name write search }
shell         -> su_exec      : file { execute execute_no_trans }
init_shell    -> shell        : fd { use }
shell         -> shell_data   : sock_file { create write setattr unlink }
```

Insertion details that matter: `policydb + 0x74` is `te_avtab` (htable / nslot / mask / nel), the key is four `u16` packed into 64 bits (`cls | tgt << 2 | src << 9`), nodes are 16 bytes, and **insertion must be ordered** — `avtab_search_node()` early-breaks on an ordered list, so an out-of-order insert is silently invisible.

---

## Route survey

Every CVE checked against this exact kernel (`3.4.5-6264821`). The table keeps two separate
columns on purpose: whether the bug is still in the code, and whether a `shell`-uid process can
actually reach it. Twenty were checked. One is usable.

| CVE | Subsystem | Vulnerability | Exploitability | Basis |
|---|---|---|---|---|
| **CVE-2015-1805** | pipe iovec OOB | **PRESENT** | **USED HERE** | `pipe_iov_copy_from_user` still takes 4 arguments (the fix adds a fifth `atomic_t *`). Arbitrary R/W confirmed on hardware. |
| CVE-2026-43499 | GhostLock, futex PI | PRESENT | BLOCKED (no read primitive) | Chain stages A/B/C were demonstrated on this device, but only by using CVE-2015-1805's read primitive to build a self-consistent forged node — after which both `CONFIG_DEBUG_LIST` checks pass. Without that primitive the node cannot be made self-consistent, so the chain cannot start. And once you have the primitive, GhostLock adds nothing. |
| CVE-2016-3134 | netfilter, `xt_compat_match_from_user` | PRESENT | BLOCKED (CAP_NET_ADMIN) | No lower bound on `msize` before `memcpy(m->data, cm->data, msize - sizeof(*cm))`. The iptables path requires `CAP_NET_ADMIN`. |
| CVE-2016-9793 | socket, `SO_SNDBUFFORCE` | PRESENT | BLOCKED (CAP_NET_ADMIN) | No upper bound on `sk_sndbuf`. Measured: `SO_SNDBUF` is clamped by `min_t`, while `SO_SNDBUFFORCE` returns EPERM even at uid 0 with `CapEff=ffffffff`. |
| CVE-2016-5195 | dirtycow, `follow_page` | FIXED | — | Three-condition check present (`FOLL_FORCE` \| `FOLL_COW` against pte dirty). A canary survived ~570k write attempts. |
| CVE-2016-0728 | keyring | FIXED | — | `key_put(keyring)` at the end of `join_session_keyring`. |
| CVE-2016-4470 | keyring | FIXED | — | `__key_link_end` only runs when `link_ret == 0`. |
| CVE-2016-8655 | AF_PACKET | FIXED | — | `if (unlikely(rb->pg_vec))` guard in `packet_set_ring()`. |
| CVE-2015-3636 | ping socket UAF | FIXED | — | Tested on device. |
| CVE-2019-2215 | binder UAF | FIXED | — | `binder_free_thread` zeroes `t->from` and `t->to_thread`. |
| CVE-2016-5340 | ashmem | ABSENT | — | 3.4 has no `is_ashmem_file()`; `ashmem_pin_unpin` carries all four checks. |
| CVE-2016-3951 | USB usbnet | ABSENT | — | `CONFIG_USB_USBNET` not set. |
| CVE-2017-11176 | `mq_notify` | ABSENT | — | `CONFIG_POSIX_MQUEUE` not set. |
| CVE-2017-6074 | DCCP | ABSENT | — | `CONFIG_IP_DCCP` not set. |
| CVE-2026-64560 | posix-cpu-timers, non-leader `exec()` race | ABSENT | — | Introduced in 5.7. No `switch_leader()` in this tree or in the device's `/proc/kallsyms`, and `posix_cpu_timer_del()` reads `p->sighand` under `tasklist_lock` — the same lock `release_task()` holds across `__exit_signal()` — so the window the CVE needs does not exist. The worst case here is the `BUG_ON` panic, not a UAF. |
| CVE-2019-2181 | binder | ABSENT | — | Not introduced in this tree. |
| CVE-2020-0041 | binder | ABSENT | — | Not introduced in this tree. |
| CVE-2020-0009 | ashmem prot | BY DESIGN | — | Intended behaviour on this kernel, not a vulnerability. |
| CVE-2016-6728 | ION, msm custom ioctl | ABSENT | — | Targets the Qualcomm msm ION custom/secure paths. The S4 ships Samsung's own `drivers/gpu/ion/ion.c`, where `ION_IOC_CUSTOM` is NULL — measured: commands 0..8 all return ENOTTY. |
| CVE-2017-0564 | ION, msm | ABSENT | — | Same reason: the vulnerable entry points do not exist on this implementation. |

A caveat on the last two: ABSENT is a verdict for *this* device only. The S5 firmware carries the
Qualcomm msm ION (`msm_ion_custom_ioctl`, `ion_cp_change_mem_v2`, `ion_secure_*`), so both CVEs
have to be re-audited against msm code rather than inherited from the S4 result.

Two of the four reachability verdicts hit the same wall, and it is worth naming: `CAP_NET_ADMIN`
is not granted to the `shell` domain, so `capable()` fails at the SELinux layer regardless of what
`CapEff` says. CVE-2016-3134 and CVE-2016-9793 both die there. Judging by patch state alone would
have marked both "exploitable" and sent the next two weeks down a chain that cannot start.

Two leak routes were also closed, and both look promising until you test them. The systematic
infoleak scan (254 probes across every shell-reachable surface) found zero usable stack addresses.
The `WARN`-`%p` channel does print real kernel stack addresses, and `dmesg` is readable from
`shell` on this build — but the trigger path BUGs inside a `pi_lock` critical section, so the
thread dies still holding a real lock and softlockup panics about 27 seconds later. Not a missing
leak; a self-defeating one.

### GhostLock availability

What decides whether this chain works is not how many nodes a rebalance touches. It is whether the
kernel **validates** the node before dereferencing it.

On 3.4, `CONFIG_DEBUG_LIST=y` together with `CONFIG_SEC_DEBUG_LIST_PANIC` makes `list_debug` a
non-zero global, so `if (list_debug) BUG_ON(...)` always takes the BUG path. In the shipped binary
the four consistency checks in `__list_del_entry` (`0xc025cd68`) are compiled down to an
**unconditional** `udf #0x12`. There is nothing to negotiate: a forged node either satisfies every
check or panics.

`lib/rbtree.c` (401 lines in this tree) has **no runtime validation at all** — no `DEBUG_RBTREE`,
no `__rb_erase_valid`, nothing in `rb_insert_color`. It dereferences and moves on, so a forged
`rb_node` does not have to be self-consistent. `rb_insert_color` also hands over the stack address
for free while rebalancing, which is why the same bug is far easier on newer kernels.

| Kernel | `waiter` is | Node validated? | External read primitive | GhostLock alone |
|---|---|---|---|---|
| 3.4 / 3.10 (S4, S5, S6) | `plist_node` | yes — `udf` | **required**, and must be a *stack* address | **no** |
| 3.14 and later (S7 onward, 4.4 / 4.9 / …) | `rb_node` | no | not required | plausible |

S5 firmware confirms the pattern from the other side: `CONFIG_DEBUG_LIST=y` again, but with a
`panic()` instead of `udf` — same effect, different instruction. S6 uses the same plist structure.
Public chains for S7 and later exist; none verified here.

This leaves the S4 in an awkward position: the only thing that can hand over a stack address is
CVE-2015-1805 itself, and once you have arbitrary read/write, GhostLock adds nothing. That is why
this project does not use the chain at all, and why "GhostLock alone" is not a route on **any**
plist kernel, not just this one.

ION does not rescue it either. Its infoleak returns a **kernel heap** address (measured on the S4:
`handle = 0xd8aed780`), while the forged `node_list` has to point at `waiter + 0x0C` on the
**stack**. Heap is not stack. The SHARE/FREE race only ever won a refcount — a leak, not memory
corruption — so it yields no read primitive. Had some other ION bug provided real read/write, the
S4 row would change; the audit did not find one. Note that the S5 ships the Qualcomm msm ION rather
than Samsung's, so its attack surface is larger and needs its own audit.

---

## Porting to another device

Only **one file** changes: `src/targets.h`. The kernel module includes the same header, so the
two sides can never disagree about offsets.

### Likely candidates

The rows below are **untested hypotheses, not verified targets** — nobody has run the chain on
them. The reasoning is structural: same KNOX generation, same `lkmauth` mechanism, same SELinux
`policydb` layout. That makes the *method* transfer; it does not make a single address reusable.

| Device | SoC | Kernel line | Assessment |
|---|---|---|---|
| SM-N900 (Note 3) | Exynos 5420 | 3.4.x | Closest match: same branch and same KNOX generation as the S4 |
| GT-I9505 (S4 LTE) | Snapdragon 600 | 3.4.x | Same branch, different SoC — the entire kernel side is a fresh port |
| GT-I9300 (S3) | Exynos 4412 | 3.0.x | Older branch: `task_struct` layout differs, `[B]` cannot be copied |
| GT-N7100 (Note 2) | Exynos 4412 | 3.0.x | Same situation as the S3 |

How to read it:

- **Note 3** is the one worth trying first. Same kernel generation, so the `[B]` offsets have a
  real chance of transferring, and `lkmauth_bootmode` exists under the same name.
- **I9505** keeps the whole userland side unchanged, but the kernel is a different tree (msm).
  Expect every `[A]` address to move; verify the exec-patch site independently rather than
  assuming the branch distance is similar.
- **S3 / Note 2** run 3.0.x. `task_struct` and `cred` are laid out differently, so `[B]` has to
  be re-derived instead of copied. `lkmauth` exists from 4.3 onward, but the policy build is older
  and `perm_bit` will not match.

What never transfers, on any of them: `init_task`, `permissive_map`, `avc_slots`, `exec_br`,
`lkmauth_bootmode`, `perm_bit`. What usually does, between kernels of the same branch: the `[B]`
offsets.

### What has to be true

- ARM32 kernel, `task_struct`/`cred` layout close to 3.4.x
- CVE-2015-1805 (or another primitive) gives you arbitrary R/W
- Samsung `lkmauth` bootmode variable exists (the `boot` command uses it)

### Step 1 — identity (matching key)

```sh
adb shell getprop ro.product.device     # -> device
adb shell cat /proc/version             # -> "3.4.5-XXXXXXX" -> kernel
```

Matching requires **both** device and kernel version to be equal. Matching on device alone is
dangerous: same phone with a different kernel has completely different addresses, and the table
would happily write into the wrong place. No match → every address-taking command refuses to run.

### Step 2 — `[B]` offsets (config-dependent, usually reusable)

```
off_task_tasks off_task_real_cred off_task_cred off_task_comm
off_cred_uid off_cred_caps off_cred_security
```

These follow the kernel config (`CONFIG_KEYS`, `CONFIG_SECURITY`, `CONFIG_DEBUG_*`), not the
image build. Derive them from a `vmlinux` with debug info:

```sh
pahole -C task_struct vmlinux | grep -E "tasks|real_cred|cred|comm"
pahole -C cred vmlinux | grep -E "uid|caps|security"
```

Sanity check on device once you have R/W: `fld <init_task> 0x1d0:p 0x2f8:p 0x304:s` should print a
pointer into the task list, `init_cred` for `real_cred` (the symbol annotation next to it is the
good sign), and the string `swapper/0`. Measured on this device:

```
+0x1d0 p  0xe68481d0
+0x2f8 p  0xc0b9f1dc  Dinit_cred+0x0
+0x304 s  "swapper/0"
```

### Step 3 — `[A]` addresses (per image, must be re-derived)

| Field | How to get it |
|---|---|
| `init_task` | `System.map` / `kallsyms` of that exact kernel |
| `modprobe_path` | symbol; 256 writable bytes in `.data`, borrowed as scratch for a fake ebitmap node |
| `permissive_map` | address of `policydb.permissive_map`; locate `policydb` from the symbol table and add the struct offset for that policy version |
| `avc_slots` | `avc_cache.slots[512]`, debug use only |
| `exec_br` | inside `sys_execve`, the `beq` that skips Samsung's KNOX check |
| `exec_br_orig` / `exec_br_patch` | the original branch word and the `b` that replaces it (this build: `0x0a000002` → `0xea000047`) |
| `lkmauth_bootmode` | `.bss` variable, zeroed every boot |

For `exec_br`, disassemble `sys_execve` and look for the conditional branch that jumps over the
credential check; the branch offset in `exec_br_patch` must be computed from the actual instruction
distance, not copied blindly.

### Step 4 — `perm_bit`

This is `init_shell`'s **type value**, not its SID, and it changes with every policy build:

```sh
adb pull /sepolicy
python3 tools/sepolicy_parse.py sepolicy .
# read the type table; the index of init_shell is perm_bit
```

`tools/sepolicy_query.py` helps cross-check individual rules and type numbers.

### Step 5 — verify before trusting

1. `ktool target` — addresses look sane, and the new entry has `verified = 0`
2. `ktool backend probe` — must print `probe(init_task=...): OK`
3. `ktool dump <init_task> 64` — should decode as a plausible `task_struct`
4. `ktool sym init_task` — must agree with the table
5. Only after the full chain (root → mount → module → `ktool enforce` → `getenforce` reports
   `Enforcing`) is confirmed on hardware, flip `verified = 1` and write what you tested into `note`

If any of these disagree, **do not proceed** — guessing addresses in kernel `.data` is how you
turn a phone into a brick.

### Step 6 — module-side values

The module additionally needs the SELinux type numbers for the 8 avtab rules. These are runtime
module parameters, so no recompile is required:

```sh
insmod ktool_mod.ko av_app_type=809 av_initshell_type=986 av_shelldata_type=200 \
                    av_suexec_type=161 av_shell_type=1178 av_sysprop_type=342
```

The boot script passes them from `targets.h`-derived values; adjust it for your policy.

---

## ktool command reference

Global: `ktool [-t <sec>] <command> ...` — `-t/--timeout` caps total retry time for read/write.

### Target / backend

| Command | Description |
|---|---|
| `target` | Print matched model/build/kernel, all addresses and offsets, and the `verified` flag |
| `backend` | Show backend name and read/write limits |
| `backend probe` | Real race read of `init_task`; the definitive "is R/W alive" check |
| `sym <name\|name*wild\|0xADDR> [-a] [-f mapfile] [-n max]` | Symbol lookup (`-a` = all matches, `-f` = custom System.map) |

### Read

| Command | Description |
|---|---|
| `dump <addr> <len>` | Read and hexdump, max 4096 B |
| `read <addr> <len>` | Read and emit raw binary to stdout, max 16 MB |
| `kread_file <addr> <len> <out> [-r\|--resume]` | Chunked read to file; `-r` resumes from existing file size |
| `bench [addr] [n]` | Read throughput: ms/read and average retries |
| `selftest <addr>` | Read the same address 4 times and print the first words — shows whether reads are stable |

### Write

| Command | Description |
|---|---|
| `kwrite_file <in> <addr> [-n]` | Chunked write with read-back verify; `-n` skips the undo log |
| `w32 <addr> <value>` | Single 32-bit write (preserves the upper 4 bytes) |
| `undo` | Replay the undo log to revert the last `kwrite_file` |
| `wtest [len] [off]` | Write-primitive diagnostic: try a length and report whether it landed |

### Search / structure

| Command | Description |
|---|---|
| `scan <start> <len> <pattern\|s:text> [max]` | Byte or string scan |
| `scan4 <start> <len> <value\|lo-hi> [max] [-u]` | 32-bit scan, `-u` = unaligned |
| `findcred <start> <len> [-u uid] [max]` | Find objects shaped like `struct cred` |
| `find <comm>` | Walk the task list and match `comm` |
| `walk <sym\|addr> <off>... [-d n]` | Follow a chain of pointers, dump the endpoint |
| `fld <addr> <off:type>...` | Field-wise struct read; types `p u h b s x` |
| `dis <addr> [n]` | ARM32 disassembly, conservative (unknown → `.word`) |

### Privilege

| Command | Description |
|---|---|
| `root <cmd>` | Escalate then `exec` (aliases `x`, `rawexec`) — ends the session |
| `promote` | Escalate but stay in the session; keeps a cred snapshot |
| `unroot` | Restore the cred snapshot taken by `promote` (validates task/comm first) |
| `pwn [cmd]` | Escalate + full permissive, then `exec` |
| `sh` | Apply exec patch + switch to `init_shell`, then hand over a shell |
| `boot <ko>` | Root, set `lkmauth_bootmode=2`, full permissive, apply the exec patch, then `exec insmod <ko>` — five steps in one exploit run. The exec patch is required: the KNOX branch at `c0012164` blocks a kernel-domain `exec`, and without it `insmod` returns EACCES |
| `who` | Current uid/euid/gid/caps |
| `caps` | Fill all capability sets on the current cred |
| `showcred` | Dump creds of every task in the list |

### SELinux

| Command | Description |
|---|---|
| `permissive [bit]` | Set a single `permissive_map` bit (defaults to `init_shell`) |
| `enforce [--noflush]` | Clear `permissive_map` + restore `modprobe_path` + flush AVC. It only undoes the in-memory permissive window — it does not uninstall anything. `--noflush` does **not** actually restore enforcement |
| `appwrite <src\|-> <dst>` | Write into another app's private data. The source is read as `init_shell` (any path), then the process is switched to the target directory's owner + `untrusted_app` in one step: the DAC key comes from a direct `cred->fsuid` write inside the module, the SELinux key from the domain switch. Works on `app_data_file` only — system apps are `system_app_data_file` and return 4 |
| `apprm [-r] [-f] <path>...` | Same identity trick, for deleting. Nothing is printed after the switch — writing to the calling shell's pipe is itself a permission check that `untrusted_app` fails, and this kernel's audit path oopses on the denial, so success is only visible in the exit code |
| `trust [on\|off]` | Insert / remove four curated avtab rules — `init_shell` → `app_data_file` and `system_app_data_file`, `file` and `dir`. With them in place plain `cp`, `rm`, `chmod` and `tar` work on app private data, so file managers and backup tools behave like they do on a Magisk device. Still Enforcing; `trust off` restores `app_data_file:dir` to `0x100020` and unlinks the other three |
| `flush [-y]` | AVC flush only; `-y` skips the 3 s warning |
| `patch` / `unpatch` | Apply / revert the KNOX `sys_execve` branch patch |
| `setsid <sid\|init_shell> <cmd...>` | Rewrite the current `cred->security->sid`, then exec. Rescue path when the AVC cache is deadlocked |

Two ways to reach app private data, and they trade off differently:

- `appwrite` / `apprm` switch **one process** to the target's owner + `untrusted_app`, touch one
  path, and exit. Nothing else on the device gains anything. Works on `app_data_file` only.
- `trust on` gives the **whole `init_shell` domain** read/write on `app_data_file` and
  `system_app_data_file`. Any `su` caller can then do it — which is what tools like Titanium
  Backup need — at the cost of root no longer being fenced off from app data until `trust off`
  or a reboot. It is the same idea as Magisk's `allow magisk * * *`, four types narrower.

Measured on this device: with `trust on`, `cp` into another app's directory returns 0, `chown` to
that app's uid returns 0, and a new file created under `com.android.settings` comes out labelled
`system_app_data_file` — the label follows the parent directory, so the app itself still reads it.
After `trust off` the same `cp` returns `Permission denied` again. `permissive_map` is never
touched; `getenforce` reads `Enforcing` throughout.

`trust` is **on by default**: `install.sh` turns it on at the end, and the boot hook re-applies it
on every boot. Opt out with `touch /data/local/tmp/ktool_notrust` (the hook then skips it) or with
`ktool trust off` for the current session. `install.sh -u` runs `trust off` before unloading the
module, so an uninstall does not leave root able to read app data until the next boot.

### File / shell

| Command | Description |
|---|---|
| `cat <path>` | Escalate + permissive, then read a file |
| `cp <src> <dst>` | Escalate + permissive, then copy |
| `ls <path>` | Escalate + permissive, then list |

### Session

| Command | Description |
|---|---|
| `repl` | Interactive session (aliases `shell`, `-i`). History persists to `/data/local/tmp/.ktool_hist` |
| `help` / `?` | Command list inside REPL |
| `history` / `!N` | Show / replay history inside REPL |
| `exit` / `quit` / `q` | Leave the session |

Inside a REPL session the exploit setup is paid once and `promote` persists across commands.

---

## Known limits

| Symptom | Cause | Handling |
|---|---|---|
| Large `kwrite` "succeeds" but memory is unchanged | iovec OOB lands unreliably | only 8-byte chunks + read-back |
| `setenforce 0` leaves it Enforcing | `CONFIG_ALWAYS_ENFORCE` | edit `permissive_map` |
| Permissive is on but `remount` is denied | AVC cache stickiness | `flush` (`avc_ss_reset`) |
| Process wedges in D state after touching `selinuxfs/load` | TIMA integrity measurement | never write selinuxfs |
| `sid` write reports failure | after the write the domain has already changed, so read-back is unreliable | `setsid` writes once without verifying; confirm via `/proc/self/attr/current` |
| Root process cannot `exec` after `unpatch` | privilege capability is gone, not just EACCES | keep the patch, or re-run `ktool patch` |
| `su` stops working entirely after editing the boot script | CRLF line endings, script aborts before running anything | convert to LF, verify with `sh -n` on device |

`setsid` is the last-resort path: when the AVC cache is deadlocked and both `mount` and
`/dev/ktool` are unusable, it rewrites `cred->security->sid` to a **new** SID so the verdict is
computed from scratch.

---

## Credits

- CVE-2015-1805 — `pipe_read()` / `pipe_write()` iovec OOB (iovyroot exploitation approach)
- **KNOXout** (Lev Aronsky, Viral Security Group) — what Samsung's TIMA and RKP actually intercept.
  This is where the "never write `selinuxfs`" rule came from, before it was confirmed on device
- phh's Superuser — su protocol and APK side

Substantial parts of the code and prose here were written with AI assistance. Every address,
offset, permission mask and `verified` claim was checked against a real device: the experiments,
the failure analysis and the decisions about what to keep are human work.

---

## Disclaimer

For security research and maintenance on **devices you own**.
Make sure you have a working recovery path before writing anything. No warranty of any kind;
the authors are not responsible for bricked devices, data loss, or voided warranties.
Addresses and type values differ per ROM and kernel — `targets.h` refuses to run when the match
fails, and that check exists for a reason.

---

## License

Two parts:

- **`src/`, `scripts/`, `tools/` are GPL-3.0-or-later** — the root `LICENSE`. They are ordinary
  userland programs talking to the kernel through syscalls; nothing links them against kernel
  code, so the licence here is a choice rather than a constraint.
- **`kmod/` must be GPL-2.0** — `kmod/LICENSE`. It is a Linux kernel module: it calls
  kernel-internal functions, walks kernel-private structures (`policydb`, `task_struct`) and is
  loaded into a GPL-2.0-only kernel. It also declares `MODULE_LICENSE("GPL")`, which is what lets
  it resolve `EXPORT_SYMBOL_GPL` symbols at all. GPL-3.0 cannot be used here — it is incompatible
  with the kernel's licence. The file header says `SPDX-License-Identifier: GPL-2.0`.

Every source file here starts with an `SPDX-License-Identifier` line, so the terms are unambiguous
per file.
