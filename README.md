# Root My Galaxy S4

Runtime root + surgical SELinux policy patching on the Samsung Galaxy S4 (GT-I9500 / Exynos 5410).
No boot image flashing, no recovery, no writes to `selinuxfs` — so the **KNOX Warranty Bit is never tripped**.

With the boot script installed, root survives reboots. KNOX apps keep working normally. Smart
Manager occasionally reports "unauthorized actions have been detected" — that is its integrity
check noticing the `/system` changes, not the e-fuse, and it is purely cosmetic.

---

## How to use

### 1. Prerequisites

- Samsung Galaxy S4 **GT-I9500** on `LRX22C.I9500ZSSHQD1` / kernel `3.4.5-6264821`
  (other builds: see [Porting](#porting-to-another-device))
- `adb` on your PC, device connected over USB

### 2. Install

```sh
./scripts/deploy_ktool.sh
```

One shot: push, escalate, flush, remount, replace, restore. Prints `DEPLOY_OK` and the final
SELinux state. Need a binary? See [Building](#building).

Root prompts on the app side are handled by **phh's Superuser** — install it before granting root:

https://fxedel.gitlab.io/fdroid-website/en/packages/me.phh.superuser/

### 3. Verify

```sh
adb shell '/system/bin/ktool target'    # must say "verified: yes"
adb shell 'getenforce'                  # Enforcing
adb shell 'su -c id'                    # uid=0, context=u:r:init_shell:s0
```

Boot persistence is optional: `ktool boot /system/lib/modules/ktool_mod.ko`, then install
`scripts/init.sec.boot.v9g.sh` as `/system/etc/init.sec.boot.sh`. Keep it **LF** — CRLF makes
mksh abort before running a single line.

---

## Status

| Item | Result |
|---|---|
| Arbitrary kernel R/W | CVE-2015-1805 (pipe iovec OOB), both directions |
| Escalation | `prepare_kernel_cred(NULL)` + direct `task->cred` overwrite; uid/gid/caps all 0 |
| SELinux end state | `Enforcing`, `permissive_map` = 0, no leftover permissive triples |
| Policy changes | 8 allow rules inserted into the in-memory `te_avtab`; nothing written to disk |
| Root policy | Four tiers: deny all / ADB only / apps only / everything; app prompts via phh protocol |
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
3. Escalation        Walk task list -> task->real_cred/cred -> zero uid/gid, fill caps.
                     Deliberately avoids commit_creds() so SELinux does not recompute the SID.
4. SELinux           a) set permissive_map (in-memory ebitmap, never selinuxfs)
                     b) avc_ss_reset(0) — otherwise cached denies keep winning
                     c) insert 8 allow rules into policydb->te_avtab
                     d) clear permissive_map + flush again -> Enforcing
5. Authorization     /system/xbin/su (fork-based, phh protocol) + Superuser APK
```

Three details that decide whether any of this works:

**`kwrite` lies about its length.** Every call returns 0 regardless of outcome. Landing rate over 5 independent tries: 8 B → 5/5, 16 B → 1/5, 32 B → 0/5, 48 B → 0/5, 72 B → 1/5. Hence fixed 8-byte chunks with read-back verification and an undo log. Slow (about 1 MB/min), but never silently half-applied.

**`setenforce 0` is dead on this kernel.** `CONFIG_ALWAYS_ENFORCE` makes `avc_denied()` return `-EACCES` without ever consulting `selinux_enforcing`. The only lever is `permissive_map`.

**Permissive does not retroactively apply.** `AVD_FLAGS_PERMISSIVE` is baked into `avd->flags` at *computation* time. Any triple already cached keeps its old verdict. This is why `enforce` and `flush` call `avc_ss_reset(0)`, and why "permissive is on but remount still fails" happens.

Writing `/sys/fs/selinux/load` is never done: it triggers TIMA integrity measurement (`Tl_TIMA_PKM: ret = -1`) and the process wedges in D state. All policy edits happen in memory instead.

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

## Building

```sh
./scripts/build.sh                              # ktool
TOOLCHAIN=/opt/arm/bin ./scripts/build_su.sh    # su (static, bundled sqlite3)
```

Kernel module:

```sh
cd kmod
make KDIR=/path/to/kernel_i9500 CROSS_COMPILE=arm-none-linux-gnueabihf-
```

`KDIR` must point at a configured GT-I9500 tree (with `.config` and `Module.symvers`).

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
plausible self-referencing list head, a kernel pointer for cred, and the string `swapper/0`.

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
5. Only after the full chain (root → mount → module → restore → Enforcing) is confirmed on
   hardware, flip `verified = 1` and write what you tested into `note`

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
| `selftest <addr>` | Read the same address N times and compare for stability |

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
| `boot <ko>` | `lkmauth_bootmode=2` + permissive + `insmod` |
| `who` | Current uid/euid/gid/caps |
| `caps` | Fill all capability sets on the current cred |
| `showcred` | Dump creds of every task in the list |

### SELinux

| Command | Description |
|---|---|
| `permissive [bit]` | Set a single `permissive_map` bit (defaults to `init_shell`) |
| `enforce [--noflush]` | Clear `permissive_map` + restore `modprobe_path` + flush AVC (aliases `unperm`, `restore`). `--noflush` does **not** actually restore enforcement |
| `flush [-y]` | AVC flush only; `-y` skips the 3 s warning |
| `patch` / `unpatch` | Apply / revert the KNOX `sys_execve` branch patch |
| `setsid <sid\|init_shell> <cmd...>` | Rewrite the current `cred->security->sid`, then exec. Rescue path when the AVC cache is deadlocked |

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
- phh's Superuser — su protocol and APK side
- SELinux in-kernel implementation: `security/selinux/ss/{avtab,policydb,services}.c`, `avc.c`

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

Three parts, three different reasons:

- **`kmod/` must be GPL-2.0.** It is a Linux kernel module: it calls kernel-internal functions,
  walks kernel-private structures (`policydb`, `task_struct`) and is loaded into a GPL-2.0-only
  kernel. It also declares `MODULE_LICENSE("GPL")`, which is what allows it to resolve
  `EXPORT_SYMBOL_GPL` symbols at all.
- **`src/`, `scripts/`, `tools/` are GPL-2.0 here, but do not have to be.** They are ordinary
  userland programs talking to the kernel through syscalls; nothing links them against kernel
  code, so they could be MIT or Apache-2.0. They carry GPL-2.0 because that is how this repository
  is distributed, not because of a technical constraint.
- **`su/` is GPL-3.0.** It is a derivative of phh's Superuser. GPL-3.0 is incompatible with
  GPL-2.0-only, so the two are kept as separate programs communicating over a socket — which is
  why this directory has its own license notice instead of sharing the root one.
