#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

"""P1.2: 纯 Python policydb v26 解析器
格式依据：本工作区内核源码 security/selinux/ss/policydb.c / avtab.c / conditional.c / ebitmap.c
（Samsung 3.4.5，policyvers=26，MLS=1，sym_num=8，ocon_num=7）
验收标准：解析结束时偏移量必须等于文件大小 399655
"""
import struct, sys, io, os
from collections import defaultdict

PATH = os.environ.get("SEPOLICY", "sepolicy")
OUTDIR = os.environ.get("SEPOLICY_OUT", ".")

if len(sys.argv) > 1:
    PATH = sys.argv[1]
if len(sys.argv) > 2:
    OUTDIR = sys.argv[2]

if not os.path.isfile(PATH):
    sys.exit("找不到策略文件: %s\n"
             "用法: %s <sepolicy> [outdir]\n"
             "（策略从设备取：adb pull /sepolicy）" % (PATH, sys.argv[0]))

# ---- avtab 常量 ----
AVTAB_ALLOWED, AVTAB_AUDITALLOW, AVTAB_AUDITDENY = 0x1, 0x2, 0x4
AVTAB_TRANSITION, AVTAB_MEMBER, AVTAB_CHANGE = 0x10, 0x20, 0x40
AVTAB_ENABLED = 0x8000

class R:
    def __init__(self, d):
        self.d, self.o = d, 0
    def u32(self):
        v = struct.unpack_from("<I", self.d, self.o)[0]; self.o += 4; return v
    def u16(self):
        v = struct.unpack_from("<H", self.d, self.o)[0]; self.o += 2; return v
    def u64(self):
        v = struct.unpack_from("<Q", self.d, self.o)[0]; self.o += 8; return v
    def raw(self, n):
        v = self.d[self.o:self.o+n]; self.o += n; return v
    def s32(self):
        n = self.u32(); return self.raw(n).decode("latin-1")

def ebitmap(r):
    mapunit, highbit, count = r.u32(), r.u32(), r.u32()
    assert mapunit == 64, f"mapunit {mapunit}"
    bits = []
    for _ in range(count):
        start = r.u32(); m = r.u64()
        while m:
            b = (m & -m).bit_length() - 1
            bits.append(start + b)
            m &= m - 1
    return bits

def mls_range(r):
    items = r.u32()
    assert items in (1, 2), f"range items {items}"
    sens = [r.u32() for _ in range(items)]
    cats0 = ebitmap(r)
    cats1 = ebitmap(r) if items > 1 else cats0
    return (sens, cats0, cats1)

def mls_level(r):
    s = r.u32(); c = ebitmap(r)
    return (s, c)

def context(r):
    return (r.u32(), r.u32(), r.u32(), mls_range(r))  # user, role, type, range

data = open(PATH, "rb").read()
r = R(data)

# ---- header ----
magic = r.u32(); assert magic == 0xf97cff8c, hex(magic)
slen = r.u32(); assert slen == 8
pstr = r.raw(slen); assert pstr == b"SE Linux", pstr
vers, config, sym_num, ocon_num = r.u32(), r.u32(), r.u32(), r.u32()
assert vers == 26 and sym_num == 8 and ocon_num == 7
mls_enabled = bool(config & 1)
print(f"[hdr] vers={vers} config={config:#x} mls={mls_enabled} sym_num={sym_num} ocon_num={ocon_num}")

policycaps = ebitmap(r)
permissive_map = ebitmap(r)
print(f"[hdr] policycaps bits={policycaps} permissive bits={permissive_map}")

# ---- symbol tables ----
sym = {}         # name -> (value, extra)
types = {}       # value -> (primary_name, prop, bounds)   只保留 primary
types_all = {}   # value -> [(name, prop), ...]            含 alias，全部保留
type_by_name = {}  # 任意名字（primary 或 alias）-> value
type_attr_map = {}
classes = {}     # value -> (name, perms dict permname->bit)
commons = {}
roles = {}
users = {}
bools = {}
sens = {}
cats = {}

numtypes = 0
for i in range(sym_num):
    nprim, nel = r.u32(), r.u32()
    if i == 0:  # common
        commons_nprim = nprim
        for _ in range(nel):
            ln, val, p_nprim, p_nel = r.u32(), r.u32(), r.u32(), r.u32()
            key = r.raw(ln).decode("latin-1")
            perms = {}
            for _ in range(p_nel):
                pl, pv = r.u32(), r.u32()
                perms[r.raw(pl).decode("latin-1")] = pv
            commons[val] = (key, perms)
    elif i == 1:  # class
        for _ in range(nel):
            ln, ln2, val, p_nprim, p_nel, ncons = r.u32(), r.u32(), r.u32(), r.u32(), r.u32(), r.u32()
            key = r.raw(ln).decode("latin-1")
            comkey = r.raw(ln2).decode("latin-1") if ln2 else None
            perms = {}
            if comkey:
                for cv, (cn, cp) in commons.items():
                    if cn == comkey:
                        perms.update(cp)
            for _ in range(p_nel):
                pl, pv = r.u32(), r.u32()
                perms[r.raw(pl).decode("latin-1")] = pv
            # constraints
            for group in range(2):
                nc = ncons if group == 0 else r.u32()
                for _ in range(nc):
                    cperms, nexpr = r.u32(), r.u32()
                    for _ in range(nexpr):
                        et, attr, op = r.u32(), r.u32(), r.u32()
                        if et == 5:  # CEXPR_NAMES
                            ebitmap(r)   # names bitmap
            classes[val] = (key, perms)
    elif i == 2:  # role
        for _ in range(nel):
            ln, val, bounds = r.u32(), r.u32(), r.u32()
            key = r.raw(ln).decode("latin-1")
            dom = ebitmap(r); typ = ebitmap(r)
            roles[val] = key
    elif i == 3:  # type
        numtypes = nprim
        for _ in range(nel):
            ln, val, prop, bounds = r.u32(), r.u32(), r.u32(), r.u32()
            key = r.raw(ln).decode("latin-1")
            # nel 1433 > nprim 1343：多出来的 90 条是 typealias。
            # alias 与 primary 共享同一个 value，直接 types[val]= 会让后读到的
            # alias 覆盖 primary（历史 bug：925 primary=system_file 被
            # dhcp_system_file 盖掉，导致 system_file "不存在"）。
            types_all.setdefault(val, []).append((key, prop))
            type_by_name[key] = val
            prev = types.get(val)
            if prev is None or ((prop & 1) and not (prev[1] & 1)):
                types[val] = (key, prop, bounds)
    elif i == 4:  # user
        for _ in range(nel):
            ln, val, bounds = r.u32(), r.u32(), r.u32()
            key = r.raw(ln).decode("latin-1")
            ebitmap(r)          # roles
            mls_range(r)        # range
            mls_level(r)        # dfltlevel
            users[val] = key
    elif i == 5:  # bool
        for _ in range(nel):
            val, state, ln = r.u32(), r.u32(), r.u32()
            key = r.raw(ln).decode("latin-1")
            bools[val] = (key, state)
    elif i == 6:  # sens
        for _ in range(nel):
            ln, isalias = r.u32(), r.u32()
            key = r.raw(ln).decode("latin-1")
            mls_level(r)
            sens[key] = isalias
    elif i == 7:  # cat
        for _ in range(nel):
            ln, val, isalias = r.u32(), r.u32(), r.u32()
            key = r.raw(ln).decode("latin-1")
            cats[val] = (key, isalias)
    print(f"[sym] table {i}: nprim={nprim} nel={nel} offset=0x{r.o:x}")

type_name = {v: n for v, (n, p, b) in types.items()}
attr_names = {v: n for v, (n, p, b) in types.items() if p & 1}   # TYPEDATUM_PROPERTY_PRIMARY?
attr_flag = {v: (p & 2) for v, (n, p, b) in types.items()}       # ATTRIBUTE bit

# ---- avtab ----
avtab = []
nel = r.u32()
for _ in range(nel):
    st, tt, tc, spec = r.u16(), r.u16(), r.u16(), r.u16()
    datum = r.u32()
    avtab.append((st, tt, tc, spec, datum))
print(f"[avtab] {nel} rules, offset=0x{r.o:x}")

# ---- cond list ----
cond_rules = []
ncond = r.u32()
for _ in range(ncond):
    cur_state, nexpr = r.u32(), r.u32()
    for _ in range(nexpr):
        r.u32(); r.u32()
    for which in range(2):
        n = r.u32()
        for _ in range(n):
            st, tt, tc, spec = r.u16(), r.u16(), r.u16(), r.u16()
            datum = r.u32()
            cond_rules.append((st, tt, tc, spec & ~AVTAB_ENABLED, datum, which))
print(f"[cond] {ncond} nodes, {len(cond_rules)} rules, offset=0x{r.o:x}")

# ---- role_tr / role_allow ----
n = r.u32(); role_tr = [(r.u32(), r.u32(), r.u32(), r.u32()) for _ in range(n)]
n = r.u32(); role_allow = [(r.u32(), r.u32()) for _ in range(n)]
print(f"[role] trans={len(role_tr)} allow={len(role_allow)} offset=0x{r.o:x}")

# ---- filename_trans ----
n = r.u32(); fntrans = []
for _ in range(n):
    ln = r.u32(); name = r.raw(ln).decode("latin-1")
    st, tt, tc, ot = r.u32(), r.u32(), r.u32(), r.u32()
    fntrans.append((name, st, tt, tc, ot))
print(f"[fntrans] {len(fntrans)} offset=0x{r.o:x}")

# ---- ocontexts ----
ocons = {}
for i in range(ocon_num):
    n = r.u32()
    lst = []
    for _ in range(n):
        if i == 0:            # ISID
            sid = r.u32(); ctx = context(r); lst.append((sid, ctx))
        elif i in (1, 2):     # FS, NETIF
            ln = r.u32(); nm = r.raw(ln).decode("latin-1")
            c0 = context(r); c1 = context(r)
            lst.append((nm, c0, c1))
        elif i == 3:          # PORT
            p = (r.u32(), r.u32(), r.u32()); ctx = context(r); lst.append((p, ctx))
        elif i == 4:          # NODE
            a = (r.u32(), r.u32()); ctx = context(r); lst.append((a, ctx))
        elif i == 5:          # FSUSE
            beh = r.u32(); ln = r.u32(); nm = r.raw(ln).decode("latin-1")
            ctx = context(r); lst.append((beh, nm, ctx))
        elif i == 6:          # NODE6
            a = (r.u32(), r.u32(), r.u32(), r.u32()); ctx = context(r); lst.append((a, ctx))
    ocons[i] = lst
    print(f"[ocon] type {i}: {n} entries, offset=0x{r.o:x}")

# ---- genfs ----
ngen = r.u32(); genfs = []
for _ in range(ngen):
    ln = r.u32(); fstype = r.raw(ln).decode("latin-1")
    n2 = r.u32()
    for _ in range(n2):
        ln = r.u32(); nm = r.raw(ln).decode("latin-1")
        sclass = r.u32(); ctx = context(r)
        genfs.append((fstype, nm, sclass, ctx))
print(f"[genfs] entries={len(genfs)} offset=0x{r.o:x}")

# ---- range_transition ----
n = r.u32(); rangetr = []
for _ in range(n):
    st, tt, tc = r.u32(), r.u32(), r.u32()
    rr = mls_range(r)
    rangetr.append((st, tt, tc, rr))
print(f"[rangetr] {len(rangetr)} offset=0x{r.o:x}")

# ---- type_attr_map ----
for i in range(numtypes):
    type_attr_map[i + 1] = ebitmap(r)

print(f"[end] offset=0x{r.o:x} file={len(data):#x} match={r.o == len(data)}")
if r.o != len(data):
    print("PARSE DESYNC — abort"); sys.exit(2)

# ================= 查询 =================
def cls_name(v): return classes.get(v, ("?", {}))[0]
def tname(v): return type_name.get(v, f"<{v}>")
def attrset(tval):
    """内核等价：flex_array_get(map, type-1) 的位 i 表示类型值 i+1"""
    return {b + 1 for b in type_attr_map.get(tval, [])}
def bits_to_perms(clsval, bits):
    perms = classes.get(clsval, ("?", {}))[1]
    return sorted(n for n, b in perms.items() if bits & (1 << (b - 1)))

# 推断 attribute 标记：TYPEDATUM_PROPERTY 常量
# PRIMARY=1, ATTRIBUTE=2（见 policydb.c type_read）
is_attr = {v: bool(p & 2) for v, (n, p, b) in types.items()}
attrs = {v: n for v, (n, p, b) in types.items() if p & 2}
prims = {v: n for v, (n, p, b) in types.items() if not (p & 2)}
print(f"\n[types] total={len(types)} primary={len(prims)} attributes={len(attrs)}")

# 模糊可疑属性位解释
prop_hist = defaultdict(int)
for v, (n, p, b) in types.items(): prop_hist[p] += 1
print(f"[types] prop histogram: {dict(prop_hist)}")

# --- permissive 域 ---
perm_names = [tname(b + 1) for b in permissive_map]   # bit index -> type value = bit+1
print(f"\n=== PERMISSIVE domains ({len(perm_names)}) ===\n{perm_names}")

# --- ISID ---
isid = ocons.get(0, [])
print(f"\n=== INITIAL SIDs ({len(isid)}) ===")
SIDNAMES = ["kernel","security","unlabeled","fs","file","file_labels","init","any_socket",
            "port","netif","netmsg","node","packet","iptables","secctx","secctx_to_secid",
            "key_socket"]
for sid, ctx in isid:
    nm = SIDNAMES[sid] if sid < len(SIDNAMES) else f"sid{sid}"
    print(f"  {sid:2d} {nm:18s} -> {tname(ctx[2])}:{ctx[3][0]}")

# --- 关键域分析 ---
def domain_rules(domain_name, limit_classes=("process","file","dir","capability","chr_file","sock_file","unix_stream_socket","tcp_socket","security","property")):
    tv = next((v for v, (n, p, b) in types.items() if n == domain_name), None)
    if tv is None:
        return None
    sattrs = attrset(tv)
    out = defaultdict(list)   # (cls, target) -> perms
    for st, tt, tc, spec, datum in avtab:
        if spec & AVTAB_ALLOWED and st in sattrs:
            out[(tc, tt)] |= set() if False else out[(tc, tt)]
    return tv, sattrs

# 汇总：source -> class -> 目标 -> perms
def rules_by_source(svals, allowed_only=True, typespec=(AVTAB_ALLOWED,), include_cond=False):
    res = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    src = avtab if not include_cond else avtab + [(a,b,c,d,e) for a,b,c,d,e,_ in cond_rules]
    for st, tt, tc, spec, datum in src:
        if st in svals and (spec & typespec[0]):
            res[cls_name(tc)][tname(tt)][ (tc,spec) ] |= datum
    return res

def summary_for(domain, maxcls=99):
    tv = next((v for v, (n, p, b) in types.items() if n == domain), None)
    if tv is None:
        print(f"\n=== {domain}: TYPE NOT FOUND ===")
        return
    sattrs = attrset(tv)
    print(f"\n=== {domain} (type value {tv}, attrs={[tname(a) for a in sattrs if a!=tv]}) ===")
    bycls = defaultdict(list)
    for st, tt, tc, spec, datum in avtab:
        if st in sattrs and spec == AVTAB_ALLOWED:
            bycls[cls_name(tc)].append((tname(tt), bits_to_perms(tc, datum)))
    for cls in sorted(bycls):
        n = len(bycls[cls])
        if n > 8:
            print(f"  [{cls}] {n} rules (targets: {', '.join(sorted({t for t,_ in bycls[cls]})[:6])}...)")
        else:
            for tgt, perms in sorted(bycls[cls]):
                print(f"  [{cls}] -> {tgt}: {','.join(perms)}")
    # transitions
    trans = [(tname(tt), cls_name(tc), tname(datum)) for st, tt, tc, spec, datum in avtab
             if st in sattrs and spec == AVTAB_TRANSITION]
    if trans:
        print(f"  [TRANSITIONS] " + "; ".join(f"{c}:{t}->{n}" for t, c, n in trans))

for d in ["shell", "adbd", "untrusted_app", "init"]:
    summary_for(d)

# --- su 相关 ---
print("\n=== su-related types ===")
for v, (n, p, b) in types.items():
    if "su" in n:
        print(f"  value={v} name={n} prop={p} attr={is_attr[v]}")
print("\n=== rules mentioning su_exec ===")
suex = [v for v, (n, p, b) in types.items() if n == "su_exec"]
if suex:
    s = suex[0]
    cnt = 0
    for st, tt, tc, spec, datum in avtab:
        if s in (st, tt) or (spec & (AVTAB_TRANSITION|AVTAB_MEMBER) and datum == s):
            if cnt < 40:
                print(f"  {tname(st)} -> {tname(tt)} [{cls_name(tc)}] spec={spec:#x} data={tname(datum) if spec&0x70 else bits_to_perms(tc,datum)}")
            cnt += 1
    print(f"  total {cnt}")

# 输出完整 allow 表供 grep
with open(os.path.join(OUTDIR, "sepolicy_rules.txt"), "w", encoding="utf-8") as f:
    f.write("# source target class spec perms/newtype\n")
    for st, tt, tc, spec, datum in avtab:
        if spec == AVTAB_ALLOWED:
            f.write(f"allow {tname(st)} {tname(tt)}:{cls_name(tc)} {{{','.join(bits_to_perms(tc,datum))}}}\n")
        elif spec & (AVTAB_TRANSITION|AVTAB_MEMBER|AVTAB_CHANGE):
            kind = {AVTAB_TRANSITION:"type_transition", AVTAB_MEMBER:"type_member", AVTAB_CHANGE:"type_change"}[spec & 0x70]
            f.write(f"{kind} {tname(st)} {tname(tt)}:{cls_name(tc)} {tname(datum)}\n")
        elif spec == AVTAB_AUDITALLOW:
            f.write(f"auditallow {tname(st)} {tname(tt)}:{cls_name(tc)} {{{','.join(bits_to_perms(tc,datum))}}}\n")
        elif spec == AVTAB_AUDITDENY:
            f.write(f"dontaudit {tname(st)} {tname(tt)}:{cls_name(tc)} {{...}}\n")
print(f"\n[out] full rules -> sepolicy_rules.txt")
