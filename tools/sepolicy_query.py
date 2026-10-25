#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

"""P1.2b: 针对性策略查询
问题：
 Q1 sid=kernel(1) 主体能做什么（commit_creds(prepare_kernel_cred(0)) 之后的能力边界）
 Q2 shell 主体：capability/process/file 权限边界
 Q3 shell 有无 process 域转换（runas? su?）
 Q4 su_exec 类型被谁用（entrypoint/transition）
 Q5 domain 属性规模校验（解析正确性旁证）
"""
import os, struct, sys
from collections import defaultdict

_HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.environ.get("SEPOLICY", os.path.join(_HERE, os.pardir, "sepolicy"))
exec(open(os.path.join(_HERE, "sepolicy_parse.py"), encoding="utf-8").read().split("# ================= 查询 =================")[0])

# 上述 exec 已执行完整解析，得到: types/type_name/classes/avtab/type_attr_map/ocon 等
def cls_name(v): return classes.get(v, ("?", {}))[0]
def tname(v): return type_name.get(v, f"<{v}>")
def attrset(tval):
    return {b + 1 for b in type_attr_map.get(tval, [])}
def bits_to_perms(clsval, bits):
    perms = classes.get(clsval, ("?", {}))[1]
    return sorted(n for n, b in perms.items() if bits & (1 << (b - 1)))
def tv_of(name):
    return next((v for v, (n, p, b) in types.items() if n == name), None)

print("\n" + "="*70)
print("Q5 domain 属性规模（解析正确性旁证）")
dom = tv_of("domain")
if dom:
    members = [v for v in types if dom in attrset(v)]
    print(f"  domain 属性成员数: {len(members)} (主类型总数 {sum(1 for v,(n,p,b) in types.items() if not p & 2)})")
for a in ["untrusteddomain", "appdomain", "netdomain", "mlstrustedsubject"]:
    av = tv_of(a)
    if av:
        print(f"  {a}: {sum(1 for v in types if av in attrset(v))} 成员")

print("\n" + "="*70)
print("Q3 shell 的 process 域转换 / entrypoint 相关")
sh = tv_of("shell")
sattrs = attrset(sh)
for st, tt, tc, spec, datum in avtab:
    if spec in (AVTAB_TRANSITION, AVTAB_MEMBER, AVTAB_CHANGE):
        if st in sattrs:
            kind = {AVTAB_TRANSITION:"type_transition", AVTAB_MEMBER:"type_member", AVTAB_CHANGE:"type_change"}[spec]
            print(f"  {kind} {tname(st)} {tname(tt)}:{cls_name(tc)} -> {tname(datum)}")
print("  -- shell 域的 capability 允许:")
for st, tt, tc, spec, datum in avtab:
    if spec == AVTAB_ALLOWED and st in sattrs and cls_name(tc) in ("capability", "capability2"):
        print(f"     {cls_name(tc)}: {','.join(bits_to_perms(tc, datum))}")

print("\n" + "="*70)
print("Q1 kernel 类型（sid 1）的完整 allow 概况")
kv = tv_of("kernel")
print(f"  kernel type value = {kv}, attrs = {[tname(a) for a in attrset(kv)]}")
kat = attrset(kv)
bycls = defaultdict(list)
for st, tt, tc, spec, datum in avtab:
    if spec == AVTAB_ALLOWED and st in kat:
        bycls[cls_name(tc)].append((tname(tt), bits_to_perms(tc, datum), st, tt))
print(f"  classes touched: {len(bycls)}")
for cls in sorted(bycls):
    items = bycls[cls]
    if len(items) <= 12:
        for tgt, perms, st_, tt_ in items:
            via = "" if st_ == kv else f" (via attr {tname(st_)})"
            print(f"    [{cls}] -> {tgt}: {','.join(perms)}{via}")
    else:
        tgts = sorted({t for t, _, _, _ in items})
        print(f"    [{cls}] {len(items)} rules, {len(tgts)} targets: {', '.join(tgts[:10])}...")
print("  -- kernel 的 process 转换:")
for st, tt, tc, spec, datum in avtab:
    if spec in (AVTAB_TRANSITION,) and st in kat:
        print(f"     {tname(st)} {tname(tt)}:{cls_name(tc)} -> {tname(datum)}")

print("\n" + "="*70)
print("Q4 su_exec 相关规则")
suex = tv_of("su_exec")
if suex:
    hits = 0
    for st, tt, tc, spec, datum in avtab:
        related = (st == suex) or (tt == suex) or (spec & 0x70 and datum == suex)
        if related:
            hits += 1
            if hits <= 25:
                if spec == AVTAB_ALLOWED:
                    print(f"  allow {tname(st)} {tname(tt)}:{cls_name(tc)} {{{','.join(bits_to_perms(tc,datum))}}}")
                else:
                    kind = {AVTAB_TRANSITION:"type_transition",AVTAB_MEMBER:"type_member",AVTAB_CHANGE:"type_change"}.get(spec, f"spec{spec:#x}")
                    print(f"  {kind} {tname(st)} {tname(tt)}:{cls_name(tc)} -> {tname(datum)}")
    print(f"  total {hits} rules referencing su_exec")
else:
    print("  su_exec type not found!")

print("\n" + "="*70)
print("Q2 shell 作为 uid0 的实际文件写权限（file/dir 类，write 相关）")
for cls in ("file", "dir"):
    cnt = 0
    for st, tt, tc, spec, datum in avtab:
        if spec == AVTAB_ALLOWED and st in sattrs and cls_name(tc) == cls:
            perms = bits_to_perms(tc, datum)
            if any(p in perms for p in ("write", "append", "create", "add_name", "remove_name", "unlink", "rename")):
                if cnt < 40:
                    print(f"  [{cls}] -> {tname(tt)}: {','.join(p for p in perms if p in ('write','append','create','add_name','remove_name','unlink','rename','setattr'))}")
                cnt += 1
    print(f"  ... [{cls}] 共 {cnt} 条带写语义的规则")
