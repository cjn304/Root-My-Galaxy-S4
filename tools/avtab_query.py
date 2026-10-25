#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

# -*- coding: utf-8 -*-
"""P4.92 只读侦察：从 sepolicy 二进制取出 avtab 插入所需的数值。

复用 sepolicy_parse.py 的解析结果（该解析器已用 offset==filesize 自校验），
输出：type 值、class 值、指定 class 下各权限的位号（mask = 1 << (bit-1)）、
以及若干条已知规则的 avtab key + hash slot，供设备侧内存验证。
"""
import io
import os
import sys
import json
import contextlib
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
PARSER = os.path.join(HERE, "sepolicy_parse.py")

spec = importlib.util.spec_from_file_location("sp", PARSER)
sp = importlib.util.module_from_spec(spec)
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    spec.loader.exec_module(sp)

type_by_name = sp.type_by_name
classes = sp.classes          # value -> (name, {perm: bit})
cls_by_name = {}
for v, (name, perms) in classes.items():
    cls_by_name[name] = (v, perms)


def tval(name):
    if name not in type_by_name:
        raise SystemExit("no such type: %s" % name)
    return type_by_name[name]


def cval(name):
    if name not in cls_by_name:
        raise SystemExit("no such class: %s" % name)
    return cls_by_name[name][0]


def perm_mask(cls, names):
    v, perms = cls_by_name[cls]
    m = 0
    for n in names:
        if n not in perms:
            raise SystemExit("class %s has no perm %s (have: %s)" %
                             (cls, n, ",".join(sorted(perms))))
        m |= 1 << (perms[n] - 1)
    return m


NEED_TYPES = [
    "init_shell", "untrusted_app", "shell", "app_data_file", "shell_data_file",
    "system_data_file", "su_exec", "null_device", "zygote", "init",
    "app_process", "system_server", "untrusted_app_25", "platform_app",
    "system_app", "isolated_app", "su",
]
NEED_CLASSES = ["fd", "process", "dir", "file", "sock_file",
                "unix_stream_socket", "binder", "capability", "service_manager"]

print("=== TYPES ===")
tvals = {}
for n in NEED_TYPES:
    if n in type_by_name:
        tvals[n] = type_by_name[n]
        print("  %-20s %4d" % (n, tvals[n]))
    else:
        print("  %-20s (不存在)" % n)

print("\n=== CLASSES ===")
cvals = {}
for n in NEED_CLASSES:
    if n in cls_by_name:
        v, perms = cls_by_name[n]
        cvals[n] = v
        print("  %-20s %3d  perms: %s" % (
            n, v, ", ".join("%s=%d" % (k, b) for k, b in sorted(perms.items(), key=lambda x: x[1]))))
    else:
        print("  %-20s (不存在)" % n)

print("\n=== 需要的规则 ===")
PLAN = [
    ("init_shell", "untrusted_app", "fd", ["use"]),
    ("untrusted_app", "init_shell", "process", ["sigchld", "sigkill", "signal"]),
    ("untrusted_app", "shell_data_file", "sock_file", ["create", "write", "read", "getattr", "unlink"]),
    ("untrusted_app", "shell_data_file", "dir", ["add_name", "remove_name", "search", "write"]),
    ("init_shell", "shell_data_file", "file", ["read", "write", "open", "getattr"]),
]
plan_out = []
for src, tgt, cls, perms in PLAN:
    try:
        s, t, c = tval(src), tval(tgt), cval(cls)
    except SystemExit as e:
        print("  [skip] %s" % e)
        continue
    have = []
    for p in perms:
        try:
            perm_mask(cls, [p])
            have.append(p)
        except SystemExit:
            pass
    m = perm_mask(cls, have)
    plan_out.append(dict(src=s, tgt=t, cls=c, mask=m, srcn=src, tgtn=tgt, clsn=cls, perms=have))
    print("  allow %-14s %-18s:%s { %s }  -> src=%d tgt=%d cls=%d mask=0x%x"
          % (src, tgt, cls, ",".join(have), s, t, c, m))

print("\n=== 已知规则定位（用于内存验证） ===")
# 选一条必然存在、且两端都是具体 type 的规则
CAND = [("init_shell", "app_data_file", "dir"),
        ("init_shell", "app_data_file", "file"),
        ("untrusted_app", "app_data_file", "dir"),
        ("untrusted_app", "app_data_file", "file"),
        ("init", "init", "process")]
avtab = sp.avtab  # (src, tgt, cls, spec, datum)
for src, tgt, cls in CAND:
    s, t, c = tval(src), tval(tgt), cval(cls)
    hits = [(spec, datum) for (a, b, cc, spec, datum) in avtab
            if a == s and b == t and cc == c and spec == 1]
    if hits:
        spec, datum = hits[0]
        print("  %s -> %s:%s  src=%d tgt=%d cls=%d allowed=0x%x perms=%s"
              % (src, tgt, cls, s, t, c, datum,
                 ",".join(sp.bits_to_perms(c, datum))))
        break

json.dump(dict(types=tvals, classes=cvals, plan=plan_out),
          open(os.path.join(HERE, "avtab_numbers.json"), "w"), indent=1)
print("\n[out] avtab_numbers.json")
