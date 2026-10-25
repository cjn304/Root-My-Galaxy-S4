#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P4.92 只读侦察：按 avtab 哈希走一条桶链，验证 key/node 布局。

用法: python avtab_walk.py <htable_hex> <nslot> <src> <tgt> <cls>
"""
import subprocess
import sys
import re

KTOOL = "/data/local/tmp/ktool"


def kdump(addr, ln):
    out = subprocess.run(["adb", "shell", "%s dump 0x%x %d" % (KTOOL, addr, ln)],
                         capture_output=True, text=True).stdout
    m = re.search(r"^%08x ((?:[0-9a-f]{8} ?)+)" % addr, out, re.M)
    if not m:
        raise SystemExit("dump failed @0x%x: %r" % (addr, out[:200]))
    hexs = m.group(1).split()
    return b"".join(bytes.fromhex(h) for h in hexs)  # ktool 按内存字节序打印


def u16(b, o):
    return int.from_bytes(b[o:o + 2], "little")


def u32(b, o):
    return int.from_bytes(b[o:o + 4], "little")


def main():
    ht = int(sys.argv[1], 16)
    nslot = int(sys.argv[2])
    src, tgt, cls = int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
    h = (cls + (tgt << 2) + (src << 9)) & (nslot - 1)
    print("hash(%d,%d,%d) & mask = %d  -> bucket 0x%x" % (src, tgt, cls, h, ht + h * 4))
    p = u32(kdump(ht + h * 4, 4), 0)
    n = 0
    while p and n < 64:
        b = kdump(p, 16)
        s, t, c, spec = u16(b, 0), u16(b, 2), u16(b, 4), u16(b, 6)
        datum = u32(b, 8)
        nxt = u32(b, 12)
        mark = "  <<< MATCH" if (s, t, c) == (src, tgt, cls) else ""
        print("  [%2d] 0x%08x  %5d -> %5d cls=%2d spec=0x%04x allowed=0x%08x next=0x%08x%s"
              % (n, p, s, t, c, spec, datum, nxt, mark))
        p = nxt
        n += 1
    print("chain length = %d" % n)


main()
