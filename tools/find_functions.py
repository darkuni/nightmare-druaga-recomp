#!/usr/bin/env python3
"""Function-boundary finder for the stripped SLUS_210.71.

The single PT_LOAD mixes code and data:
  0x400000-0x62F540  code A (main game + SDK + CRI)
  0x62F540-0x689000  data: VU1 microcode (0x62FF10, 0x633C10), rodata, jump tables
  0x689000-0x6A16C4  code B (static initializers, reached via a pointer table)
  0x6A16C4-end       data

Function starts:
  - ELF entry, every JAL target
  - padded boundary: `jr ra` + delay slot, >=1 nop of padding, next non-nop word
    (CodeWarrior pads functions with nops; multi-return functions have no padding)
  - `addiu sp,sp,-N` straight after `jr ra` + delay slot
Function end = next start, clamped to its region.

Output: PS2Recomp ghidra_output CSV  (name,start,end,size)
Usage: find_functions.py SLUS_210.71 out.csv
Stdlib only.
"""
import struct
import sys
from collections import Counter

JR_RA = 0x03E00008
CODE_REGIONS = [(0x400000, 0x62F540), (0x689000, 0x6A16C4)]


def load(elf):
    d = open(elf, "rb").read()
    entry, phoff = struct.unpack_from("<II", d, 0x18)
    phentsize, phnum = struct.unpack_from("<HH", d, 0x2A)
    for i in range(phnum):
        p_type, p_off, p_vaddr, _, p_filesz = struct.unpack_from("<5I", d, phoff + i * phentsize)
        if p_type == 1 and p_filesz:
            return entry, p_vaddr, d[p_off:p_off + p_filesz]
    sys.exit("no PT_LOAD")


def region_of(a):
    for r in CODE_REGIONS:
        if r[0] <= a < r[1]:
            return r
    return None


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    entry, base, blob = load(sys.argv[1])
    w = struct.unpack("<%dI" % (len(blob) // 4), blob)
    idx = lambda a: (a - base) // 4
    src = {}

    def add(a, s):
        if a % 4 == 0 and region_of(a):
            src.setdefault(a, s)

    add(entry, "entry")
    for lo, hi in CODE_REGIONS:
        add(lo, "region")
        for i in range(idx(lo), idx(hi)):
            x = w[i]
            if x >> 26 == 3:
                add(((x & 0x3FFFFFF) << 2) | (base & 0xF0000000), "jal")
            if x == JR_RA:
                j = i + 2
                k = j
                while k < idx(hi) and w[k] == 0:
                    k += 1
                if k >= idx(hi):
                    continue
                if (w[k] >> 16) == 0x27BD and (w[k] & 0x8000):
                    add(base + k * 4, "prologue")
                elif k > j:
                    add(base + k * 4, "padded")

    starts = sorted(src)
    rows = []
    for n, a in enumerate(starts):
        hi = region_of(a)[1]
        e = min(starts[n + 1] if n + 1 < len(starts) else hi, hi)
        rows.append((a, e))
    with open(sys.argv[2], "w") as f:
        f.write("name,start,end,size\n")
        for a, e in rows:
            f.write("sub_%08X,0x%08X,0x%08X,%d\n" % (a, a, e, e - a))
    print("%d functions" % len(rows), dict(Counter(src.values())))


if __name__ == "__main__":
    main()
