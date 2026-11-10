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
  - any data word pointing into code B (static-ctor table)
  - data words pointing at a stack prologue in code A (vtables / callback tables)
  - addresses built in code with lui/addiu that land in code (function pointers)
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

    # stack prologue straight after an unconditional tail jump (`j target` or `b`) + delay slot,
    # e.g. ADXT_StartAfs at 0x615F20 follows a `j 0x612620` wrapper.
    for lo, hi in CODE_REGIONS:
        for i in range(idx(lo), idx(hi) - 2):
            x = w[i]
            is_j = x >> 26 == 2
            is_b = (x >> 16) == 0x1000  # beq zero,zero
            if not (is_j or is_b):
                continue
            k = i + 2
            while k < idx(hi) and w[k] == 0:
                k += 1
            if k < idx(hi) and (w[k] >> 16) == 0x27BD and (w[k] & 0x8000):
                add(base + k * 4, "prologue_after_j")

    # code B is only reached through pointers (static-ctor table at 0x6A16D0-0x6A1AF0)
    lo_b, hi_b = CODE_REGIONS[1]
    for i, x in enumerate(w):
        if region_of(base + i * 4) is None and lo_b <= x < hi_b:
            add(x, "ctor_ptr")

    def is_prologue(a):
        x = w[idx(a)]
        return (x >> 16) == 0x27BD and (x & 0x8000)

    # data words pointing at a stack prologue in code A (vtables, callback tables).
    # Prologue-only: switch-table case labels also live in data and must not split functions.
    lo_a, hi_a = CODE_REGIONS[0]
    for i, x in enumerate(w):
        if region_of(base + i * 4) is None and lo_a <= x < hi_a and x % 4 == 0 and is_prologue(x):
            add(x, "data_ptr")

    # data words pointing at a frameless leaf that starts right after `jr ra` + delay slot
    # (or after nop padding), e.g. CRI callback tables. Skip jump-table-like runs:
    # >=3 consecutive pointers clustered within 0x800 bytes, mostly not known starts.
    in_jt = set()
    i = 0
    n = len(w)
    while i < n:
        j = i
        while j < n and region_of(base + j * 4) is None and lo_a <= w[j] < hi_a and w[j] % 4 == 0:
            j += 1
        if j - i >= 3:
            run = w[i:j]
            known = sum(1 for t in run if t in src)
            # jump table: targets cluster inside one function and are mostly not known starts.
            # function table (e.g. CRI callbacks at 0x665740): mostly known starts.
            if max(run) - min(run) < 0x800 and known * 2 < len(run):
                in_jt.update(range(i, j))
        i = j + 1 if j == i else j
    for i, x in enumerate(w):
        if i in in_jt or region_of(base + i * 4) is not None:
            continue
        if lo_a <= x < hi_a and x % 4 == 0:
            k = idx(x)
            if w[k - 2] == JR_RA or (w[k - 1] == 0 and w[k] != 0):
                add(x, "data_leaf")

    # function pointers built in code: lui rX,hi ; addiu rY,rX,lo  (within 8 instructions)
    for lo, hi in CODE_REGIONS:
        for i in range(idx(lo), idx(hi)):
            x = w[i]
            if x >> 26 != 0x0F:
                continue
            rt = (x >> 16) & 31
            upper = (x & 0xFFFF) << 16
            for j in range(i + 1, min(i + 9, idx(hi))):
                y = w[j]
                if y >> 26 == 0x09 and (y >> 21) & 31 == rt:
                    a = (upper + ((y & 0xFFFF) ^ 0x8000) - 0x8000) & 0xFFFFFFFF
                    if region_of(a) and a % 4 == 0:
                        add(a, "lui_ptr")
                    break
                if (y >> 16) & 31 == rt and y >> 26 in (0x0F, 0x08, 0x09, 0x0D, 0x23):
                    break  # rt overwritten

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
