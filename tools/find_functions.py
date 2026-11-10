#!/usr/bin/env python3
"""Heuristic function-boundary finder for the stripped SLUS_210.71.

Seeds: ELF entry, every in-range JAL target, every `addiu sp,sp,-N` that follows
a `jr ra` + delay slot (+ optional nop padding). Function end = the next start.
Output CSV: start,end,size,source  (hex addresses)

Usage: find_functions.py SLUS_210.71 out.csv
Stdlib only. Feeds the PS2Recomp config until a Ghidra export replaces it.
"""
import struct
import sys

JR_RA = 0x03E00008
NOP = 0


def load(elf):
    d = open(elf, "rb").read()
    entry, phoff = struct.unpack_from("<II", d, 0x18)
    phentsize, phnum = struct.unpack_from("<HH", d, 0x2A)
    for i in range(phnum):
        p_type, p_off, p_vaddr, _, p_filesz = struct.unpack_from("<5I", d, phoff + i * phentsize)
        if p_type == 1 and p_filesz:
            return entry, p_vaddr, d[p_off:p_off + p_filesz]
    sys.exit("no PT_LOAD")


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    entry, base, blob = load(sys.argv[1])
    w = struct.unpack("<%dI" % (len(blob) // 4), blob)
    # code ends after the last jr ra (+ delay slot)
    last = max(i for i, x in enumerate(w) if x == JR_RA) + 2
    end_addr = base + last * 4
    src = {}

    def add(a, s):
        if base <= a < end_addr and a % 4 == 0:
            src.setdefault(a, s)

    add(entry, "entry")
    for x in w[:last]:
        if x >> 26 == 3:
            add(((x & 0x3FFFFFF) << 2) | (base & 0xF0000000), "jal")
    for i in range(last):
        if w[i] == JR_RA:
            j = i + 2
            while j < last and w[j] == NOP:
                j += 1
            if j < last and (w[j] >> 16) == 0x27BD and (w[j] & 0x8000):
                add(base + j * 4, "prologue")
    starts = sorted(src)
    with open(sys.argv[2], "w") as f:
        f.write("start,end,size,source\n")
        for k, a in enumerate(starts):
            e = starts[k + 1] if k + 1 < len(starts) else end_addr
            f.write("0x%08X,0x%08X,%d,%s\n" % (a, e, e - a, src[a]))
    from collections import Counter
    print("%d functions, code 0x%X-0x%X" % (len(starts), base, end_addr), dict(Counter(src.values())))


if __name__ == "__main__":
    main()
