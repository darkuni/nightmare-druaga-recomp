#!/usr/bin/env python3
"""DataChain (DATA.DAT) extractor for The Nightmare of Druaga: Fushigi no Dungeon (PS2, SLUS-210.71).

Reimplements the loader at 0x564E50 in SLUS_210.71:
  - sector 0 header: "DataChain" magic, u32 @0x10 == 0x1000,
    u32 @0x14 = cipher mode, u32 @0x18 = entry count, u32 @0x1C = table size
  - table starts at 0x800, `table size` bytes
  - per table byte i:  if mode == 2: b ^= key[i & 0xFF]   (256 u32 words @ 0x64F7A0, low byte used)
                       b = ~b; b = swap_nibbles(b)
  - entry = 64 bytes: name[0x30] NUL-padded, u32 offset (bytes), u32 size (bytes), 8 bytes unused
File payloads are stored in the clear.

Usage: datachain.py SLUS_210.71 DATA.DAT OUTDIR [--list]
Pure stdlib, no dependencies.
"""
import os
import struct
import sys

ELF_KEY_VADDR = 0x64F7A0
MAGIC = b"DataChain\0"


def load_key(elf_path):
    d = open(elf_path, "rb").read()
    if d[:4] != b"\x7fELF":
        sys.exit("not an ELF: " + elf_path)
    phoff, = struct.unpack_from("<I", d, 0x1C)
    phentsize, phnum = struct.unpack_from("<HH", d, 0x2A)
    for i in range(phnum):
        p_type, p_off, p_vaddr, _, p_filesz = struct.unpack_from("<5I", d, phoff + i * phentsize)
        if p_type == 1 and p_vaddr <= ELF_KEY_VADDR < p_vaddr + p_filesz:
            o = p_off + ELF_KEY_VADDR - p_vaddr
            return [w & 0xFF for w in struct.unpack_from("<256I", d, o)]
    sys.exit("key table not found in ELF (wrong executable?)")


def read_table(dat, key):
    hdr = dat.read(0x800)
    if not hdr.startswith(MAGIC):
        sys.exit("bad DataChain magic")
    tag, mode, count, size = struct.unpack_from("<4I", hdr, 0x10)
    if tag != 0x1000:
        sys.exit("unexpected header tag %#x" % tag)
    t = bytearray(dat.read(size))
    for i, b in enumerate(t):
        if mode == 2:
            b ^= key[i & 0xFF]
        b = ~b & 0xFF
        t[i] = ((b & 0xF) << 4) | (b >> 4)
    ents = []
    for k in range(count):
        e = t[k * 64:(k + 1) * 64]
        name = e[:0x30].split(b"\0")[0].decode("ascii")
        off, sz = struct.unpack_from("<II", e, 0x30)
        ents.append((name, off, sz))
    return ents


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 3:
        sys.exit(__doc__)
    elf, datp, out = args
    key = load_key(elf)
    with open(datp, "rb") as dat:
        ents = read_table(dat, key)
        if "--list" in sys.argv:
            for i, (n, o, s) in enumerate(ents):
                print("%d\t%s\t%#x\t%d" % (i, n, o, s))
            return
        for n, o, s in ents:
            dst = os.path.join(out, *n.split("/"))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            dat.seek(o)
            with open(dst, "wb") as f:
                f.write(dat.read(s))
    print("extracted %d files to %s" % (len(ents), out))


if __name__ == "__main__":
    main()
