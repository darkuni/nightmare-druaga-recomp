# The Nightmare of Druaga: Fushigi no Dungeon - recomp notes

## Disc (USA, SLUS-210.71)

- DVD image, 4,542,955,520 bytes. Real file data is ~675 MB; the rest is padding.
- `SYSTEM.CNF`: `BOOT2 = cdrom0:\SLUS_210.71;1`, VER 1.00, NTSC
- Files: `SLUS_210.71` (2.7 MB ELF), `DATA.DAT` (DataChain archive, 211 MB), `BGM.AFS` (CRI AFS, 282 MB, 75 entries), `NODA.PSS` (178 MB intro movie, MPEG2 + ADPCM), `CACHE.DIR` (lists `bgm.afs`, `data.dat`), `MODULES/*.IRX` + `IOPRP300.IMG`
- IOP modules: SIO2MAN, PADMAN, MCMAN, MCSERV, LIBSD, SDRDRV, CDVDSTM, CRI_ADXI, MTXSND/MTXFILE/MTXADPCM, MODSESQ/MODMIDI/MODHSYN

## Executable

- Compiler: `MW MIPS C Compiler (2.4.1.01)` (Metrowerks CodeWarrior)
- Sony SDK 3.0 (`PsIIlibkernl3000`)
- CRI middleware, all built Apr 12 2004: ADXF/PS2EE 7.14, ADXT/PS2EE 9.19, ADXPS2 2.52, ADXRT 3010, CVFS 2.35, DTR 1.06, DTX 1.07, DVCI 2.70
- libmpeg (IPU) for NODA.PSS
- **Stripped.** `.symtab`/`.strtab` empty. One PT_LOAD at 0x400000, filesz 0x2A6A80, memsz 0x52FE00 (code + data + bss merged, no section split)
- Entry 0x400008. Last `jr ra` at 0x6A16BC.
- ~8,257 `jr ra`, ~5,758 distinct `jal` targets, 36,770 `jal` sites
- COP2 (VU0 macro): 1,486 ops, 950 `lqc2` / 893 `sqc2`. MMI: 1,342 ops.
- **VU1 microcode embedded in the ELF** (MPG VIFcodes right before each):
  - 0x62FF10-0x633B08 (~15 KB)
  - 0x633C10-0x6355B0 (~6.5 KB)
- GS via `sceGs*` (libgraph), path checks reference VIF1/VU1/GIF

## DataChain (DATA.DAT)

Loader at 0x564E50. Header strings at 0x67F240 region (`EB2ChainDH`, `DataChain`).

- Sector 0: magic `DataChain`, `u32 @0x10 = 0x1000`, `@0x14 = mode (2)`, `@0x18 = count (5099)`, `@0x1C = table size (0x50000)`
- Table at 0x800. Per byte: `if mode==2: b ^= key[i&0xFF]` (key = 256 words at 0x64F7A0, low byte), then `b = ~b`, then swap nibbles
- 64-byte entries: name[0x30], u32 offset, u32 size
- **Only the table is encrypted.** Payloads are plain.
- `tools/datachain.py` extracts it (stdlib only).

Content by extension: skmd 3689, dpk 218, mset 207, dfls 198, chain 157, ath 151, est 147, cst 138, efp 78, eth 38, lz 36 (`LZB1` header), dgs 12, tx 10, chaindata 5.
Top dirs: CHARACTER/WP 2405, CHARACTER/PT 1088, CHARACTER/TEST 416, MAP/DUNGEON 224, CHARACTER/THINK 189.

## Plan

1. Function boundaries: Ghidra + `ps2xRecomp/tools/ghidra/ExportPS2Functions.java` (PS2Recomp's recommended path for stripped retail ELFs)
2. Identify SDK + CRI library functions by signature so they bind to runtime HLE (`handler@0xADDR` stubs) instead of being recompiled
3. Recompile EE code with PS2Recomp; IOP via ps2xIOP HLE
4. VU1: two microprograms only - small enough to hand-translate or interpret
5. Replace CRI ADX/AFS + PSS playback with native decoders
6. Windows + Linux (SteamOS) builds via CI
