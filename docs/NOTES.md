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

## Memory layout (single PT_LOAD)

| Range | Contents |
|---|---|
| 0x400000-0x62F540 | code A (game, SDK, CRI) |
| 0x62F540-0x689000 | data: VU1 microcode (MPG at 0x62FF0C / 0x633C0C), rodata, jump tables (e.g. 0x688E60) |
| 0x689000-0x6A16C4 | code B: static initializers, only reached through a pointer table |
| 0x6A16C4-0x6A6880 | data |

## Function map

`tools/find_functions.py` writes a PS2Recomp `ghidra_output` CSV: 8,323 functions
(4,182 JAL targets, 2,695 prologues after `jr ra`, 1,359 nop-padded boundaries, 21 static-ctor
table entries, 26 data pointers to prologues, 37 lui/addiu-built function pointers, entry, 2 region starts).

Static-ctor table: 0x6A16D0-0x6A1AF0 (264 pointers into code B), run by the CRT before main.

## Boot log

1. ELF loads, kernel/CRT start, ctors at 0x689000/0x689040/0x6891E0 run, stops at 0x689200 (missed ctor) -> fixed with ctor-table rule
2. All ctors pass, stops at 0x490B30 (callback built with lui/addiu, follows a tail branch) -> fixed with pointer rules

## PS2Recomp status (ran-j/PS2Recomp @ e563698)

- `ps2_analyzer` -> `config/druaga.toml`: 215 SDK functions bound to runtime handlers, 346 library functions detected without handlers, 3 jump tables, MMIO map
- Without the map the analyzer decodes the data region as code (6,958 errors). With `functions.csv`: **0 errors**, 8,024 recompiled, 215 stubs
- 1,336 warnings, all unresolved JR/JALR (switch tables + function pointers) handled by runtime fallback lookup
- Generated C++ (~149 MB) is derived from the game and is never committed
3. Ctors + `main` run, all 12 IRX modules load on ps2xIOP (SIO2MAN ... CRI_ADXI). Stalls after `CRI ADX Driver : sceSdInit(SD_INIT_COLD)`.
   - gdb: EE spinning in `sub_00423438` = `sceCdLayerSearchFile` (real libcdvd code waiting on cdvdfsv). The analyzer left it and its wrapper `sceCdSearchFile` (0x423738) unbound. CRI CVFS calls the layer version directly from 0x61C1CC.
   - Fix: bind both addresses to the runtime `sceCdSearchFile` handler (config/druaga.toml)
   - Side fix: `patches/0001-ps2xIOP-spu2-statx-ready.patch` - SPU2 STATX bit 7 always reads ready; LIBSD otherwise polls up to 16M iterations per transfer

## Building

PS2Recomp @ e563698 + `patches/*.patch`. GCC needs `-march=x86-64-v3` (SSE4.1 intrinsics in ps2_memory.cpp; MSVC doesn't care).

4. After the CD fix: `\DATA.DAT;1` and `\BGM.AFS;1` resolve, first GIF chain goes out (`sceDmaSend` ch2, chain, TIE), then EE spins in `sub_0042BB70`, a DMA-queue drain (`while q[0x14] != q[0x18] sceDmaSync`).
   - Queue class vtable at 0x6A1B98. Consumer is the DMAC handler 0x42C010 (registered via `AddDmacHandler` syscall 0x12, arg = queue), which advances q[0x18] and kicks the next `sceDmaSend`.
   - Runtime traced: DMA-complete reaches `dispatchIrq(dmac, 2)` but the channel-2 enable bit is clear (mask 0xFFFFFFFB). The game brackets kicks with `DisableDmac(2)`/`EnableDmac(2)` and the runtime finishes the transfer synchronously inside that window, then drops the masked interrupt.
   - Fix: `patches/0002-runtime-dmac-latch-callback-stacks-priority0.patch` latches masked DMAC causes (like D_STAT) and delivers them on `EnableDmac`.
5. GIF + VIF1 queues drain (VU1 microcode upload from 0x62F600). Pad init runs (60-frame waits), then the main thread jumps to 0.
   - Cause: runtime interrupt/callback stacks are carved down from 0x2000000, and this game's `SetupThread(gp, 0x1FE0000, 0x20000)` puts the main stack right there. Callback frames overwrote `main`'s saved `ra` (main = 0x427C70, frame at 0x1FFFF70).
   - Fix (same patch 0002): `invocationStackTop()` skips carve-outs that overlap any guest thread stack (now 0x1FDFFF0).
6. Gets through `INIT GS` and `INIT ENVIRONMENT`, MTXSND starts its sequencer thread. Missing function 0x61C388: frameless CRI leaf reached only via a function table at 0x665740.
   - Fix: `data_leaf` rule in find_functions.py (data pointers landing right after `jr ra`+delay or padding; runs clustered in <0x800 that are mostly unknown targets are treated as switch tables and skipped). 8,793 functions; none of the analyzer's 72 jump-table targets became starts.

## Debug switches (local runtime build only, not in patches)

`DRUAGA_SCHED_TRACE`, `DRUAGA_SYSCALL_TRACE`, and `PS2X_ENABLE_AGRESSIVE_LOGS=ON` (writes ps2_log.txt call trace). Run with `stdbuf -o0` or stdout is lost on kill.
7. Reaches `ADX WORK SIZE : 0x0004b1e4`, then main `SleepThread`s forever (inside 0x5652F0 loop, after CRI init).
   - CRI ADXM creates its 4 server threads (0x60F550/0x60F640/0x60F748/0x60F828) at main's *current* priority (read via `ReferThreadStatus(0)` -> 0x662458). Main is priority 0; the runtime's `CreateThread` and `ChangeThreadPriority` rejected 0 with KE_ILLEGAL_PRIORITY (-403). CRI stored -403 as its thread id and the VSync handler `iReferThreadStatus`/`iWakeupThread` never hit a real thread.
   - Fix (patch 0002): accept priority 0..127, like the EE kernel.
8. CRI ADX's EE<->IOP path (PS2RNA -> CRI_ADXI.IRX) handed back a NULL buffer and CRI trapped at 0x6257A8. ADXM's server handshake (priority juggling + Suspend/Resume, then WakeupThread) also never settled under the cooperative scheduler, so main slept forever in 0x610AB8.
   - **Native CRI.** `runtime/DruagaAdx.cpp` (patch 0003) replaces the game's CRI surface:
     - ADXT: `StartAfs` 0x615F20, `Stop` 0x614710, `GetStat` 0x6147D0, `SetOutVol` 0x615098. Decodes ADX straight from BGM.AFS (all 75 tracks: ADX v4, stereo, 48 kHz, unencrypted, highpass 500, 54 loop) and plays through raylib audio streams. Decoder output is bit-exact against a reference decoder, including the loop wrap.
     - ADXF: `Open` 0x60DC98, `Seek` 0x60E690, `Tell` 0x60E7A8, `ReadNw` 0x60E370, `GetStat` 0x60E8F0, `LoadPartitionNw` 0x60D290, `GetPtStat` 0x60D6E8. Synchronous reads from the disc files.
     - `ret0`: PS2RNA server 0x623408, ADXM exec 0x610970 / 0x610AB8.
   - Game BGM API (for reference): play = `ADXT_StartAfs(handle[slot], ptid, table_0x64FBA0[idx])` via 0x565430; stop 0x565460; volume = 300*f - 300 (0.1 dB) via 0x565530; `ADXT_GetStat` polled for 4 handles at 0x565480.
   - find_functions.py: `prologue_after_j` rule (prologue after an unconditional `j`/`b` + delay). 8,913 functions, 0 errors.
9. **First frame.** DATA.DAT loads, SE bank goes to MTXSND ("setup SeSequence"), and the autosave notice renders (docs/img/first_frame.png). Pressing X (keyboard X = cross) passes it; the memory card check succeeds.
10. Intro movie NODA.PSS: runtime needs `PS2X_ENABLE_FFMPEG=ON` (Linux: libavcodec/libavformat/libswscale/libswresample dev packages; Windows: the runtime fetches a prebuilt FFmpeg). Then it decoded 8 frames and deadlocked: this game reads + demuxes only from its `sceMpegCbNodata` callback (0x5E82F0, called from inside `sceMpegGetPicture`), with no separate feeder thread.
    - Fix: `patches/0004-runtime-mpeg-nodata-callback.patch`. When `GetPicture` runs dry it queues the game's Nodata callbacks as guest calls, wakes itself when one finishes, and marks the stream ended if a callback returns 0.
    - Movie plays (docs/img/intro_movie.png). Start skips it.
11. **Title screen** (docs/img/title_screen.png). `ADXT_StartAfs(ptid=1, fid=1)` goes through the native ADX player for the title BGM. Idle on the title loops back to the attract movie.

## Input (runtime keyboard map)

Arrows = D-pad, X = cross, C = circle, Z = square, V = triangle, Enter = Start, Q/E = L1/R1, 1/3 = L2/R2.
