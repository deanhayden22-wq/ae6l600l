"""
SH-2E disassembler for the AE5L600L ROM (Renesas SH7058).

CANONICAL DECODER for this project. Prefer this over the ~27 per-script copies
in scripts/disasm/ -- those were written independently and each carried a bogus
FSQRT decode (patched 2026-07-26 to emit .INVALID_SH2E instead).

Architecture note -- this matters, get it right:
    SH7058 = SH-2E core = classic SH-2 integer ISA + SINGLE-PRECISION FPU.
    It is NOT plain SH-2 (no FPU) and NOT SH-2A (32-bit instrs, MOVI20, MOVU).
    Verified from ROM bytes: ~28,000 FPU sites, zero SH-2A-only encodings.

Instructions this core does NOT have, so seeing one means you are decoding DATA
as code -- treat as a region-boundary error, not a finding:
    FSQRT, FSCHG, FRCHG, any double-precision op, MOVI20, MOVU, 32-bit forms.
This module emits ".word 0x#### (INVALID-SH2E)" for those rather than inventing
a mnemonic.

Memory map (SH7058):
    ROM  0x00000000-0x000FFFFF   (1 MB)
    RAM  0xFFFF0000-0xFFFFBFFF   (48 KB on-chip)  <- note: NOT 0xFFFF8000+
    On-chip peripherals  0xFFFFE000-0xFFFFFFFF   (ATU-II timers at 0xFFFFF6xx)

Usage:
    from sh2e_disasm import disasm
    rom = open('rom/ae5l600l.bin','rb').read()
    for pc, word, text, is_delay_slot_parent in disasm(rom, 0x09A3B0, 0x09A4A0):
        print(f"{pc:06X}  {word:04X}  {text}")
"""
import struct


def _n(w): return (w >> 8) & 0xF
def _m(w): return (w >> 4) & 0xF
def _d4(w): return w & 0xF
def _d8(w): return w & 0xFF
def _s8(w):
    v = w & 0xFF
    return v - 0x100 if v & 0x80 else v
def _s12(w):
    v = w & 0xFFF
    return v - 0x1000 if v & 0x800 else v


def decode(w, pc):
    n, m, d4, d8 = _n(w), _m(w), _d4(w), _d8(w)
    R, F = f"r{n}", f"r{m}"
    FRn, FRm = f"fr{n}", f"fr{m}"
    op = w >> 12

    if w == 0x0009: return "nop", False
    if w == 0x000B: return "rts", True
    if w == 0x0028: return "clrmac", False
    if w == 0x0048: return "clrs", False
    if w == 0x0008: return "clrt", False
    if w == 0x0019: return "div0u", False
    if w == 0x001B: return "sleep", False
    if w == 0x002B: return "rte", True
    if w == 0x0058: return "sets", False
    if w == 0x0018: return "sett", False

    if op == 0x0:
        if d4 == 0x4: return f"mov.b {F},@(r0,{R})", False
        if d4 == 0x5: return f"mov.w {F},@(r0,{R})", False
        if d4 == 0x6: return f"mov.l {F},@(r0,{R})", False
        if d4 == 0x7: return f"mul.l {F},{R}", False
        if d4 == 0xC: return f"mov.b @(r0,{F}),{R}", False
        if d4 == 0xD: return f"mov.w @(r0,{F}),{R}", False
        if d4 == 0xE: return f"mov.l @(r0,{F}),{R}", False
        if d4 == 0xF: return f"mac.l @{F}+,@{R}+", False
        if d4 == 0x3:
            return {0x0: f"bsrf {R}", 0x2: f"braf {R}", 0x8: f"pref @{R}"}.get(m, f".word 0x{w:04X}"), m in (0, 2)
        if d4 == 0xA:
            return {0x0: f"sts mach,{R}", 0x1: f"sts macl,{R}", 0x2: f"sts pr,{R}",
                    0x5: f"sts fpul,{R}", 0x6: f"sts fpscr,{R}"}.get(m, f".word 0x{w:04X}"), False
        if d4 == 0x2:
            return {0x0: f"stc sr,{R}", 0x1: f"stc gbr,{R}", 0x2: f"stc vbr,{R}"}.get(m, f".word 0x{w:04X}"), False
        if d4 == 0x9:
            # 0x0009 nop and 0x0019 div0u are matched exactly above; 0000nnnn00101001 = MOVT Rn
            return (f"movt {R}", False) if m == 0x2 else (f".word 0x{w:04X}", False)
        if d4 == 0x8 and n == 0:
            return {0x0: "clrt", 0x1: "sett", 0x2: "clrmac", 0x4: "clrs", 0x5: "sets"}.get(m, f".word 0x{w:04X}"), False
        if d4 == 0xB and n == 0:
            return {0x0: "rts", 0x1: "sleep", 0x2: "rte"}.get(m, f".word 0x{w:04X}"), m in (0, 2)
        return f".word 0x{w:04X}", False

    if op == 0x1: return f"mov.l {F},@({d4*4},{R})", False
    if op == 0x2:
        return {0x0: f"mov.b {F},@{R}", 0x1: f"mov.w {F},@{R}", 0x2: f"mov.l {F},@{R}",
                0x4: f"mov.b {F},@-{R}", 0x5: f"mov.w {F},@-{R}", 0x6: f"mov.l {F},@-{R}",
                0x7: f"div0s {F},{R}", 0x8: f"tst {F},{R}", 0x9: f"and {F},{R}",
                0xA: f"xor {F},{R}", 0xB: f"or {F},{R}", 0xC: f"cmp/str {F},{R}",
                0xD: f"xtrct {F},{R}", 0xE: f"mulu.w {F},{R}", 0xF: f"muls.w {F},{R}"}.get(d4, f".word 0x{w:04X}"), False
    if op == 0x3:
        return {0x0: f"cmp/eq {F},{R}", 0x2: f"cmp/hs {F},{R}", 0x3: f"cmp/ge {F},{R}",
                0x4: f"div1 {F},{R}", 0x5: f"dmulu.l {F},{R}", 0x6: f"cmp/hi {F},{R}",
                0x7: f"cmp/gt {F},{R}", 0x8: f"sub {F},{R}", 0xA: f"subc {F},{R}",
                0xB: f"subv {F},{R}", 0xC: f"add {F},{R}", 0xD: f"dmuls.l {F},{R}",
                0xE: f"addc {F},{R}", 0xF: f"addv {F},{R}"}.get(d4, f".word 0x{w:04X}"), False
    if op == 0x4:
        one = {0x00: f"shll {R}", 0x01: f"shlr {R}", 0x04: f"rotl {R}", 0x05: f"rotr {R}",
               0x08: f"shll2 {R}", 0x09: f"shlr2 {R}", 0x10: f"dt {R}", 0x11: f"cmp/pz {R}",
               0x15: f"cmp/pl {R}", 0x18: f"shll8 {R}", 0x19: f"shlr8 {R}",
               0x20: f"shal {R}", 0x21: f"shar {R}", 0x24: f"rotcl {R}", 0x25: f"rotcr {R}",
               0x28: f"shll16 {R}", 0x29: f"shlr16 {R}",
               0x02: f"sts.l mach,@-{R}", 0x12: f"sts.l macl,@-{R}", 0x22: f"sts.l pr,@-{R}",
               0x52: f"sts.l fpul,@-{R}", 0x62: f"sts.l fpscr,@-{R}",
               0x06: f"lds.l @{R}+,mach", 0x16: f"lds.l @{R}+,macl", 0x26: f"lds.l @{R}+,pr",
               0x56: f"lds.l @{R}+,fpul", 0x66: f"lds.l @{R}+,fpscr",
               0x0A: f"lds {R},mach", 0x1A: f"lds {R},macl", 0x2A: f"lds {R},pr",
               0x5A: f"lds {R},fpul", 0x6A: f"lds {R},fpscr",
               0x03: f"stc.l sr,@-{R}", 0x13: f"stc.l gbr,@-{R}", 0x23: f"stc.l vbr,@-{R}",
               0x07: f"ldc.l @{R}+,sr", 0x17: f"ldc.l @{R}+,gbr", 0x27: f"ldc.l @{R}+,vbr",
               0x0E: f"ldc {R},sr", 0x1E: f"ldc {R},gbr", 0x2E: f"ldc {R},vbr",
               0x0B: f"jsr @{R}", 0x2B: f"jmp @{R}", 0x1B: f"tas.b @{R}"}
        key = w & 0xFF
        if key in one: return one[key], key in (0x0B, 0x2B)
        # NOTE: 0x4nmC/0x4nmD are SHAD/SHLD -- SH-2A/SH-3/SH-4 ONLY. The SH7058
        # is an SH-2E and cannot execute them. Decoding them turns literal pools
        # into plausible-looking code, so they are rejected here on purpose.
        if d4 == 0xF: return f"mac.w @{F}+,@{R}+", False
        return f".word 0x{w:04X}", False
    if op == 0x5: return f"mov.l @({d4*4},{F}),{R}", False
    if op == 0x6:
        return {0x0: f"mov.b @{F},{R}", 0x1: f"mov.w @{F},{R}", 0x2: f"mov.l @{F},{R}",
                0x3: f"mov {F},{R}", 0x4: f"mov.b @{F}+,{R}", 0x5: f"mov.w @{F}+,{R}",
                0x6: f"mov.l @{F}+,{R}", 0x7: f"not {F},{R}", 0x8: f"swap.b {F},{R}",
                0x9: f"swap.w {F},{R}", 0xA: f"negc {F},{R}", 0xB: f"neg {F},{R}",
                0xC: f"extu.b {F},{R}", 0xD: f"extu.w {F},{R}", 0xE: f"exts.b {F},{R}",
                0xF: f"exts.w {F},{R}"}.get(d4, f".word 0x{w:04X}"), False
    if op == 0x7: return f"add #{_s8(w)},{R}", False
    if op == 0x8:
        sub = (w >> 8) & 0xF
        disp = _s8(w)
        tgt = pc + 4 + disp * 2
        return {0x0: f"mov.b r0,@({d4},{F})", 0x1: f"mov.w r0,@({d4*2},{F})",
                0x4: f"mov.b @({d4},{F}),r0", 0x5: f"mov.w @({d4*2},{F}),r0",
                0x8: f"cmp/eq #{_s8(w)},r0",
                0x9: f"bt 0x{tgt:06X}", 0xB: f"bf 0x{tgt:06X}",
                0xD: f"bt/s 0x{tgt:06X}", 0xF: f"bf/s 0x{tgt:06X}"}.get(sub, f".word 0x{w:04X}"), False
    if op == 0x9:
        ea = (pc + 4 + d8 * 2) & ~1
        return f"mov.w @(0x{ea:06X}),{R}", False
    if op == 0xA: return f"bra 0x{(pc + 4 + _s12(w) * 2):06X}", True
    if op == 0xB: return f"bsr 0x{(pc + 4 + _s12(w) * 2):06X}", True
    if op == 0xC:
        sub = (w >> 8) & 0xF
        ea = ((pc + 4) & ~3) + d8 * 4
        return {0x0: f"mov.b r0,@({d8},gbr)", 0x1: f"mov.w r0,@({d8*2},gbr)",
                0x2: f"mov.l r0,@({d8*4},gbr)", 0x3: f"trapa #{d8}",
                0x4: f"mov.b @({d8},gbr),r0", 0x5: f"mov.w @({d8*2},gbr),r0",
                0x6: f"mov.l @({d8*4},gbr),r0", 0x7: f"mova @(0x{ea:06X}),r0",
                0x8: f"tst #{d8},r0", 0x9: f"and #{d8},r0", 0xA: f"xor #{d8},r0",
                0xB: f"or #{d8},r0", 0xC: f"tst.b #{d8},@(r0,gbr)",
                0xD: f"and.b #{d8},@(r0,gbr)", 0xE: f"xor.b #{d8},@(r0,gbr)",
                0xF: f"or.b #{d8},@(r0,gbr)"}.get(sub, f".word 0x{w:04X}"), False
    if op == 0xD:
        ea = ((pc + 4) & ~3) + d8 * 4
        return f"mov.l @(0x{ea:06X}),{R}", False
    if op == 0xE: return f"mov #{_s8(w)},{R}", False
    if op == 0xF:
        if d4 == 0xD:
            sub = m
            return {0x0: f"fsts fpul,{FRn}", 0x1: f"flds {FRn},fpul", 0x2: f"float fpul,{FRn}",
                    0x3: f"ftrc {FRn},fpul", 0x4: f"fneg {FRn}", 0x5: f"fabs {FRn}",
                    0x8: f"fldi0 {FRn}", 0x9: f"fldi1 {FRn}"}.get(sub, f".word 0x{w:04X} (INVALID-SH2E)"), False
        return {0x0: f"fadd {FRm},{FRn}", 0x1: f"fsub {FRm},{FRn}", 0x2: f"fmul {FRm},{FRn}",
                0x3: f"fdiv {FRm},{FRn}", 0x4: f"fcmp/eq {FRm},{FRn}", 0x5: f"fcmp/gt {FRm},{FRn}",
                0x6: f"fmov.s @(r0,{F}),{FRn}", 0x7: f"fmov.s {FRm},@(r0,{R})",
                0x8: f"fmov.s @{F},{FRn}", 0x9: f"fmov.s @{F}+,{FRn}",
                0xA: f"fmov.s {FRm},@{R}", 0xB: f"fmov.s {FRm},@-{R}",
                0xC: f"fmov {FRm},{FRn}", 0xE: f"fmac fr0,{FRm},{FRn}"}.get(d4, f".word 0x{w:04X} (INVALID-SH2E)"), False
    return f".word 0x{w:04X}", False


def disasm(data, start, end, base=0):
    out = []
    pc = start
    while pc < end:
        w = struct.unpack_from(">H", data, pc - base)[0]
        txt, delay = decode(w, pc)
        out.append((pc, w, txt, delay))
        pc += 2
    return out


def literal(data, addr, size=4, base=0):
    if size == 4:
        return struct.unpack_from(">I", data, addr - base)[0]
    return struct.unpack_from(">H", data, addr - base)[0]
