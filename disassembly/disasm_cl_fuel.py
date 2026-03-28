#!/usr/bin/env python3
"""Disassemble CL fuel target functions from Subaru ECU ROM (SH7058, SH-2A, Big-Endian)."""

import struct
import sys

ROM_PATH = r"C:\Users\Dean\Documents\GitHub\ae6l600l\rom\AE5L600L 20g rev 20.5 tiny wrex.bin"

with open(ROM_PATH, "rb") as f:
    ROM = f.read()

def read16(addr):
    return struct.unpack(">H", ROM[addr:addr+2])[0]

def read32(addr):
    return struct.unpack(">I", ROM[addr:addr+4])[0]

def read_float(addr):
    return struct.unpack(">f", ROM[addr:addr+4])[0]

def sign_extend_8(v):
    if v & 0x80:
        return v - 0x100
    return v

def sign_extend_12(v):
    if v & 0x800:
        return v - 0x1000
    return v

REG = lambda n: f"R{n}"
FREG = lambda n: f"FR{n}"

# Known RAM addresses
RAM_NAMES = {
    0xFFFF77DC: "CL_target_comp_A_output",
    0xFFFF77E0: "CL_target_comp_B_output",
    0xFFFF77D8: "CL_target_comp_output",  # guess
    0xFFFF77E4: "CL_target_comp_C_output",  # guess
    0xFFFF77E8: "CL_target_comp_D_output",  # guess
    0xFFFF6F80: "AFC_current",
    0xFFFF6F84: "AFC_correction",
    0xFFFF7028: "CL_fueling_base",
    0xFFFF702C: "CL_fueling_status",
}

def classify_addr(val):
    if val >= 0xFFFF0000:
        name = RAM_NAMES.get(val, "")
        extra = f"  ; RAM {name}" if name else f"  ; RAM 0x{val:08X}"
        return "RAM", extra
    elif val < len(ROM):
        try:
            fval = read_float(val)
            if abs(fval) < 1e10 and abs(fval) > 1e-10 or fval == 0.0:
                return "CAL", f"  ; ROM 0x{val:08X} = {fval:.6f} (float)"
            else:
                return "ROM", f"  ; ROM 0x{val:08X} = 0x{read32(val):08X}"
        except:
            return "ROM", f"  ; ROM 0x{val:08X}"
    else:
        return "CONST", f"  ; const 0x{val:08X}"

def disasm_one(pc):
    """Disassemble one instruction at pc. Returns (mnemonic, size, annotation, is_rts, literal_info)."""
    op = read16(pc)
    ann = ""
    lit_info = None  # (pool_addr, value)

    # NOP
    if op == 0x0009:
        return "nop", 2, "", False, None
    # RTS
    if op == 0x000B:
        return "rts", 2, "", True, None
    # CLRT
    if op == 0x0008:
        return "clrt", 2, "", False, None
    # SETT
    if op == 0x0018:
        return "sett", 2, "", False, None

    nib0 = (op >> 12) & 0xF
    nib1 = (op >> 8) & 0xF
    nib2 = (op >> 4) & 0xF
    nib3 = op & 0xF
    n = nib1
    m = nib2
    d8 = op & 0xFF
    d4 = op & 0xF
    d12 = op & 0xFFF

    # 0xEnDD = mov #imm8,Rn
    if nib0 == 0xE:
        imm = sign_extend_8(d8)
        return f"mov #{imm},{REG(n)}", 2, f"  ; 0x{imm & 0xFF:02X}", False, None

    # 0x7nDD = add #imm8,Rn
    if nib0 == 0x7:
        imm = sign_extend_8(d8)
        return f"add #{imm},{REG(n)}", 2, "", False, None

    # 0x6nm3 = mov Rm,Rn
    if nib0 == 0x6 and nib3 == 0x3:
        return f"mov {REG(m)},{REG(n)}", 2, "", False, None

    # 0x6nm0 = mov.b @Rm,Rn
    if nib0 == 0x6 and nib3 == 0x0:
        return f"mov.b @{REG(m)},{REG(n)}", 2, "", False, None

    # 0x6nm1 = mov.w @Rm,Rn
    if nib0 == 0x6 and nib3 == 0x1:
        return f"mov.w @{REG(m)},{REG(n)}", 2, "", False, None

    # 0x6nm2 = mov.l @Rm,Rn
    if nib0 == 0x6 and nib3 == 0x2:
        return f"mov.l @{REG(m)},{REG(n)}", 2, "", False, None

    # 0x6nmC = extu.b Rm,Rn
    if nib0 == 0x6 and nib3 == 0xC:
        return f"extu.b {REG(m)},{REG(n)}", 2, "", False, None

    # 0x6nmD = extu.w Rm,Rn
    if nib0 == 0x6 and nib3 == 0xD:
        return f"extu.w {REG(m)},{REG(n)}", 2, "", False, None

    # 0x6nm6 = mov.l @Rm+,Rn
    if nib0 == 0x6 and nib3 == 0x6:
        return f"mov.l @{REG(m)}+,{REG(n)}", 2, "", False, None

    # 0x2nm0 = mov.b Rm,@Rn
    if nib0 == 0x2 and nib3 == 0x0:
        return f"mov.b {REG(m)},@{REG(n)}", 2, "", False, None

    # 0x2nm1 = mov.w Rm,@Rn
    if nib0 == 0x2 and nib3 == 0x1:
        return f"mov.w {REG(m)},@{REG(n)}", 2, "", False, None

    # 0x2nm2 = mov.l Rm,@Rn
    if nib0 == 0x2 and nib3 == 0x2:
        return f"mov.l {REG(m)},@{REG(n)}", 2, "", False, None

    # 0x2nm6 = mov.l Rm,@-Rn
    if nib0 == 0x2 and nib3 == 0x6:
        return f"mov.l {REG(m)},@-{REG(n)}", 2, "", False, None

    # 0x2nm8 = tst Rm,Rn
    if nib0 == 0x2 and nib3 == 0x8:
        return f"tst {REG(m)},{REG(n)}", 2, "", False, None

    # 0x80nD = mov.b R0,@(disp,Rn)
    if nib0 == 0x8 and nib1 == 0x0:
        return f"mov.b R0,@({d4},{REG(nib2)})", 2, "", False, None

    # 0x84nD = mov.b @(disp,Rn),R0
    if nib0 == 0x8 and nib1 == 0x4:
        return f"mov.b @({d4},{REG(nib2)}),R0", 2, "", False, None

    # 0x1nmD = mov.l Rm,@(disp*4,Rn)
    if nib0 == 0x1:
        disp = d4 * 4
        return f"mov.l {REG(m)},@({disp},{REG(n)})", 2, "", False, None

    # 0x5nmD = mov.l @(disp*4,Rm),Rn
    if nib0 == 0x5:
        disp = d4 * 4
        return f"mov.l @({disp},{REG(m)}),{REG(n)}", 2, "", False, None

    # 0x9nDD = mov.w @(disp*2+PC+4),Rn
    if nib0 == 0x9:
        disp = d8
        pool_addr = disp * 2 + pc + 4
        val = read16(pool_addr)
        ann = f"  ; @0x{pool_addr:05X} = 0x{val:04X} ({val})"
        return f"mov.w @(0x{disp*2:X},PC),{REG(n)}", 2, ann, False, None

    # 0xDnDD = mov.l @(disp*4+(PC&~3)+4),Rn
    if nib0 == 0xD:
        disp = d8
        pool_addr = disp * 4 + (pc & ~3) + 4
        val = read32(pool_addr)
        kind, extra = classify_addr(val)
        ann = f"  ; @0x{pool_addr:05X} -> 0x{val:08X}{extra}"
        lit_info = (pool_addr, val)
        return f"mov.l @(0x{disp*4:X},PC),{REG(n)}", 2, ann, False, lit_info

    # GBR instructions
    if nib0 == 0xC:
        if nib1 == 0x0:
            return f"mov.b R0,@({d8},GBR)", 2, "", False, None
        if nib1 == 0x1:
            return f"mov.w R0,@({d8*2},GBR)", 2, "", False, None
        if nib1 == 0x4:
            return f"mov.b @({d8},GBR),R0", 2, "", False, None
        if nib1 == 0x5:
            return f"mov.w @({d8*2},GBR),R0", 2, "", False, None
        if nib1 == 0x8:
            return f"tst #{d8},R0", 2, f"  ; tst #0x{d8:02X},R0", False, None

    # BRA
    if nib0 == 0xA:
        offset = sign_extend_12(d12) * 2 + pc + 4
        return f"bra 0x{offset:05X}", 2, f"  ; -> 0x{offset:05X}", False, None

    # BSR
    if nib0 == 0xB:
        offset = sign_extend_12(d12) * 2 + pc + 4
        return f"bsr 0x{offset:05X}", 2, f"  ; -> 0x{offset:05X}", False, None

    # BT
    if op & 0xFF00 == 0x8900:
        offset = sign_extend_8(d8) * 2 + pc + 4
        return f"bt 0x{offset:05X}", 2, f"  ; -> 0x{offset:05X}", False, None

    # BF
    if op & 0xFF00 == 0x8B00:
        offset = sign_extend_8(d8) * 2 + pc + 4
        return f"bf 0x{offset:05X}", 2, f"  ; -> 0x{offset:05X}", False, None

    # BT/S
    if op & 0xFF00 == 0x8D00:
        offset = sign_extend_8(d8) * 2 + pc + 4
        return f"bt/s 0x{offset:05X}", 2, f"  ; -> 0x{offset:05X}", False, None

    # BF/S
    if op & 0xFF00 == 0x8F00:
        offset = sign_extend_8(d8) * 2 + pc + 4
        return f"bf/s 0x{offset:05X}", 2, f"  ; -> 0x{offset:05X}", False, None

    # CMP/EQ #imm,R0
    if op & 0xFF00 == 0x8800:
        imm = sign_extend_8(d8)
        return f"cmp/eq #{imm},R0", 2, "", False, None

    # 3nmX comparisons
    if nib0 == 0x3:
        if nib3 == 0x0:
            return f"cmp/eq {REG(m)},{REG(n)}", 2, "", False, None
        if nib3 == 0x2:
            return f"cmp/hs {REG(m)},{REG(n)}", 2, "  ; unsigned >=", False, None
        if nib3 == 0x3:
            return f"cmp/ge {REG(m)},{REG(n)}", 2, "  ; signed >=", False, None
        if nib3 == 0x6:
            return f"cmp/hi {REG(m)},{REG(n)}", 2, "  ; unsigned >", False, None
        if nib3 == 0x7:
            return f"cmp/gt {REG(m)},{REG(n)}", 2, "  ; signed >", False, None
        if nib3 == 0xC:
            return f"add {REG(m)},{REG(n)}", 2, "", False, None

    # 4n0B = jsr @Rn
    if nib0 == 0x4 and nib2 == 0x0 and nib3 == 0xB:
        return f"jsr @{REG(n)}", 2, "", False, None

    # 4n2B = jmp @Rn
    if nib0 == 0x4 and nib2 == 0x2 and nib3 == 0xB:
        return f"jmp @{REG(n)}", 2, "", False, None

    # 4n22 = sts.l PR,@-Rn
    if nib0 == 0x4 and nib2 == 0x2 and nib3 == 0x2:
        return f"sts.l PR,@-{REG(n)}", 2, "", False, None

    # 4n26 = lds.l @Rn+,PR
    if nib0 == 0x4 and nib2 == 0x2 and nib3 == 0x6:
        return f"lds.l @{REG(n)}+,PR", 2, "", False, None

    # 4n1E = ldc Rn,GBR
    if nib0 == 0x4 and nib2 == 0x1 and nib3 == 0xE:
        return f"ldc {REG(n)},GBR", 2, "", False, None

    # 0n02 = stc SR/GBR/VBR,Rn
    if nib0 == 0x0 and nib2 == 0x0 and nib3 == 0x2:
        srcs = {0: "SR", 1: "GBR", 2: "VBR"}
        src = srcs.get(m, f"CR{m}")
        return f"stc {src},{REG(n)}", 2, "", False, None

    # 0n0A = sts MACH/MACL/PR,Rn
    if nib0 == 0x0 and nib2 == 0x0 and nib3 == 0xA:
        srcs = {0: "MACH", 1: "MACL", 2: "PR"}
        src = srcs.get(m, f"SR{m}")
        return f"sts {src},{REG(n)}", 2, "", False, None

    # FPU instructions
    if nib0 == 0xF:
        fn = nib1
        fm = nib2
        sub = nib3
        if sub == 0x0:
            return f"fadd {FREG(fm)},{FREG(fn)}", 2, "", False, None
        if sub == 0x1:
            return f"fsub {FREG(fm)},{FREG(fn)}", 2, "", False, None
        if sub == 0x2:
            return f"fmul {FREG(fm)},{FREG(fn)}", 2, "", False, None
        if sub == 0x4:
            return f"fcmp/eq {FREG(fm)},{FREG(fn)}", 2, "", False, None
        if sub == 0x5:
            return f"fcmp/gt {FREG(fm)},{FREG(fn)}", 2, "", False, None
        if sub == 0x6:
            return f"fmov.s @(R0,{REG(fm)}),{FREG(fn)}", 2, "", False, None
        if sub == 0x7:
            return f"fmov.s {FREG(fm)},@(R0,{REG(fn)})", 2, "", False, None
        if sub == 0x8:
            return f"fmov.s @{REG(fm)},{FREG(fn)}", 2, "", False, None
        if sub == 0x9:
            return f"fmov.s @{REG(fm)}+,{FREG(fn)}", 2, "", False, None
        if sub == 0xA:
            return f"fmov.s {FREG(fm)},@{REG(fn)}", 2, "", False, None
        if sub == 0xB:
            return f"fmov.s {FREG(fm)},@-{REG(fn)}", 2, "", False, None
        if sub == 0xC:
            return f"fmov {FREG(fm)},{FREG(fn)}", 2, "", False, None
        if sub == 0xD:
            if fm == 0x8:
                return f"fldi0 {FREG(fn)}", 2, "", False, None
            if fm == 0x9:
                return f"fldi1 {FREG(fn)}", 2, "", False, None
            if fm == 0x4:
                return f"fneg {FREG(fn)}", 2, "", False, None
            # float/fpscr/fpul transfers
            if fm == 0x0:
                return f"fsts FPUL,{FREG(fn)}", 2, "", False, None
            if fm == 0x2:
                return f"float FPUL,{FREG(fn)}", 2, "", False, None
            if fm == 0x3:
                return f"ftrc {FREG(fn)},FPUL", 2, "", False, None
            if fm == 0x1:
                return f"flds {FREG(fn)},FPUL", 2, "", False, None
            if fm == 0x5:
                return f"fcnvsd FPUL,{FREG(fn)}", 2, "", False, None
            if fm == 0x6:
                return f"fcnvds {FREG(fn)},FPUL", 2, "", False, None
            if fm == 0xA:
                return f"sts FPSCR,{REG(fn)}", 2, "", False, None
        if sub == 0xE:
            return f"fmac FR0,{FREG(fm)},{FREG(fn)}", 2, "", False, None

    # More 0x4xxx group
    if nib0 == 0x4:
        # 4n10 = dt Rn
        if nib2 == 0x1 and nib3 == 0x0:
            return f"dt {REG(n)}", 2, "", False, None
        # 4n11 = cmp/pz Rn
        if nib2 == 0x1 and nib3 == 0x1:
            return f"cmp/pz {REG(n)}", 2, "  ; Rn >= 0", False, None
        # 4n15 = cmp/pl Rn
        if nib2 == 0x1 and nib3 == 0x5:
            return f"cmp/pl {REG(n)}", 2, "  ; Rn > 0", False, None
        # 4n00 = shll Rn
        if nib2 == 0x0 and nib3 == 0x0:
            return f"shll {REG(n)}", 2, "", False, None
        # 4n01 = shlr Rn
        if nib2 == 0x0 and nib3 == 0x1:
            return f"shlr {REG(n)}", 2, "", False, None
        # 4n04 = rotl Rn
        if nib2 == 0x0 and nib3 == 0x4:
            return f"rotl {REG(n)}", 2, "", False, None
        # 4n05 = rotr Rn
        if nib2 == 0x0 and nib3 == 0x5:
            return f"rotr {REG(n)}", 2, "", False, None
        # 4n08 = shll2 Rn
        if nib2 == 0x0 and nib3 == 0x8:
            return f"shll2 {REG(n)}", 2, "", False, None
        # 4n09 = shlr2 Rn
        if nib2 == 0x0 and nib3 == 0x9:
            return f"shlr2 {REG(n)}", 2, "", False, None
        # 4n18 = shll8 Rn
        if nib2 == 0x1 and nib3 == 0x8:
            return f"shll8 {REG(n)}", 2, "", False, None
        # 4n19 = shlr8 Rn
        if nib2 == 0x1 and nib3 == 0x9:
            return f"shlr8 {REG(n)}", 2, "", False, None
        # 4n28 = shll16 Rn
        if nib2 == 0x2 and nib3 == 0x8:
            return f"shll16 {REG(n)}", 2, "", False, None
        # 4n29 = shlr16 Rn
        if nib2 == 0x2 and nib3 == 0x9:
            return f"shlr16 {REG(n)}", 2, "", False, None
        # 4n0E = ldc Rn,SR
        if nib2 == 0x0 and nib3 == 0xE:
            return f"ldc {REG(n)},SR", 2, "", False, None
        # 4n17 = lds.l @Rn+,MACL (or PR with 0x26)
        # 4n07 = lds.l @Rn+,MACH
        # 4n5A = lds Rn,FPSCR
        if nib2 == 0x5 and nib3 == 0xA:
            return f"lds {REG(n)},FPSCR", 2, "", False, None
        # 4n6A = lds Rn,FPUL
        if nib2 == 0x6 and nib3 == 0xA:
            return f"lds {REG(n)},FPUL", 2, "", False, None
        # 4n2A = lds Rn,PR
        if nib2 == 0x2 and nib3 == 0xA:
            return f"lds {REG(n)},PR", 2, "", False, None
        # 4n5A - sts FPUL,Rn
        if nib2 == 0x5 and nib3 == 0xA:
            return f"lds {REG(n)},FPSCR", 2, "", False, None

    # 0x0nmC = mov.b @(R0,Rm),Rn
    if nib0 == 0x0 and nib3 == 0xC:
        return f"mov.b @(R0,{REG(m)}),{REG(n)}", 2, "", False, None

    # 0x0nmD = mov.w @(R0,Rm),Rn
    if nib0 == 0x0 and nib3 == 0xD:
        return f"mov.w @(R0,{REG(m)}),{REG(n)}", 2, "", False, None

    # 0x0nmE = mov.l @(R0,Rm),Rn
    if nib0 == 0x0 and nib3 == 0xE:
        return f"mov.l @(R0,{REG(m)}),{REG(n)}", 2, "", False, None

    # 3nm4 = div1 Rm,Rn
    if nib0 == 0x3 and nib3 == 0x4:
        return f"div1 {REG(m)},{REG(n)}", 2, "", False, None

    # 2nmD = xtrct Rm,Rn
    if nib0 == 0x2 and nib3 == 0xD:
        return f"xtrct {REG(m)},{REG(n)}", 2, "", False, None

    # 2nmE = mulu.w Rm,Rn
    if nib0 == 0x2 and nib3 == 0xE:
        return f"mulu.w {REG(m)},{REG(n)}", 2, "", False, None

    # 2nmF = muls.w Rm,Rn
    if nib0 == 0x2 and nib3 == 0xF:
        return f"muls.w {REG(m)},{REG(n)}", 2, "", False, None

    # 0nm7 = mul.l Rm,Rn
    if nib0 == 0x0 and nib3 == 0x7:
        return f"mul.l {REG(m)},{REG(n)}", 2, "", False, None

    # 2nm9 = and Rm,Rn
    if nib0 == 0x2 and nib3 == 0x9:
        return f"and {REG(m)},{REG(n)}", 2, "", False, None

    # 2nmA = xor Rm,Rn
    if nib0 == 0x2 and nib3 == 0xA:
        return f"xor {REG(m)},{REG(n)}", 2, "", False, None

    # 2nmB = or Rm,Rn
    if nib0 == 0x2 and nib3 == 0xB:
        return f"or {REG(m)},{REG(n)}", 2, "", False, None

    # 3nm8 = sub Rm,Rn
    if nib0 == 0x3 and nib3 == 0x8:
        return f"sub {REG(m)},{REG(n)}", 2, "", False, None

    # C9xx = and #imm,R0
    if nib0 == 0xC and nib1 == 0x9:
        return f"and #{d8},R0", 2, f"  ; 0x{d8:02X}", False, None

    # CBxx = or #imm,R0
    if nib0 == 0xC and nib1 == 0xB:
        return f"or #{d8},R0", 2, f"  ; 0x{d8:02X}", False, None

    # 3nmE = addc Rm,Rn
    if nib0 == 0x3 and nib3 == 0xE:
        return f"addc {REG(m)},{REG(n)}", 2, "", False, None

    # 3nmA = subc Rm,Rn
    if nib0 == 0x3 and nib3 == 0xA:
        return f"subc {REG(m)},{REG(n)}", 2, "", False, None

    # 4n24 = rotcl Rn
    if nib0 == 0x4 and nib2 == 0x2 and nib3 == 0x4:
        return f"rotcl {REG(n)}", 2, "", False, None

    # 3nm5 = dmulu.l Rm,Rn
    if nib0 == 0x3 and nib3 == 0x5:
        return f"dmulu.l {REG(m)},{REG(n)}", 2, "", False, None

    # 3nmD = dmuls.l Rm,Rn
    if nib0 == 0x3 and nib3 == 0xD:
        return f"dmuls.l {REG(m)},{REG(n)}", 2, "", False, None

    # 2nm4 = mov.b Rm,@-Rn
    if nib0 == 0x2 and nib3 == 0x4:
        return f"mov.b {REG(m)},@-{REG(n)}", 2, "", False, None

    # 2nm5 = mov.w Rm,@-Rn
    if nib0 == 0x2 and nib3 == 0x5:
        return f"mov.w {REG(m)},@-{REG(n)}", 2, "", False, None

    # 6nm4 = mov.b @Rm+,Rn
    if nib0 == 0x6 and nib3 == 0x4:
        return f"mov.b @{REG(m)}+,{REG(n)}", 2, "", False, None

    # 6nm5 = mov.w @Rm+,Rn
    if nib0 == 0x6 and nib3 == 0x5:
        return f"mov.w @{REG(m)}+,{REG(n)}", 2, "", False, None

    # 81nD = mov.w R0,@(disp*2,Rn)
    if nib0 == 0x8 and nib1 == 0x1:
        disp = d4 * 2
        return f"mov.w R0,@({disp},{REG(nib2)})", 2, "", False, None

    # 85nD = mov.w @(disp*2,Rm),R0
    if nib0 == 0x8 and nib1 == 0x5:
        disp = d4 * 2
        return f"mov.w @({disp},{REG(nib2)}),R0", 2, "", False, None

    # 4nFA = sts FPUL,Rn -- actually 0x005A pattern
    if nib0 == 0x0 and nib2 == 0x5 and nib3 == 0xA:
        return f"sts FPUL,{REG(n)}", 2, "", False, None

    # 3nm1 = cmp/hs unsigned ... wait already covered

    # negc
    if nib0 == 0x6 and nib3 == 0xA:
        return f"negc {REG(m)},{REG(n)}", 2, "", False, None

    # neg
    if nib0 == 0x6 and nib3 == 0xB:
        return f"neg {REG(m)},{REG(n)}", 2, "", False, None

    # swap.b
    if nib0 == 0x6 and nib3 == 0x8:
        return f"swap.b {REG(m)},{REG(n)}", 2, "", False, None

    # swap.w
    if nib0 == 0x6 and nib3 == 0x9:
        return f"swap.w {REG(m)},{REG(n)}", 2, "", False, None

    # exts.b
    if nib0 == 0x6 and nib3 == 0xE:
        return f"exts.b {REG(m)},{REG(n)}", 2, "", False, None

    # exts.w
    if nib0 == 0x6 and nib3 == 0xF:
        return f"exts.w {REG(m)},{REG(n)}", 2, "", False, None

    # not
    if nib0 == 0x6 and nib3 == 0x7:
        return f"not {REG(m)},{REG(n)}", 2, "", False, None

    return f".word 0x{op:04X}", 2, "  ; UNKNOWN", False, None


def disasm_function(start_addr, name, max_instr=500):
    """Disassemble a function from start_addr until RTS + delay slot."""
    print(f"\n{'='*80}")
    print(f"  FUNCTION: {name}")
    print(f"  Start: 0x{start_addr:05X}")
    print(f"{'='*80}\n")

    pc = start_addr
    instructions = []
    literals = {}  # pool_addr -> value
    ram_reads = set()
    ram_writes = set()
    cal_refs = {}  # addr -> float value
    found_rts = False
    delay_slot_next = False

    for i in range(max_instr):
        mnem, size, ann, is_rts, lit_info = disasm_one(pc)

        op = read16(pc)
        line = f"  0x{pc:05X}:  {op:04X}    {mnem}{ann}"
        instructions.append(line)
        print(line)

        if lit_info:
            pool_addr, val = lit_info
            literals[pool_addr] = val
            if val >= 0xFFFF0000:
                # Track as RAM - we don't know read/write from just the load,
                # but we note it
                pass
            elif val < len(ROM):
                try:
                    fval = read_float(val)
                    if (abs(fval) < 1e10 and abs(fval) > 1e-10) or fval == 0.0:
                        cal_refs[val] = fval
                except:
                    pass

        if delay_slot_next:
            # We just processed the delay slot after RTS
            break

        if is_rts:
            delay_slot_next = True

        pc += size

    # Now do a second pass to track RAM read/write patterns
    # We look for mov.l @(disp,PC),Rn loading a RAM addr, then subsequent use
    print(f"\n--- Literal Pool ---")
    for addr in sorted(literals.keys()):
        val = literals[addr]
        kind, extra = classify_addr(val)
        print(f"  @0x{addr:05X}: 0x{val:08X}  [{kind}]{extra}")

    # Collect all RAM addresses from literals
    ram_addrs = set()
    for val in literals.values():
        if val >= 0xFFFF0000:
            ram_addrs.add(val)
            name_str = RAM_NAMES.get(val, f"0x{val:08X}")

    print(f"\n--- RAM Addresses Referenced ---")
    for addr in sorted(ram_addrs):
        name_str = RAM_NAMES.get(addr, "")
        print(f"  0x{addr:08X}  {name_str}")

    print(f"\n--- Calibration (ROM) Values Referenced ---")
    for addr in sorted(cal_refs.keys()):
        fval = cal_refs[addr]
        raw = read32(addr)
        print(f"  ROM 0x{addr:05X}: float = {fval:.6f}  (raw 0x{raw:08X})")

    print()
    return instructions, literals, ram_addrs, cal_refs


# ============================================================
# MAIN
# ============================================================

print("=" * 80)
print("  SH-2A ROM Disassembly: CL Fuel Target Functions")
print("  ROM:", ROM_PATH)
print("  ROM size:", len(ROM), "bytes")
print("=" * 80)

# 1) cl_fuel_target_A at 0x33CC0
instr_a, lit_a, ram_a, cal_a = disasm_function(0x33CC0, "cl_fuel_target_A (writes FFFF77DC)")

# 2) Dispatcher at 0x33304
instr_d, lit_d, ram_d, cal_d = disasm_function(0x33304, "CL fueling dispatcher (master controller)")

# 3) cl_fuel_target_B at 0x33D1C
instr_b, lit_b, ram_b, cal_b = disasm_function(0x33D1C, "cl_fuel_target_B (writes FFFF77E0)")

# ============================================================
# PSEUDOCODE ANALYSIS
# ============================================================
print("\n" + "=" * 80)
print("  PSEUDOCODE / ANALYSIS SUMMARY")
print("=" * 80)

print("""
NOTE: Detailed pseudocode requires tracing register usage through the
disassembly. The raw disassembly above provides the complete instruction
listing. Key observations will be noted based on the literal pool references
and instruction patterns.
""")

# For each function, print a summary based on what we found
for name, literals, ram_addrs, cal_refs in [
    ("cl_fuel_target_A", lit_a, ram_a, cal_a),
    ("CL fueling dispatcher", lit_d, ram_d, cal_d),
    ("cl_fuel_target_B", lit_b, ram_b, cal_b),
]:
    print(f"\n--- {name} ---")
    print(f"  RAM addresses: {len(ram_addrs)}")
    for a in sorted(ram_addrs):
        print(f"    0x{a:08X}  {RAM_NAMES.get(a, '')}")
    print(f"  CAL float references: {len(cal_refs)}")
    for a in sorted(cal_refs.keys()):
        print(f"    ROM 0x{a:05X} = {cal_refs[a]:.6f}")
    # Count BSR calls
    print()
