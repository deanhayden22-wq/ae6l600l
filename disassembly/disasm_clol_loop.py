#!/usr/bin/env python3
"""Disassemble CL/OL decay loop to find where FFFF79A0 is read and used."""
import struct

ROM_PATH = 'C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin'
with open(ROM_PATH, 'rb') as f:
    rom = f.read()

ROM_SIZE = len(rom)

def read_u16(a): return struct.unpack('>H', rom[a:a+2])[0]
def read_u32(a): return struct.unpack('>I', rom[a:a+4])[0]
def read_float(a): return struct.unpack('>f', rom[a:a+4])[0]

def disasm_one(addr):
    op = read_u16(addr)
    top = (op >> 12) & 0xF
    n = (op >> 8) & 0xF
    m = (op >> 4) & 0xF
    d8 = op & 0xFF
    d4 = op & 0xF
    d12 = op & 0xFFF
    imm8 = d8 if d8 < 128 else d8 - 256

    if op == 0x000B: return "rts"
    if op == 0x0009: return "nop"
    if op == 0x0008: return "clrt"
    if op == 0x0018: return "sett"
    if op == 0x001B: return "sleep"
    if op == 0x0028: return "clrmac"
    if op == 0x0019: return "div0u"

    if top == 0xF:
        sub = d4
        fn = n; fm = m
        if sub == 0x0: return "fadd FR%d,FR%d" % (fm, fn)
        if sub == 0x1: return "fsub FR%d,FR%d" % (fm, fn)
        if sub == 0x2: return "fmul FR%d,FR%d" % (fm, fn)
        if sub == 0x3: return "fdiv FR%d,FR%d" % (fm, fn)
        if sub == 0x4: return "fcmp/eq FR%d,FR%d" % (fm, fn)
        if sub == 0x5: return "fcmp/gt FR%d,FR%d" % (fm, fn)
        if sub == 0x6: return "fmov.s @(R0,R%d),FR%d" % (m, fn)
        if sub == 0x7: return "fmov.s FR%d,@(R0,R%d)" % (fn, m)
        if sub == 0x8: return "fmov.s @R%d,FR%d" % (fm, fn)
        if sub == 0x9: return "fmov.s @R%d+,FR%d" % (fm, fn)
        if sub == 0xA: return "fmov.s FR%d,@R%d" % (fn, fm)
        if sub == 0xB: return "fmov.s FR%d,@-R%d" % (fn, fm)
        if sub == 0xC: return "fmov FR%d,FR%d" % (fm, fn)
        if sub == 0xE: return "fmac FR0,FR%d,FR%d" % (fm, fn)
        if sub == 0xD:
            if fm == 0: return "fsts FPUL,FR%d" % fn
            if fm == 1: return "flds FR%d,FPUL" % fn
            if fm == 2: return "float FPUL,FR%d" % fn
            if fm == 3: return "ftrc FR%d,FPUL" % fn
            if fm == 4: return "fneg FR%d" % fn
            if fm == 5: return "fabs FR%d" % fn
            if fm == 6: return "fsqrt FR%d" % fn
            if fm == 8: return "fldi0 FR%d" % fn
            if fm == 9: return "fldi1 FR%d" % fn
            if fm == 0xA: return "lds R%d,FPUL" % fn
        return ".word 0x%04X (Fxxx)" % op

    if top == 0xD:
        pdisp = d8 * 4
        ppool = ((addr + 4) & ~3) + pdisp
        if ppool + 3 < len(rom):
            pval = read_u32(ppool)
            if 0xFFFF0000 <= pval:
                return "mov.l @(0x%X,PC),R%d  ; pool@0x%05X=0x%08X (RAM)" % (d8, n, ppool, pval)
            elif 0x00050000 <= pval <= 0x000FFFFF:
                return "mov.l @(0x%X,PC),R%d  ; pool@0x%05X=0x%08X (ROM)" % (d8, n, ppool, pval)
            else:
                fv = read_float(ppool)
                return "mov.l @(0x%X,PC),R%d  ; pool@0x%05X=0x%08X (%.6g)" % (d8, n, ppool, pval, fv)
        return "mov.l @(0x%X,PC),R%d" % (d8, n)

    if top == 0xC:
        sub = n
        if sub == 0x7: return "mova @(0x%X,PC),R0  =0x%05X" % (d8, ((addr+4)&~3)+d8*4)
        if sub == 0x4: return "mov.b @(0x%X,GBR),R0" % d8
        if sub == 0x5: return "mov.w @(0x%X,GBR),R0" % d8
        if sub == 0x6: return "mov.l @(0x%X,GBR),R0" % d8
        if sub == 0x0: return "mov.b R0,@(0x%X,GBR)" % d8
        if sub == 0x1: return "mov.w R0,@(0x%X,GBR)" % d8
        if sub == 0x2: return "mov.l R0,@(0x%X,GBR)" % d8
        if sub == 0x8: return "tst #%d,R0" % d8
        if sub == 0x9: return "and #%d,R0" % d8
        if sub == 0xA: return "xor #%d,R0" % d8
        if sub == 0xB: return "or #%d,R0" % d8
        return ".word 0x%04X (Cxxx)" % op

    if top == 0xE: return "mov #%d,R%d" % (imm8, n)

    if top == 0x9:
        pdisp = d8 * 2
        paddr = addr + 4 + pdisp
        if paddr + 1 < len(rom):
            pval = read_u16(paddr)
            return "mov.w @(0x%X,PC),R%d  ; @0x%05X=0x%04X" % (d8, n, paddr, pval)
        return "mov.w @(0x%X,PC),R%d" % (d8, n)

    if top == 0x7: return "add #%d,R%d" % (imm8, n)

    if top == 0x6:
        sub = d4
        if sub == 3: return "mov R%d,R%d" % (m, n)
        if sub == 2: return "mov.l @R%d,R%d" % (m, n)
        if sub == 6: return "mov.l @R%d+,R%d" % (m, n)
        if sub == 5: return "mov.w @R%d+,R%d" % (m, n)
        if sub == 4: return "mov.b @R%d+,R%d" % (m, n)
        if sub == 1: return "mov.w @R%d,R%d" % (m, n)
        if sub == 0: return "mov.b @R%d,R%d" % (m, n)
        if sub == 0xC: return "extu.b R%d,R%d" % (m, n)
        if sub == 0xD: return "extu.w R%d,R%d" % (m, n)
        if sub == 0xE: return "exts.b R%d,R%d" % (m, n)
        if sub == 0xF: return "exts.w R%d,R%d" % (m, n)
        if sub == 0x8: return "swap.b R%d,R%d" % (m, n)
        if sub == 0x9: return "swap.w R%d" % n
        return ".word 0x%04X (6xxx)" % op

    if top == 0x5:
        disp = d4 * 4
        return "mov.l @(%d,R%d),R%d" % (disp, m, n)

    if top == 0x4:
        low8 = op & 0xFF
        if low8 == 0x08: return "shll2 R%d" % n
        if low8 == 0x18: return "shll8 R%d" % n
        if low8 == 0x28: return "shll16 R%d" % n
        if low8 == 0x00: return "shll R%d" % n
        if low8 == 0x01: return "shlr R%d" % n
        if low8 == 0x09: return "shlr2 R%d" % n
        if low8 == 0x19: return "shlr8 R%d" % n
        if low8 == 0x29: return "shlr16 R%d" % n
        if low8 == 0x0B: return "jsr @R%d" % n
        if low8 == 0x2B: return "jmp @R%d" % n
        if low8 == 0x2A: return "lds R%d,PR" % n
        if low8 == 0x0A: return "lds R%d,MACH" % n
        if low8 == 0x1A: return "lds R%d,MACL" % n
        if low8 == 0x1B: return "tas.b @R%d" % n
        if low8 == 0x0E: return "ldc R%d,SR" % n
        if low8 == 0x1E: return "ldc R%d,GBR" % n
        if low8 == 0x2E: return "ldc R%d,VBR" % n
        if low8 == 0x0F: return "mac.w @R%d" % n
        if low8 == 0x02: return "sts.l PR,@-R%d" % n
        if low8 == 0x12: return "sts.l MACH,@-R%d" % n
        if low8 == 0x22: return "sts.l MACL,@-R%d" % n
        if low8 == 0x03: return "stc.l SR,@-R%d" % n
        if low8 == 0x13: return "stc.l GBR,@-R%d" % n
        if low8 == 0x26: return "lds.l @R%d+,PR" % n
        if low8 == 0x16: return "lds.l @R%d+,MACH" % n
        return ".word 0x%04X (4xxx)" % op

    if top == 0x3:
        sub = d4
        ops3 = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",6:"cmp/hi",7:"cmp/gt",
                8:"sub",0xC:"add",0xA:"subc",0xE:"addc",4:"div1",5:"dmulu.l"}
        return "%s R%d,R%d" % (ops3.get(sub, ".word 0x%04X"%op), m, n)

    if top == 0x2:
        sub = d4
        if sub == 8: return "tst R%d,R%d" % (m, n)
        if sub == 2: return "mov.l R%d,@R%d" % (m, n)
        if sub == 1: return "mov.w R%d,@R%d" % (m, n)
        if sub == 0: return "mov.b R%d,@R%d" % (m, n)
        if sub == 6: return "mov.l R%d,@(R0,R%d)" % (m, n)
        if sub == 5: return "mov.w R%d,@(R0,R%d)" % (m, n)
        if sub == 4: return "mov.b R%d,@(R0,R%d)" % (m, n)
        if sub == 9: return "and R%d,R%d" % (m, n)
        if sub == 0xA: return "xor R%d,R%d" % (m, n)
        if sub == 0xB: return "or R%d,R%d" % (m, n)
        if sub == 0xD: return "xtrct R%d,R%d" % (m, n)
        return ".word 0x%04X (2xxx)" % op

    if top == 0x1:
        disp = d4 * 4
        return "mov.l R%d,@(%d,R%d)" % (n, disp, m)

    if top == 0x0:
        sub = d4
        if sub == 0xA and m == 2: return "sts PR,R%d" % n
        if sub == 0xA and m == 0: return "sts MACH,R%d" % n
        if sub == 0xA and m == 1: return "sts MACL,R%d" % n
        if sub == 0x3 and n == 0: return "bsrf R%d" % m
        if sub == 0xC: return "mov.b @(R0,R%d),R%d" % (m, n)
        if sub == 0xD: return "mov.w @(R0,R%d),R%d" % (m, n)
        if sub == 0xE: return "mov.l @(R0,R%d),R%d" % (m, n)
        if sub == 0x4: return "mov.b R%d,@(R0,R%d)" % (n, m)
        if sub == 0x5: return "mov.w R%d,@(R0,R%d)" % (n, m)
        if sub == 0x6: return "mov.l R%d,@(R0,R%d)" % (n, m)
        if sub == 0x2 and m == 0: return "stc SR,R%d" % n
        if sub == 0x2 and m == 1: return "stc GBR,R%d" % n
        if sub == 0x2 and m == 2: return "stc VBR,R%d" % n
        if sub == 0xF: return "mac.l @R%d+,@R%d+" % (m, n)
        if sub == 0x7: return "mul.l R%d,R%d" % (m, n)
        return ".word 0x%04X (0xxx)" % op

    if top == 0x8:
        sub = n
        if sub == 0x9:
            disp = imm8*2; target = addr + 4 + disp
            return "bt 0x%05X" % target
        if sub == 0xD:
            disp = imm8*2; target = addr + 4 + disp
            return "bt/s 0x%05X" % target
        if sub == 0xF:
            disp = imm8*2; target = addr + 4 + disp
            return "bf/s 0x%05X" % target
        if sub == 0xB:
            disp = imm8*2; target = addr + 4 + disp
            return "bf 0x%05X" % target
        if sub == 0x0: return "mov.b R0,@(%d,R%d)" % (d4, m)
        if sub == 0x1: return "mov.w R0,@(%d,R%d)" % (d4*2, m)
        if sub == 0x4: return "mov.b @(%d,R%d),R0" % (d4, m)
        if sub == 0x5: return "mov.w @(%d,R%d),R0" % (d4*2, m)
        return ".word 0x%04X (8xxx)" % op

    if top == 0xA:
        disp = d12 if d12 < 0x800 else d12 - 0x1000
        target = addr + 4 + disp * 2
        return "bra 0x%05X" % target

    if top == 0xB:
        disp = d12 if d12 < 0x800 else d12 - 0x1000
        target = addr + 4 + disp * 2
        return "bsr 0x%05X" % target

    return ".word 0x%04X" % op


def print_range(start, end, targets=None):
    if targets is None:
        targets = set()
    addr = start
    while addr < end:
        op = read_u16(addr)
        s = disasm_one(addr)
        # Flag FPU instructions and RAM references
        flags = []
        if (op & 0xF000) == 0xF000:
            flags.append("FPU")
        # Check for RAM addresses in the instruction
        if "RAM" in s or "FFFF" in s:
            flags.append("RAM")
        # Highlight specifically target addresses
        for t in targets:
            if "0x%05X" % t in s or "0x%08X" % t in s:
                flags.append("<<< TARGET")
        flag_str = "  ; " + ", ".join(flags) if flags else ""
        print("  %05X: %04X  %-42s%s" % (addr, op, s, flag_str))
        addr += 2


# The main CL/OL function. We know callers are at 0x36016 and 0x36064.
# The actual init at 0x36962 writes FFFF79A0.
# The CL/OL decay loop that READS FFFF79A0 is what we need to find.
# Let's check the function at 0x3602A (bsr target from 0x36016).

print("=" * 90)
print("CL/OL CALLER at ROM 0x35FC0 - 0x36100 (context around callers)")
print("=" * 90)
print_range(0x35FC0, 0x36100)

print()
print("=" * 90)
print("CL/OL MAIN function: ROM 0x36000 - 0x360D2")
print("=" * 90)
print_range(0x36000, 0x360D2)

print()
print("=" * 90)
print("CL/OL CONTINUATION: ROM 0x360D2 - 0x36500")
print("=" * 90)
print_range(0x360D2, 0x36500)
