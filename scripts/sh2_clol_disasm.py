#!/usr/bin/env python3
"""SH-2 disassembler for CL/OL decision function at 0x032E28"""
import struct, sys

with open('rom/ae5l600l.bin', 'rb') as f:
    rom = f.read()

def read16(addr):
    return struct.unpack_from('>H', rom, addr)[0]

def read32(addr):
    return struct.unpack_from('>I', rom, addr)[0]

def sign8(v):
    return v if v < 128 else v - 256

def sign12(v):
    return v if v < 2048 else v - 4096

def disasm_sh2(addr, opcode):
    n = (opcode >> 8) & 0xF
    m = (opcode >> 4) & 0xF
    d = opcode & 0xFF
    d4 = opcode & 0xF
    top = (opcode >> 12) & 0xF

    if opcode == 0x000B: return "rts", ""
    if opcode == 0x0009: return "nop", ""
    if opcode == 0x0008: return "clrt", ""
    if opcode == 0x0018: return "sett", ""
    if opcode == 0x002B: return "rte", ""

    if top == 0x0:
        lo = opcode & 0xF
        if lo == 0xC: return f"mov.b @(R0,R{m}),R{n}", ""
        if lo == 0xD: return f"mov.w @(R0,R{m}),R{n}", ""
        if lo == 0xE: return f"mov.l @(R0,R{m}),R{n}", ""
        lo2 = opcode & 0xFF
        if lo2 == 0x07: return f"mul.l R{m},R{n}", ""
        if lo == 0x4: return f"mov.b R{m},@(R0,R{n})", ""
        if lo == 0x5: return f"mov.w R{m},@(R0,R{n})", ""
        if lo == 0x6: return f"mov.l R{m},@(R0,R{n})", ""
        if lo2 == 0x0A: return f"sts MACH,R{n}", ""
        if lo2 == 0x1A: return f"sts MACL,R{n}", ""
        if lo2 == 0x2A: return f"sts PR,R{n}", ""
        if lo2 == 0x12: return f"stc GBR,R{n}", ""
        if lo == 0x3: return f"bsrf R{n}", ""

    if top == 0x1:
        return f"mov.l R{m},@({d4*4},R{n})", ""

    if top == 0x2:
        sub = opcode & 0xF
        if sub == 0: return f"mov.b R{m},@R{n}", ""
        if sub == 1: return f"mov.w R{m},@R{n}", ""
        if sub == 2: return f"mov.l R{m},@R{n}", ""
        if sub == 4: return f"mov.b R{m},@-R{n}", ""
        if sub == 5: return f"mov.w R{m},@-R{n}", ""
        if sub == 6: return f"mov.l R{m},@-R{n}", ""
        if sub == 7: return f"div0s R{m},R{n}", ""
        if sub == 8: return f"tst R{m},R{n}", ""
        if sub == 9: return f"and R{m},R{n}", ""
        if sub == 0xA: return f"xor R{m},R{n}", ""
        if sub == 0xB: return f"or R{m},R{n}", ""
        if sub == 0xC: return f"cmp/str R{m},R{n}", ""
        if sub == 0xD: return f"xtrct R{m},R{n}", ""
        if sub == 0xE: return f"mulu.w R{m},R{n}", ""
        if sub == 0xF: return f"muls.w R{m},R{n}", ""

    if top == 0x3:
        sub = opcode & 0xF
        ops = {0:"cmp/eq", 2:"cmp/hs", 3:"cmp/ge", 4:"div1", 5:"dmulu.l",
               6:"cmp/hi", 7:"cmp/gt", 8:"sub", 0xA:"subc", 0xB:"subv",
               0xC:"add", 0xD:"dmuls.l", 0xE:"addc", 0xF:"addv"}
        if sub in ops: return f"{ops[sub]} R{m},R{n}", ""

    if top == 0x4:
        lo2 = opcode & 0xFF
        if lo2 == 0x0B: return f"jsr @R{n}", ""
        if lo2 == 0x2B: return f"jmp @R{n}", ""
        if lo2 == 0x0E: return f"ldc R{n},SR", ""
        if lo2 == 0x1E: return f"ldc R{n},GBR", ""
        if lo2 == 0x2E: return f"ldc R{n},VBR", ""
        if lo2 == 0x08: return f"shll2 R{n}", ""
        if lo2 == 0x18: return f"shll8 R{n}", ""
        if lo2 == 0x28: return f"shll16 R{n}", ""
        if lo2 == 0x09: return f"shlr2 R{n}", ""
        if lo2 == 0x19: return f"shlr8 R{n}", ""
        if lo2 == 0x29: return f"shlr16 R{n}", ""
        if lo2 == 0x00: return f"shll R{n}", ""
        if lo2 == 0x01: return f"shlr R{n}", ""
        if lo2 == 0x04: return f"rotl R{n}", ""
        if lo2 == 0x05: return f"rotr R{n}", ""
        if lo2 == 0x15: return f"cmp/pl R{n}", ""
        if lo2 == 0x11: return f"cmp/pz R{n}", ""
        if lo2 == 0x10: return f"dt R{n}", ""
        if lo2 == 0x20: return f"shal R{n}", ""
        if lo2 == 0x21: return f"shar R{n}", ""
        if lo2 == 0x24: return f"rotcl R{n}", ""
        if lo2 == 0x25: return f"rotcr R{n}", ""
        if lo2 == 0x0A: return f"lds R{n},MACH", ""
        if lo2 == 0x1A: return f"lds R{n},MACL", ""
        if lo2 == 0x2A: return f"lds R{n},PR", ""
        lo1 = opcode & 0xF
        if lo1 == 0xC: return f"shad R{m},R{n}", ""
        if lo1 == 0xD: return f"shld R{m},R{n}", ""
        if lo1 == 0xF: return f"mac.w @R{m}+,@R{n}+", ""

    if top == 0x5:
        return f"mov.l @({d4*4},R{n}),R{m}", f"R{m} = [R{n}+0x{d4*4:X}]"

    if top == 0x6:
        sub = opcode & 0xF
        if sub == 0: return f"mov.b @R{m},R{n}", ""
        if sub == 1: return f"mov.w @R{m},R{n}", ""
        if sub == 2: return f"mov.l @R{m},R{n}", ""
        if sub == 3: return f"mov R{m},R{n}", ""
        if sub == 4: return f"mov.b @R{m}+,R{n}", ""
        if sub == 5: return f"mov.w @R{m}+,R{n}", ""
        if sub == 6: return f"mov.l @R{m}+,R{n}", ""
        if sub == 7: return f"not R{m},R{n}", ""
        if sub == 8: return f"swap.b R{m},R{n}", ""
        if sub == 9: return f"swap.w R{m},R{n}", ""
        if sub == 0xA: return f"negc R{m},R{n}", ""
        if sub == 0xB: return f"neg R{m},R{n}", ""
        if sub == 0xC: return f"extu.b R{m},R{n}", ""
        if sub == 0xD: return f"extu.w R{m},R{n}", ""
        if sub == 0xE: return f"exts.b R{m},R{n}", ""
        if sub == 0xF: return f"exts.w R{m},R{n}", ""

    if top == 0x7:
        imm = sign8(d)
        return f"add #{imm},R{n}", f"R{n} += {imm}"

    if top == 0x8:
        sub = (opcode >> 8) & 0xF
        if sub == 0: return f"mov.b R0,@({d},R{n})", f"[R{n}+{d}] = R0"
        if sub == 1: return f"mov.w R0,@({d*2},R{n})", f"[R{n}+{d*2}] = R0"
        if sub == 4: return f"mov.b @({d},R{m}),R0", f"R0 = [R{m}+{d}]"
        if sub == 5: return f"mov.w @({d*2},R{m}),R0", f"R0 = [R{m}+{d*2}]"
        if sub == 8:
            imm = sign8(d)
            return f"cmp/eq #{imm},R0", f"T = (R0 == {imm})"
        if sub == 9:
            target = addr + 4 + sign8(d) * 2
            return f"bt 0x{target:06X}", f"branch if T=1"
        if sub == 0xB:
            target = addr + 4 + sign8(d) * 2
            return f"bf 0x{target:06X}", f"branch if T=0"
        if sub == 0xD:
            target = addr + 4 + sign8(d) * 2
            return f"bt/s 0x{target:06X}", f"delayed branch if T=1"
        if sub == 0xF:
            target = addr + 4 + sign8(d) * 2
            return f"bf/s 0x{target:06X}", f"delayed branch if T=0"

    if top == 0x9:
        disp = d
        ea = (addr + 4) + disp * 2
        if ea < len(rom):
            val = read16(ea)
            return f"mov.w @(0x{disp*2:X},PC),R{n}", f"R{n} = 0x{val:04X} (from 0x{ea:06X})"
        return f"mov.w @(0x{disp*2:X},PC),R{n}", ""

    if top == 0xA:
        disp12 = opcode & 0xFFF
        target = addr + 4 + sign12(disp12) * 2
        return f"bra 0x{target:06X}", ""

    if top == 0xB:
        disp12 = opcode & 0xFFF
        target = addr + 4 + sign12(disp12) * 2
        return f"bsr 0x{target:06X}", ""

    if top == 0xC:
        sub = (opcode >> 8) & 0xF
        if sub == 0: return f"mov.b R0,@({d},GBR)", ""
        if sub == 1: return f"mov.w R0,@({d*2},GBR)", ""
        if sub == 2: return f"mov.l R0,@({d*4},GBR)", ""
        if sub == 3: return f"trapa #{d}", ""
        if sub == 4: return f"mov.b @({d},GBR),R0", ""
        if sub == 5: return f"mov.w @({d*2},GBR),R0", ""
        if sub == 6: return f"mov.l @({d*4},GBR),R0", ""
        if sub == 7:
            ea = ((addr + 4) & ~3) + d * 4
            if ea < len(rom):
                val = read32(ea)
                return f"mova @(0x{d*4:X},PC),R0", f"R0 = 0x{ea:06X} (-> 0x{val:08X})"
            return f"mova @(0x{d*4:X},PC),R0", ""
        if sub == 8: return f"tst #{d},R0", ""
        if sub == 9: return f"and #{d},R0", ""
        if sub == 0xA: return f"xor #{d},R0", ""
        if sub == 0xB: return f"or #{d},R0", ""
        if sub == 0xD: return f"and.b #{d},@(R0,GBR)", ""

    if top == 0xD:
        disp = d
        ea = ((addr + 4) & ~3) + disp * 4
        if ea < len(rom):
            val = read32(ea)
            return f"mov.l @(0x{disp*4:X},PC),R{n}", f"R{n} = 0x{val:08X} (from 0x{ea:06X})"
        return f"mov.l @(0x{disp*4:X},PC),R{n}", ""

    if top == 0xE:
        imm = sign8(d)
        return f"mov #{imm},R{n}", f"R{n} = {imm}"

    if top == 0xF:
        sub = opcode & 0xF
        fn = (opcode >> 4) & 0xF
        fnn = (opcode >> 8) & 0xF
        if sub == 0: return f"fadd FR{fn},FR{fnn}", ""
        if sub == 1: return f"fsub FR{fn},FR{fnn}", ""
        if sub == 2: return f"fmul FR{fn},FR{fnn}", ""
        if sub == 3: return f"fdiv FR{fn},FR{fnn}", ""
        if sub == 4: return f"fcmp/eq FR{fn},FR{fnn}", ""
        if sub == 5: return f"fcmp/gt FR{fn},FR{fnn}", ""
        if sub == 6: return f"fmov @(R0,R{fn}),FR{fnn}", ""
        if sub == 7: return f"fmov FR{fn},@(R0,R{fnn})", ""
        if sub == 8: return f"fmov @R{fn},FR{fnn}", ""
        if sub == 9: return f"fmov @R{fn}+,FR{fnn}", ""
        if sub == 0xA: return f"fmov FR{fn},@R{fnn}", ""
        if sub == 0xB: return f"fmov FR{fn},@-R{fnn}", ""
        if sub == 0xC: return f"fmov FR{fn},FR{fnn}", ""
        if sub == 0xD:
            if fn == 0: return f"fsts FPUL,FR{fnn}", ""
            if fn == 1: return f"flds FR{fnn},FPUL", ""
            if fn == 2: return f"float FPUL,FR{fnn}", ""
            if fn == 3: return f"ftrc FR{fnn},FPUL", ""
            if fn == 8: return f"lds R{fnn},FPSCR", ""
            if fn == 0xA: return f"lds R{fnn},FPUL", ""
            if fn == 6: return f"sts FPSCR,R{fnn}", ""
            if fn == 4: return f"fneg FR{fnn}", ""
            if fn == 5: return f"fabs FR{fnn}", ""
        if sub == 0xE: return f"fmac FR0,FR{fn},FR{fnn}", ""

    return f".word 0x{opcode:04X}", "unknown"

# Disassemble extended range to cover literal pool too
# Also read further for the literal pool and subroutine targets
start = 0x032D00
end = 0x033100  # extended to catch literal pool refs past 0x3000

print("=" * 110)
print("FULL SH-2 DISASSEMBLY: 0x032D00 - 0x033100")
print("=" * 110)

for a in range(start, end, 2):
    opcode = read16(a)
    mnem, comment = disasm_sh2(a, opcode)
    line = f"  {a:06X}:  {opcode:04X}    {mnem}"
    if comment:
        line = line.ljust(60) + f"; {comment}"
    print(line)
