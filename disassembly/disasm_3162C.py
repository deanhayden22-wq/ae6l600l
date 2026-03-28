#!/usr/bin/env python3
"""Complete annotated SH-2 disassembly of function at 0x3162C computing FFFF7452 CL readiness flag.
Handles the mid-function literal pool between code block 1 and code block 2."""
import struct, sys

ROM_PATH = 'C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin'

with open(ROM_PATH, 'rb') as f:
    rom = f.read()

GBR = 0xFFFF7450

def read_u8(data, addr):
    return data[addr]

def read_u16(data, addr):
    return struct.unpack('>H', data[addr:addr+2])[0]

def read_u32(data, addr):
    return struct.unpack('>I', data[addr:addr+4])[0]

def read_float(data, addr):
    return struct.unpack('>f', data[addr:addr+4])[0]

def read_s8(val):
    if val > 127: return val - 256
    return val

def sign12(v):
    return v if v < 2048 else v - 4096

def rn(n): return f"R{n}"
def frn(n): return f"FR{n}"

def classify_addr(val):
    if 0xFFFF0000 <= val <= 0xFFFFFFFF:
        return "RAM"
    elif 0x000A0000 <= val <= 0x000FFFFF:
        return "CAL"
    elif val < 0x00100000:
        return "ROM"
    elif 0xFFFE0000 <= val <= 0xFFFEFFFF:
        return "I/O"
    else:
        return "CONST"

branch_targets = set()
call_targets = set()
pool_refs = set()  # track literal pool addresses

def disasm_one(addr):
    op = read_u16(rom, addr)
    nibbles = [(op >> 12) & 0xF, (op >> 8) & 0xF, (op >> 4) & 0xF, op & 0xF]
    n_reg = nibbles[1]
    m_reg = nibbles[2]
    d8 = op & 0xFF
    d4 = op & 0xF
    top = nibbles[0]

    mnemonic = ""
    comment = ""

    if op == 0x0009:
        mnemonic = "nop"
    elif op == 0x000B:
        mnemonic = "rts"
        comment = "; <<< RETURN >>>"
    elif op == 0x0019:
        mnemonic = "div0u"
    elif op == 0x0008:
        mnemonic = "clrt"
    elif op == 0x0018:
        mnemonic = "sett"
    elif op == 0x002B:
        mnemonic = "rte"

    elif top == 0x0:
        sub = nibbles[3]
        if sub == 0xC:
            mnemonic = f"mov.b  @(R0,{rn(m_reg)}),{rn(n_reg)}"
        elif sub == 0xD:
            mnemonic = f"mov.w  @(R0,{rn(m_reg)}),{rn(n_reg)}"
        elif sub == 0xE:
            mnemonic = f"mov.l  @(R0,{rn(m_reg)}),{rn(n_reg)}"
        elif sub == 0x4:
            mnemonic = f"mov.b  {rn(m_reg)},@(R0,{rn(n_reg)})"
        elif sub == 0x5:
            mnemonic = f"mov.w  {rn(m_reg)},@(R0,{rn(n_reg)})"
        elif sub == 0x6:
            mnemonic = f"mov.l  {rn(m_reg)},@(R0,{rn(n_reg)})"
        elif sub == 0x7:
            mnemonic = f"mul.l  {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0x3:
            mnemonic = f"bsrf   {rn(n_reg)}"
        elif sub == 0x2:
            if m_reg == 0:
                mnemonic = f"stc    SR,{rn(n_reg)}"
            elif m_reg == 1:
                mnemonic = f"stc    GBR,{rn(n_reg)}"
            elif m_reg == 2:
                mnemonic = f"stc    VBR,{rn(n_reg)}"
            else:
                mnemonic = f".word  0x{op:04X}"
        elif sub == 0xA:
            if m_reg == 0:
                mnemonic = f"sts    MACH,{rn(n_reg)}"
            elif m_reg == 1:
                mnemonic = f"sts    MACL,{rn(n_reg)}"
            elif m_reg == 2:
                mnemonic = f"sts    PR,{rn(n_reg)}"
            else:
                mnemonic = f".word  0x{op:04X}"
        else:
            mnemonic = f".word  0x{op:04X}"

    elif top == 0x1:
        disp = d4 * 4
        mnemonic = f"mov.l  {rn(m_reg)},@({disp},{rn(n_reg)})"

    elif top == 0x2:
        sub = nibbles[3]
        if sub in (0,1,2):
            sz = {0:".b",1:".w",2:".l"}[sub]
            mnemonic = f"mov{sz}  {rn(m_reg)},@{rn(n_reg)}"
        elif sub in (4,5,6):
            sz = {4:".b",5:".w",6:".l"}[sub]
            mnemonic = f"mov{sz}  {rn(m_reg)},@-{rn(n_reg)}"
        elif sub == 7:
            mnemonic = f"div0s  {rn(m_reg)},{rn(n_reg)}"
        elif sub == 8:
            mnemonic = f"tst    {rn(m_reg)},{rn(n_reg)}"
        elif sub == 9:
            mnemonic = f"and    {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xA:
            mnemonic = f"xor    {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xB:
            mnemonic = f"or     {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xC:
            mnemonic = f"cmp/str {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xD:
            mnemonic = f"xtrct  {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xE:
            mnemonic = f"mulu.w {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xF:
            mnemonic = f"muls.w {rn(m_reg)},{rn(n_reg)}"
        else:
            mnemonic = f".word  0x{op:04X}"

    elif top == 0x3:
        sub = nibbles[3]
        ops3 = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",4:"div1",5:"dmulu.l",
                6:"cmp/hi",7:"cmp/gt",8:"sub",0xA:"subc",0xB:"subv",
                0xC:"add",0xD:"dmuls.l",0xE:"addc",0xF:"addv"}
        if sub in ops3:
            mnemonic = f"{ops3[sub]}  {rn(m_reg)},{rn(n_reg)}"
        else:
            mnemonic = f".word  0x{op:04X}"

    elif top == 0x4:
        low8 = op & 0xFF
        if low8 == 0x22:
            mnemonic = f"sts.l  PR,@-{rn(n_reg)}"
        elif low8 == 0x26:
            mnemonic = f"lds.l  @{rn(n_reg)}+,PR"
        elif low8 == 0x13:
            mnemonic = f"stc.l  GBR,@-{rn(n_reg)}"
        elif low8 == 0x17:
            mnemonic = f"ldc.l  @{rn(n_reg)}+,GBR"
        elif low8 == 0x1E:
            mnemonic = f"ldc    {rn(n_reg)},GBR"
        elif low8 == 0x0B:
            mnemonic = f"jsr    @{rn(n_reg)}"
            comment = f"; call via {rn(n_reg)}"
        elif low8 == 0x2B:
            mnemonic = f"jmp    @{rn(n_reg)}"
            comment = f"; jump via {rn(n_reg)}"
        elif low8 == 0x15:
            mnemonic = f"cmp/pl {rn(n_reg)}"
        elif low8 == 0x11:
            mnemonic = f"cmp/pz {rn(n_reg)}"
        elif low8 == 0x10:
            mnemonic = f"dt     {rn(n_reg)}"
        elif low8 == 0x00:
            mnemonic = f"shll   {rn(n_reg)}"
        elif low8 == 0x01:
            mnemonic = f"shlr   {rn(n_reg)}"
        elif low8 == 0x04:
            mnemonic = f"rotl   {rn(n_reg)}"
        elif low8 == 0x05:
            mnemonic = f"rotr   {rn(n_reg)}"
        elif low8 == 0x08:
            mnemonic = f"shll2  {rn(n_reg)}"
        elif low8 == 0x09:
            mnemonic = f"shlr2  {rn(n_reg)}"
        elif low8 == 0x18:
            mnemonic = f"shll8  {rn(n_reg)}"
        elif low8 == 0x19:
            mnemonic = f"shlr8  {rn(n_reg)}"
        elif low8 == 0x28:
            mnemonic = f"shll16 {rn(n_reg)}"
        elif low8 == 0x29:
            mnemonic = f"shlr16 {rn(n_reg)}"
        elif low8 == 0x20:
            mnemonic = f"shal   {rn(n_reg)}"
        elif low8 == 0x21:
            mnemonic = f"shar   {rn(n_reg)}"
        elif low8 == 0x24:
            mnemonic = f"rotcl  {rn(n_reg)}"
        elif low8 == 0x25:
            mnemonic = f"rotcr  {rn(n_reg)}"
        elif low8 == 0x0A:
            mnemonic = f"lds    {rn(n_reg)},MACH"
        elif low8 == 0x1A:
            mnemonic = f"lds    {rn(n_reg)},MACL"
        elif low8 == 0x2A:
            mnemonic = f"lds    {rn(n_reg)},PR"
        else:
            lo1 = nibbles[3]
            if lo1 == 0xC:
                mnemonic = f"shad   {rn(m_reg)},{rn(n_reg)}"
            elif lo1 == 0xD:
                mnemonic = f"shld   {rn(m_reg)},{rn(n_reg)}"
            elif lo1 == 0xF:
                mnemonic = f"mac.w  @{rn(m_reg)}+,@{rn(n_reg)}+"
            else:
                mnemonic = f".word  0x{op:04X}  ; 4xxx"

    elif top == 0x5:
        disp = d4 * 4
        mnemonic = f"mov.l  @({disp},{rn(m_reg)}),{rn(n_reg)}"

    elif top == 0x6:
        sub = nibbles[3]
        if sub == 0: mnemonic = f"mov.b  @{rn(m_reg)},{rn(n_reg)}"
        elif sub == 1: mnemonic = f"mov.w  @{rn(m_reg)},{rn(n_reg)}"
        elif sub == 2: mnemonic = f"mov.l  @{rn(m_reg)},{rn(n_reg)}"
        elif sub == 3: mnemonic = f"mov    {rn(m_reg)},{rn(n_reg)}"
        elif sub == 4: mnemonic = f"mov.b  @{rn(m_reg)}+,{rn(n_reg)}"
        elif sub == 5: mnemonic = f"mov.w  @{rn(m_reg)}+,{rn(n_reg)}"
        elif sub == 6: mnemonic = f"mov.l  @{rn(m_reg)}+,{rn(n_reg)}"
        elif sub == 7: mnemonic = f"not    {rn(m_reg)},{rn(n_reg)}"
        elif sub == 8: mnemonic = f"swap.b {rn(m_reg)},{rn(n_reg)}"
        elif sub == 9: mnemonic = f"swap.w {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xA: mnemonic = f"negc   {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xB: mnemonic = f"neg    {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xC: mnemonic = f"extu.b {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xD: mnemonic = f"extu.w {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xE: mnemonic = f"exts.b {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xF: mnemonic = f"exts.w {rn(m_reg)},{rn(n_reg)}"
        else: mnemonic = f".word  0x{op:04X}"

    elif top == 0x7:
        imm = read_s8(d8)
        mnemonic = f"add    #{imm},{rn(n_reg)}"
        if n_reg == 15:
            comment = f"; SP adjust: SP += {imm}"

    elif top == 0x8:
        sub = nibbles[1]
        if sub == 0x0:
            mnemonic = f"mov.b  R0,@({d4},{rn(m_reg)})"
        elif sub == 0x1:
            disp = d4 * 2
            mnemonic = f"mov.w  R0,@({disp},{rn(m_reg)})"
        elif sub == 0x4:
            mnemonic = f"mov.b  @({d4},{rn(m_reg)}),R0"
        elif sub == 0x5:
            disp = d4 * 2
            mnemonic = f"mov.w  @({disp},{rn(m_reg)}),R0"
        elif sub == 0x8:
            imm = read_s8(d8)
            mnemonic = f"cmp/eq #{imm},R0"
        elif sub == 0x9:
            disp = read_s8(d8) * 2 + 4
            target = addr + disp
            mnemonic = f"bt     0x{target:05X}"
            branch_targets.add(target)
        elif sub == 0xB:
            disp = read_s8(d8) * 2 + 4
            target = addr + disp
            mnemonic = f"bf     0x{target:05X}"
            branch_targets.add(target)
        elif sub == 0xD:
            disp = read_s8(d8) * 2 + 4
            target = addr + disp
            mnemonic = f"bt/s   0x{target:05X}"
            branch_targets.add(target)
        elif sub == 0xF:
            disp = read_s8(d8) * 2 + 4
            target = addr + disp
            mnemonic = f"bf/s   0x{target:05X}"
            branch_targets.add(target)
        else:
            mnemonic = f".word  0x{op:04X}"

    elif top == 0x9:
        disp = d8 * 2
        pa = addr + 4 + disp
        val = read_u16(rom, pa)
        mnemonic = f"mov.w  @(0x{pa:05X},PC),{rn(n_reg)}"
        comment = f"; {rn(n_reg)} = 0x{val:04X} ({val}) [pool 0x{pa:05X}]"
        pool_refs.add(pa)

    elif top == 0xA:
        disp12 = op & 0xFFF
        target = addr + 4 + sign12(disp12) * 2
        mnemonic = f"bra    0x{target:05X}"
        branch_targets.add(target)

    elif top == 0xB:
        disp12 = op & 0xFFF
        target = addr + 4 + sign12(disp12) * 2
        mnemonic = f"bsr    0x{target:05X}"
        call_targets.add(target)
        comment = f"; call 0x{target:05X}"

    elif top == 0xC:
        sub = nibbles[1]
        if sub == 0x0:
            disp = d8
            gbr_addr = GBR + disp
            mnemonic = f"mov.b  R0,@(0x{disp:02X},GBR)"
            comment = f"; write byte [{gbr_addr:08X}]"
        elif sub == 0x1:
            disp = d8 * 2
            gbr_addr = GBR + disp
            mnemonic = f"mov.w  R0,@(0x{disp:03X},GBR)"
            comment = f"; write word [{gbr_addr:08X}]"
        elif sub == 0x2:
            disp = d8 * 4
            gbr_addr = GBR + disp
            mnemonic = f"mov.l  R0,@(0x{disp:03X},GBR)"
            comment = f"; write long [{gbr_addr:08X}]"
        elif sub == 0x3:
            mnemonic = f"trapa  #0x{d8:02X}"
        elif sub == 0x4:
            disp = d8
            gbr_addr = GBR + disp
            mnemonic = f"mov.b  @(0x{disp:02X},GBR),R0"
            comment = f"; R0 = byte [{gbr_addr:08X}]"
        elif sub == 0x5:
            disp = d8 * 2
            gbr_addr = GBR + disp
            mnemonic = f"mov.w  @(0x{disp:03X},GBR),R0"
            comment = f"; R0 = word [{gbr_addr:08X}]"
        elif sub == 0x6:
            disp = d8 * 4
            gbr_addr = GBR + disp
            mnemonic = f"mov.l  @(0x{disp:03X},GBR),R0"
            comment = f"; R0 = long [{gbr_addr:08X}]"
        elif sub == 0x7:
            disp = d8 * 4
            pa = ((addr + 4) & ~3) + disp
            val = read_u32(rom, pa)
            mnemonic = f"mova   @(0x{pa:05X},PC),R0"
            comment = f"; R0 = 0x{pa:05X} (-> 0x{val:08X})"
            pool_refs.add(pa)
        elif sub == 0x8:
            mnemonic = f"tst    #0x{d8:02X},R0"
        elif sub == 0x9:
            mnemonic = f"and    #0x{d8:02X},R0"
        elif sub == 0xA:
            mnemonic = f"xor    #0x{d8:02X},R0"
        elif sub == 0xB:
            mnemonic = f"or     #0x{d8:02X},R0"
        elif sub == 0xD:
            mnemonic = f"and.b  #0x{d8:02X},@(R0,GBR)"
            comment = "; read-modify-write byte at [R0+GBR]"
        elif sub == 0xF:
            mnemonic = f"or.b   #0x{d8:02X},@(R0,GBR)"
            comment = "; read-modify-write byte at [R0+GBR]"
        else:
            mnemonic = f".word  0x{op:04X}  ; Cxxx"

    elif top == 0xD:
        disp = d8 * 4
        pa = ((addr + 4) & ~3) + disp
        if pa + 3 < len(rom):
            val = read_u32(rom, pa)
            cls = classify_addr(val)
            mnemonic = f"mov.l  @(0x{pa:05X},PC),{rn(n_reg)}"
            pool_refs.add(pa)
            if cls == "RAM":
                comment = f"; {rn(n_reg)} = 0x{val:08X} (RAM) [pool 0x{pa:05X}]"
            elif cls == "ROM":
                comment = f"; {rn(n_reg)} = 0x{val:08X} (ROM) [pool 0x{pa:05X}]"
            elif cls == "CAL":
                comment = f"; {rn(n_reg)} = 0x{val:08X} (CAL) [pool 0x{pa:05X}]"
                try:
                    fval = read_float(rom, val)
                    comment += f" float={fval}"
                except:
                    pass
            elif cls == "I/O":
                comment = f"; {rn(n_reg)} = 0x{val:08X} (I/O) [pool 0x{pa:05X}]"
            else:
                comment = f"; {rn(n_reg)} = 0x{val:08X} (const) [pool 0x{pa:05X}]"
        else:
            mnemonic = f"mov.l  @(0x{pa:05X},PC),{rn(n_reg)}"

    elif top == 0xE:
        imm = read_s8(d8)
        mnemonic = f"mov    #{imm},{rn(n_reg)}"
        if imm >= 0:
            comment = f"; {rn(n_reg)} = {imm} (0x{imm:02X})"
        else:
            comment = f"; {rn(n_reg)} = {imm} (0x{d8:02X})"

    elif top == 0xF:
        sub = nibbles[3]
        fn = n_reg
        fm = m_reg
        if sub == 0x0: mnemonic = f"fadd   {frn(fm)},{frn(fn)}"
        elif sub == 0x1: mnemonic = f"fsub   {frn(fm)},{frn(fn)}"
        elif sub == 0x2: mnemonic = f"fmul   {frn(fm)},{frn(fn)}"
        elif sub == 0x3: mnemonic = f"fdiv   {frn(fm)},{frn(fn)}"
        elif sub == 0x4: mnemonic = f"fcmp/eq {frn(fm)},{frn(fn)}"
        elif sub == 0x5: mnemonic = f"fcmp/gt {frn(fm)},{frn(fn)}"
        elif sub == 0x6: mnemonic = f"fmov.s @(R0,{rn(m_reg)}),{frn(fn)}"
        elif sub == 0x7: mnemonic = f"fmov.s {frn(fm)},@(R0,{rn(n_reg)})"
        elif sub == 0x8: mnemonic = f"fmov.s @{rn(m_reg)},{frn(fn)}"
        elif sub == 0x9: mnemonic = f"fmov.s @{rn(m_reg)}+,{frn(fn)}"
        elif sub == 0xA: mnemonic = f"fmov.s {frn(fm)},@{rn(n_reg)}"
        elif sub == 0xB: mnemonic = f"fmov.s {frn(fm)},@-{rn(n_reg)}"
        elif sub == 0xC: mnemonic = f"fmov   {frn(fm)},{frn(fn)}"
        elif sub == 0xD:
            if fm == 0x0: mnemonic = f"fsts   FPUL,{frn(fn)}"
            elif fm == 0x1: mnemonic = f"flds   {frn(fn)},FPUL"
            elif fm == 0x2: mnemonic = f"float  FPUL,{frn(fn)}"
            elif fm == 0x3: mnemonic = f"ftrc   {frn(fn)},FPUL"
            elif fm == 0x4: mnemonic = f"fneg   {frn(fn)}"
            elif fm == 0x5: mnemonic = f"fabs   {frn(fn)}"
            elif fm == 0x6: mnemonic = f"fsqrt  {frn(fn)}"
            elif fm == 0x8: mnemonic = f"fldi0  {frn(fn)}"
            elif fm == 0x9: mnemonic = f"fldi1  {frn(fn)}"
            elif fm == 0xA:
                mnemonic = f"lds    {rn(n_reg)},FPUL"
            else: mnemonic = f".word  0x{op:04X}  ; FPU_xD"
        elif sub == 0xE: mnemonic = f"fmac   FR0,{frn(fm)},{frn(fn)}"
        else:
            mnemonic = f".word  0x{op:04X}  ; FPU"

    if not mnemonic:
        mnemonic = f".word  0x{op:04X}"

    return op, mnemonic, comment

# ====================================================================
# Define code regions (skip literal pool in the middle)
# ====================================================================
# Code block 1: 0x3162C - 0x317DC (ends with bra 0x319E4, delay slot C001)
# Literal pool 1: 0x317DC - 0x3186C
# Code block 2: 0x3186C - 0x31A06 (ends with RTS at 0x31A02, delay slot at 0x31A04)
# Literal pool 2: 0x31A06 - ...

CODE_BLOCK_1_START = 0x3162C
CODE_BLOCK_1_END   = 0x317DC  # first non-code byte (literal pool starts)
CODE_BLOCK_2_START = 0x3186C
CODE_BLOCK_2_END   = 0x31A06  # after RTS delay slot

LITPOOL_1_START = 0x317DC
LITPOOL_1_END   = 0x3186C

code_ranges = [
    (CODE_BLOCK_1_START, CODE_BLOCK_1_END),
    (CODE_BLOCK_2_START, CODE_BLOCK_2_END),
]

def is_code(addr):
    for s, e in code_ranges:
        if s <= addr < e:
            return True
    return False

# ====================================================================
# PASS 1: collect branch targets from all code regions
# ====================================================================
for start, end in code_ranges:
    addr = start
    while addr < end:
        disasm_one(addr)
        addr += 2

# ====================================================================
# PASS 2: output with labels
# ====================================================================
output_lines = []

def out(s=""):
    output_lines.append(s)

out("=" * 130)
out(f"COMPLETE ANNOTATED DISASSEMBLY: Function at 0x{CODE_BLOCK_1_START:05X}")
out(f"Purpose: Compute FFFF7452 master CL readiness flag")
out(f"ROM: {ROM_PATH}")
out(f"Processor: SH7058 (SH-2), Big-endian, ROM base = 0x00000000, RAM = 0xFFFF0000-0xFFFFFFFF")
out(f"GBR = 0x{GBR:08X}")
out(f"GBR+0x02 = FFFF7452 (master CL readiness flag)")
out(f"Code block 1: 0x{CODE_BLOCK_1_START:05X} - 0x{CODE_BLOCK_1_END:05X}")
out(f"Literal pool 1: 0x{LITPOOL_1_START:05X} - 0x{LITPOOL_1_END:05X}")
out(f"Code block 2: 0x{CODE_BLOCK_2_START:05X} - 0x{CODE_BLOCK_2_END:05X}")
out("=" * 130)
out()

# Code block 1
out(";" + "=" * 80)
out("; CODE BLOCK 1: 0x{:05X} - 0x{:05X}".format(CODE_BLOCK_1_START, CODE_BLOCK_1_END))
out(";" + "=" * 80)

addr = CODE_BLOCK_1_START
while addr < CODE_BLOCK_1_END:
    if addr in branch_targets:
        out(f"\n  loc_{addr:05X}:")
    if addr in call_targets:
        out(f"\n  sub_{addr:05X}:")

    op, mnemonic, comment = disasm_one(addr)
    line = f"  {addr:05X}:  {op:04X}    {mnemonic}"
    if comment:
        line = line.ljust(68) + comment
    out(line)
    addr += 2

# Literal pool 1
out()
out(";" + "=" * 80)
out("; LITERAL POOL 1: 0x{:05X} - 0x{:05X}".format(LITPOOL_1_START, LITPOOL_1_END))
out(";" + "=" * 80)

addr = LITPOOL_1_START
while addr < LITPOOL_1_END:
    val = read_u32(rom, addr)
    cls = classify_addr(val)
    extra = ""
    if cls == "RAM":
        extra = f"  <- RAM"
    elif cls == "CAL":
        extra = f"  <- CAL"
        try:
            fval = read_float(rom, val)
            extra += f" float={fval}"
        except:
            pass
    elif cls == "ROM":
        extra = f"  <- ROM"
    out(f"  {addr:05X}:  {val:08X}  {cls:5s}{extra}")
    addr += 4

# Code block 2
out()
out(";" + "=" * 80)
out("; CODE BLOCK 2: 0x{:05X} - 0x{:05X}".format(CODE_BLOCK_2_START, CODE_BLOCK_2_END))
out(";" + "=" * 80)

addr = CODE_BLOCK_2_START
while addr < CODE_BLOCK_2_END:
    if addr in branch_targets:
        out(f"\n  loc_{addr:05X}:")
    if addr in call_targets:
        out(f"\n  sub_{addr:05X}:")

    op, mnemonic, comment = disasm_one(addr)
    line = f"  {addr:05X}:  {op:04X}    {mnemonic}"
    if comment:
        line = line.ljust(68) + comment
    out(line)
    addr += 2

# ====================================================================
# Pool references summary
# ====================================================================
out()
out("=" * 130)
out("ALL LITERAL POOL REFERENCES (resolved)")
out("=" * 130)
for pa in sorted(pool_refs):
    if pa + 3 < len(rom):
        val = read_u32(rom, pa)
        cls = classify_addr(val)
        extra = ""
        if cls == "RAM":
            extra = f"  <- RAM"
        elif cls == "CAL":
            try:
                fval = read_float(rom, val)
                extra = f"  <- CAL float={fval}"
            except:
                extra = "  <- CAL"
        elif cls == "ROM":
            extra = f"  <- ROM (subroutine?)"
        out(f"  Pool 0x{pa:05X} -> 0x{val:08X}  {cls}{extra}")

# ====================================================================
# GBR-relative summary
# ====================================================================
out()
out("=" * 130)
out("GBR-RELATIVE ADDRESSES ACCESSED (GBR = 0xFFFF7450)")
out("=" * 130)

gbr_accesses = []
for start, end in code_ranges:
    addr = start
    while addr < end:
        op = read_u16(rom, addr)
        top4 = (op >> 12) & 0xF
        sub = (op >> 8) & 0xF
        d8 = op & 0xFF
        if top4 == 0xC:
            if sub == 0x0:
                gbr_accesses.append((addr, "write.b", GBR + d8))
            elif sub == 0x1:
                gbr_accesses.append((addr, "write.w", GBR + d8*2))
            elif sub == 0x2:
                gbr_accesses.append((addr, "write.l", GBR + d8*4))
            elif sub == 0x4:
                gbr_accesses.append((addr, "read.b", GBR + d8))
            elif sub == 0x5:
                gbr_accesses.append((addr, "read.w", GBR + d8*2))
            elif sub == 0x6:
                gbr_accesses.append((addr, "read.l", GBR + d8*4))
            elif sub == 0xD:
                gbr_accesses.append((addr, "and.b", "R0+GBR"))
            elif sub == 0xF:
                gbr_accesses.append((addr, "or.b", "R0+GBR"))
        addr += 2

for iaddr, access_type, access_addr in sorted(gbr_accesses, key=lambda x: (str(x[2]), x[0])):
    if isinstance(access_addr, int):
        out(f"  0x{iaddr:05X}: {access_type:10s}  0x{access_addr:08X}")
    else:
        out(f"  0x{iaddr:05X}: {access_type:10s}  {access_addr}")

# ====================================================================
# RAM addresses
# ====================================================================
out()
out("=" * 130)
out("RAM ADDRESSES REFERENCED (via literal pool)")
out("=" * 130)
ram_set = set()
for pa in sorted(pool_refs):
    if pa + 3 < len(rom):
        val = read_u32(rom, pa)
        if 0xFFFF0000 <= val <= 0xFFFFFFFF:
            ram_set.add(val)
for ra in sorted(ram_set):
    out(f"  RAM 0x{ra:08X}")

# ====================================================================
# Subroutine calls
# ====================================================================
out()
out("=" * 130)
out("SUBROUTINE CALLS")
out("=" * 130)
# JSR calls (via literal pool)
jsr_targets = []
for start, end in code_ranges:
    addr = start
    while addr < end:
        op = read_u16(rom, addr)
        if (op & 0xF0FF) == 0x400B:  # JSR @Rn
            n = (op >> 8) & 0xF
            # Find the preceding mov.l that loaded this register
            # Search backward for the mov.l @(disp,PC),Rn
            for ba in range(addr-2, max(addr-20, start-1), -2):
                bop = read_u16(rom, ba)
                if (bop >> 12) == 0xD and ((bop >> 8) & 0xF) == n:
                    disp = (bop & 0xFF) * 4
                    pa = ((ba + 4) & ~3) + disp
                    val = read_u32(rom, pa)
                    jsr_targets.append((addr, val))
                    break
        addr += 2

for iaddr, target in sorted(jsr_targets):
    out(f"  0x{iaddr:05X}: JSR -> 0x{target:08X}")

for t in sorted(call_targets):
    out(f"  BSR -> 0x{t:05X}")

# Write output
result = "\n".join(output_lines)
print(result)

with open('C:/Users/Dean/Documents/GitHub/ae6l600l/disassembly/disasm_3162C_annotated.txt', 'w') as f:
    f.write(result)
    f.write("\n")

print(f"\n\nWritten to disasm_3162C_annotated.txt")
