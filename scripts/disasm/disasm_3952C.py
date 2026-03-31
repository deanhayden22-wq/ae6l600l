#!/usr/bin/env python3
"""Complete annotated SH-2 disassembly of function at 0x39524-0x39760"""
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
    """Classify a 32-bit value as RAM, ROM, calibration, or constant."""
    if 0xFFFF0000 <= val <= 0xFFFFFFFF:
        return "RAM"
    elif val < 0x00100000:
        return "ROM"
    elif 0x000A0000 <= val <= 0x000FFFFF:
        return "CAL"
    elif 0xFFFE0000 <= val <= 0xFFFEFFFF:
        return "I/O"
    else:
        return "CONST"

# Collect all branch targets for labeling
branch_targets = set()
call_targets = set()

def disasm_one(addr):
    """Disassemble one instruction, return (mnemonic, comment, is_branch_delay, branch_target_or_None)"""
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
        pool_addr = addr + 4 + disp
        val = read_u16(rom, pool_addr)
        mnemonic = f"mov.w  @(0x{pool_addr:05X},PC),{rn(n_reg)}"
        comment = f"; {rn(n_reg)} = 0x{val:04X} ({val}) [from pool 0x{pool_addr:05X}]"

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
            pool_addr = ((addr + 4) & ~3) + disp
            val = read_u32(rom, pool_addr)
            mnemonic = f"mova   @(0x{pool_addr:05X},PC),R0"
            comment = f"; R0 = 0x{pool_addr:05X} (-> 0x{val:08X})"
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
            gbr_comment = "; read-modify-write byte at [R0+GBR]"
            comment = gbr_comment
        elif sub == 0xF:
            mnemonic = f"or.b   #0x{d8:02X},@(R0,GBR)"
            comment = "; read-modify-write byte at [R0+GBR]"
        else:
            mnemonic = f".word  0x{op:04X}  ; Cxxx"

    elif top == 0xD:
        disp = d8 * 4
        pool_addr = ((addr + 4) & ~3) + disp
        if pool_addr + 3 < len(rom):
            val = read_u32(rom, pool_addr)
            cls = classify_addr(val)
            mnemonic = f"mov.l  @(0x{pool_addr:05X},PC),{rn(n_reg)}"
            if cls == "RAM":
                comment = f"; {rn(n_reg)} = 0x{val:08X} (RAM) [from pool 0x{pool_addr:05X}]"
            elif cls == "ROM":
                comment = f"; {rn(n_reg)} = 0x{val:08X} (ROM) [from pool 0x{pool_addr:05X}]"
            elif cls == "CAL":
                comment = f"; {rn(n_reg)} = 0x{val:08X} (CAL) [from pool 0x{pool_addr:05X}]"
                try:
                    fval = read_float(rom, val)
                    comment += f" float={fval}"
                except:
                    pass
            elif cls == "I/O":
                comment = f"; {rn(n_reg)} = 0x{val:08X} (I/O) [from pool 0x{pool_addr:05X}]"
            else:
                comment = f"; {rn(n_reg)} = 0x{val:08X} (const) [from pool 0x{pool_addr:05X}]"
        else:
            mnemonic = f"mov.l  @(0x{pool_addr:05X},PC),{rn(n_reg)}"

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
# PASS 1: collect branch targets
# ====================================================================
START = 0x39524
END = 0x39760  # past the last instruction, before literal pool

addr = START
while addr < END:
    disasm_one(addr)
    addr += 2

# ====================================================================
# PASS 2: output with labels
# ====================================================================
print("=" * 120)
print(f"COMPLETE ANNOTATED DISASSEMBLY: 0x{START:05X} - 0x{END:05X}")
print(f"ROM: {ROM_PATH}")
print(f"Processor: SH7058 (SH-2), Big-endian, ROM base = 0x00000000, RAM = 0xFFFF0000-0xFFFFFFFF")
print(f"GBR = 0x{GBR:08X}")
print("=" * 120)
print()

addr = START
while addr < END:
    # Print label if this address is a branch target
    if addr in branch_targets:
        print(f"\n  loc_{addr:05X}:")
    if addr in call_targets:
        print(f"\n  sub_{addr:05X}:")

    op, mnemonic, comment = disasm_one(addr)

    line = f"  {addr:05X}:  {op:04X}    {mnemonic}"
    if comment:
        line = line.ljust(65) + comment
    print(line)
    addr += 2

# ====================================================================
# LITERAL POOL DUMP
# ====================================================================
print()
print("=" * 120)
print("LITERAL POOL (data after code)")
print("=" * 120)

# Dump from end of code through what appears to be the literal pool
pool_start = END
# Scan until we hit something that looks like code again or reach a reasonable end
pool_end = 0x397A0  # generous end

addr = pool_start
while addr < pool_end:
    if addr + 3 < len(rom):
        val = read_u32(rom, addr)
        cls = classify_addr(val)
        extra = ""
        if cls == "RAM":
            extra = f"  <- RAM address"
        elif cls == "ROM":
            extra = f"  <- ROM address"
        elif cls == "CAL":
            extra = f"  <- Calibration"
            try:
                fval = read_float(rom, val)
                extra += f" (float @ 0x{val:05X} = {fval})"
            except:
                pass
        elif cls == "I/O":
            extra = f"  <- I/O register"
        else:
            # Try interpreting as float
            try:
                fval = read_float(rom, addr)
                if abs(fval) > 1e-10 and abs(fval) < 1e10:
                    extra = f"  (as float: {fval})"
            except:
                pass
        print(f"  {addr:05X}:  {val:08X}    {cls:5s}  0x{val:08X}{extra}")
    addr += 4

# ====================================================================
# SUMMARY: All subroutine calls
# ====================================================================
print()
print("=" * 120)
print("SUBROUTINE CALLS (BSR/JSR targets)")
print("=" * 120)
for t in sorted(call_targets):
    print(f"  0x{t:05X}")

print()
print("=" * 120)
print("BRANCH TARGETS (internal labels)")
print("=" * 120)
for t in sorted(branch_targets):
    print(f"  loc_{t:05X}")

# ====================================================================
# RAM addresses accessed (from GBR-relative and literal pool loads)
# ====================================================================
print()
print("=" * 120)
print("RAM ADDRESSES REFERENCED (via literal pool)")
print("=" * 120)

# Re-scan literal pool for RAM addresses
for a in range(pool_start, pool_end, 4):
    if a + 3 < len(rom):
        val = read_u32(rom, a)
        if 0xFFFF0000 <= val <= 0xFFFFFFFF:
            print(f"  Pool 0x{a:05X} -> RAM 0x{val:08X}")
