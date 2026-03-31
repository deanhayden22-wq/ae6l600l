#!/usr/bin/env python3
"""Find writes to FFFF79A0 and disassemble the surrounding function."""
import struct

ROM_PATH = 'C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin'
with open(ROM_PATH, 'rb') as f:
    rom = f.read()

ROM_SIZE = len(rom)
GBR = 0xFFFF7450

def read_u16(addr):
    return struct.unpack('>H', rom[addr:addr+2])[0]

def read_u32(addr):
    return struct.unpack('>I', rom[addr:addr+4])[0]

def read_float_at(addr):
    if addr + 3 < ROM_SIZE:
        return struct.unpack('>f', rom[addr:addr+4])[0]
    return None

def sign12(v):
    return v if v < 2048 else v - 4096

def read_s8(v):
    return v if v < 128 else v - 256

def disasm_one(addr):
    op = read_u16(addr)
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
    elif top == 0x0:
        sub = nibbles[3]
        if sub == 0x4:
            mnemonic = "mov.b  R%d,@(R0,R%d)" % (m_reg, n_reg)
        elif sub == 0x5:
            mnemonic = "mov.w  R%d,@(R0,R%d)" % (m_reg, n_reg)
        elif sub == 0x6:
            mnemonic = "mov.l  R%d,@(R0,R%d)" % (m_reg, n_reg)
        elif sub == 0xC:
            mnemonic = "mov.b  @(R0,R%d),R%d" % (m_reg, n_reg)
        elif sub == 0xD:
            mnemonic = "mov.w  @(R0,R%d),R%d" % (m_reg, n_reg)
        elif sub == 0xE:
            mnemonic = "mov.l  @(R0,R%d),R%d" % (m_reg, n_reg)
        elif sub == 0x7:
            mnemonic = "mul.l  R%d,R%d" % (m_reg, n_reg)
        elif sub == 0x3:
            mnemonic = "bsrf   R%d" % n_reg
        elif sub == 0x2:
            if m_reg == 0:
                mnemonic = "stc    SR,R%d" % n_reg
            elif m_reg == 1:
                mnemonic = "stc    GBR,R%d" % n_reg
            elif m_reg == 2:
                mnemonic = "stc    VBR,R%d" % n_reg
            else:
                mnemonic = ".word  0x%04X" % op
        elif sub == 0xA:
            if m_reg == 0:
                mnemonic = "sts    MACH,R%d" % n_reg
            elif m_reg == 1:
                mnemonic = "sts    MACL,R%d" % n_reg
            elif m_reg == 2:
                mnemonic = "sts    PR,R%d" % n_reg
            else:
                mnemonic = ".word  0x%04X" % op
        else:
            mnemonic = ".word  0x%04X" % op
    elif top == 0x1:
        disp = d4 * 4
        mnemonic = "mov.l  R%d,@(%d,R%d)" % (m_reg, disp, n_reg)
    elif top == 0x2:
        sub = d4
        if sub == 0:
            mnemonic = "mov.b  R%d,@R%d" % (m_reg, n_reg)
        elif sub == 1:
            mnemonic = "mov.w  R%d,@R%d" % (m_reg, n_reg)
        elif sub == 2:
            mnemonic = "mov.l  R%d,@R%d" % (m_reg, n_reg)
        elif sub == 4:
            mnemonic = "mov.b  R%d,@-R%d" % (m_reg, n_reg)
        elif sub == 5:
            mnemonic = "mov.w  R%d,@-R%d" % (m_reg, n_reg)
        elif sub == 6:
            mnemonic = "mov.l  R%d,@-R%d" % (m_reg, n_reg)
        elif sub == 7:
            mnemonic = "div0s  R%d,R%d" % (m_reg, n_reg)
        elif sub == 8:
            mnemonic = "tst    R%d,R%d" % (m_reg, n_reg)
        elif sub == 9:
            mnemonic = "and    R%d,R%d" % (m_reg, n_reg)
        elif sub == 0xA:
            mnemonic = "xor    R%d,R%d" % (m_reg, n_reg)
        elif sub == 0xB:
            mnemonic = "or     R%d,R%d" % (m_reg, n_reg)
        elif sub == 0xD:
            mnemonic = "xtrct  R%d,R%d" % (m_reg, n_reg)
        elif sub == 0xE:
            mnemonic = "mulu.w R%d,R%d" % (m_reg, n_reg)
        elif sub == 0xF:
            mnemonic = "muls.w R%d,R%d" % (m_reg, n_reg)
        else:
            mnemonic = ".word  0x%04X" % op
    elif top == 0x3:
        sub = d4
        ops3 = {0:"cmp/eq", 2:"cmp/hs", 3:"cmp/ge", 4:"div1", 5:"dmulu.l",
                6:"cmp/hi", 7:"cmp/gt", 8:"sub", 0xA:"subc", 0xB:"subv",
                0xC:"add", 0xD:"dmuls.l", 0xE:"addc", 0xF:"addv"}
        if sub in ops3:
            mnemonic = "%s  R%d,R%d" % (ops3[sub], m_reg, n_reg)
        else:
            mnemonic = ".word  0x%04X" % op
    elif top == 0x4:
        low8 = op & 0xFF
        if low8 == 0x22:
            mnemonic = "sts.l  PR,@-R%d" % n_reg
        elif low8 == 0x26:
            mnemonic = "lds.l  @R%d+,PR" % n_reg
        elif low8 == 0x0B:
            mnemonic = "jsr    @R%d" % n_reg
            comment = "; call via R%d" % n_reg
        elif low8 == 0x2B:
            mnemonic = "jmp    @R%d" % n_reg
            comment = "; jump via R%d" % n_reg
        elif low8 == 0x15:
            mnemonic = "cmp/pl R%d" % n_reg
        elif low8 == 0x11:
            mnemonic = "cmp/pz R%d" % n_reg
        elif low8 == 0x10:
            mnemonic = "dt     R%d" % n_reg
        elif low8 == 0x00:
            mnemonic = "shll   R%d" % n_reg
        elif low8 == 0x01:
            mnemonic = "shlr   R%d" % n_reg
        elif low8 == 0x08:
            mnemonic = "shll2  R%d" % n_reg
        elif low8 == 0x09:
            mnemonic = "shlr2  R%d" % n_reg
        elif low8 == 0x18:
            mnemonic = "shll8  R%d" % n_reg
        elif low8 == 0x19:
            mnemonic = "shlr8  R%d" % n_reg
        elif low8 == 0x28:
            mnemonic = "shll16 R%d" % n_reg
        elif low8 == 0x29:
            mnemonic = "shlr16 R%d" % n_reg
        elif low8 == 0x20:
            mnemonic = "shal   R%d" % n_reg
        elif low8 == 0x21:
            mnemonic = "shar   R%d" % n_reg
        elif low8 == 0x0A:
            mnemonic = "lds    R%d,MACH" % n_reg
        elif low8 == 0x1A:
            mnemonic = "lds    R%d,MACL" % n_reg
        elif low8 == 0x2A:
            mnemonic = "lds    R%d,PR" % n_reg
        elif low8 == 0x1E:
            mnemonic = "ldc    R%d,GBR" % n_reg
        elif low8 == 0x13:
            mnemonic = "stc.l  GBR,@-R%d" % n_reg
        elif low8 == 0x17:
            mnemonic = "ldc.l  @R%d+,GBR" % n_reg
        else:
            lo1 = d4
            if lo1 == 0xC:
                mnemonic = "shad   R%d,R%d" % (m_reg, n_reg)
            elif lo1 == 0xD:
                mnemonic = "shld   R%d,R%d" % (m_reg, n_reg)
            elif lo1 == 0xF:
                mnemonic = "mac.w  @R%d+,@R%d+" % (m_reg, n_reg)
            else:
                mnemonic = ".word  0x%04X" % op
    elif top == 0x5:
        disp = d4 * 4
        mnemonic = "mov.l  @(%d,R%d),R%d" % (disp, m_reg, n_reg)
    elif top == 0x6:
        sub = d4
        if sub == 0:
            mnemonic = "mov.b  @R%d,R%d" % (m_reg, n_reg)
        elif sub == 1:
            mnemonic = "mov.w  @R%d,R%d" % (m_reg, n_reg)
        elif sub == 2:
            mnemonic = "mov.l  @R%d,R%d" % (m_reg, n_reg)
        elif sub == 3:
            mnemonic = "mov    R%d,R%d" % (m_reg, n_reg)
        elif sub == 4:
            mnemonic = "mov.b  @R%d+,R%d" % (m_reg, n_reg)
        elif sub == 5:
            mnemonic = "mov.w  @R%d+,R%d" % (m_reg, n_reg)
        elif sub == 6:
            mnemonic = "mov.l  @R%d+,R%d" % (m_reg, n_reg)
        elif sub == 7:
            mnemonic = "not    R%d,R%d" % (m_reg, n_reg)
        elif sub == 8:
            mnemonic = "swap.b R%d,R%d" % (m_reg, n_reg)
        elif sub == 9:
            mnemonic = "swap.w R%d,R%d" % (m_reg, n_reg)
        elif sub == 0xB:
            mnemonic = "neg    R%d,R%d" % (m_reg, n_reg)
        elif sub == 0xC:
            mnemonic = "extu.b R%d,R%d" % (m_reg, n_reg)
        elif sub == 0xD:
            mnemonic = "extu.w R%d,R%d" % (m_reg, n_reg)
        elif sub == 0xE:
            mnemonic = "exts.b R%d,R%d" % (m_reg, n_reg)
        elif sub == 0xF:
            mnemonic = "exts.w R%d,R%d" % (m_reg, n_reg)
        else:
            mnemonic = ".word  0x%04X" % op
    elif top == 0x7:
        imm = read_s8(d8)
        mnemonic = "add    #%d,R%d" % (imm, n_reg)
    elif top == 0x8:
        sub = nibbles[1]
        if sub == 0x0:
            mnemonic = "mov.b  R0,@(%d,R%d)" % (d4, m_reg)
        elif sub == 0x1:
            mnemonic = "mov.w  R0,@(%d,R%d)" % (d4*2, m_reg)
        elif sub == 0x4:
            mnemonic = "mov.b  @(%d,R%d),R0" % (d4, m_reg)
        elif sub == 0x5:
            mnemonic = "mov.w  @(%d,R%d),R0" % (d4*2, m_reg)
        elif sub == 0x8:
            imm = read_s8(d8)
            mnemonic = "cmp/eq #%d,R0" % imm
        elif sub == 0x9:
            disp = read_s8(d8) * 2 + 4
            target = addr + disp
            mnemonic = "bt     0x%05X" % target
        elif sub == 0xB:
            disp = read_s8(d8) * 2 + 4
            target = addr + disp
            mnemonic = "bf     0x%05X" % target
        elif sub == 0xD:
            disp = read_s8(d8) * 2 + 4
            target = addr + disp
            mnemonic = "bt/s   0x%05X" % target
        elif sub == 0xF:
            disp = read_s8(d8) * 2 + 4
            target = addr + disp
            mnemonic = "bf/s   0x%05X" % target
        else:
            mnemonic = ".word  0x%04X" % op
    elif top == 0x9:
        disp = d8 * 2
        pool_addr = addr + 4 + disp
        val = read_u16(pool_addr) if pool_addr+1 < ROM_SIZE else 0
        mnemonic = "mov.w  @(0x%05X,PC),R%d" % (pool_addr, n_reg)
        comment = "; R%d = 0x%04X" % (n_reg, val)
    elif top == 0xA:
        disp12 = op & 0xFFF
        target = addr + 4 + sign12(disp12) * 2
        mnemonic = "bra    0x%05X" % target
    elif top == 0xB:
        disp12 = op & 0xFFF
        target = addr + 4 + sign12(disp12) * 2
        mnemonic = "bsr    0x%05X" % target
        comment = "; call 0x%05X" % target
    elif top == 0xC:
        sub = nibbles[1]
        if sub == 0x0:
            mnemonic = "mov.b  R0,@(0x%02X,GBR)" % d8
            comment = "; [0x%08X]" % (GBR + d8)
        elif sub == 0x1:
            mnemonic = "mov.w  R0,@(0x%03X,GBR)" % (d8*2)
            comment = "; [0x%08X]" % (GBR + d8*2)
        elif sub == 0x2:
            mnemonic = "mov.l  R0,@(0x%03X,GBR)" % (d8*4)
            comment = "; [0x%08X]" % (GBR + d8*4)
        elif sub == 0x4:
            mnemonic = "mov.b  @(0x%02X,GBR),R0" % d8
            comment = "; R0=[0x%08X]" % (GBR + d8)
        elif sub == 0x5:
            mnemonic = "mov.w  @(0x%03X,GBR),R0" % (d8*2)
            comment = "; R0=[0x%08X]" % (GBR + d8*2)
        elif sub == 0x6:
            mnemonic = "mov.l  @(0x%03X,GBR),R0" % (d8*4)
            comment = "; R0=[0x%08X]" % (GBR + d8*4)
        elif sub == 0x7:
            disp = d8 * 4
            pool_addr = ((addr + 4) & ~3) + disp
            val = read_u32(pool_addr) if pool_addr+3 < ROM_SIZE else 0
            mnemonic = "mova   @(0x%05X,PC),R0" % pool_addr
            comment = "; R0=0x%05X" % pool_addr
        elif sub == 0x8:
            mnemonic = "tst    #0x%02X,R0" % d8
        elif sub == 0x9:
            mnemonic = "and    #0x%02X,R0" % d8
        elif sub == 0xA:
            mnemonic = "xor    #0x%02X,R0" % d8
        elif sub == 0xB:
            mnemonic = "or     #0x%02X,R0" % d8
        else:
            mnemonic = ".word  0x%04X" % op
    elif top == 0xD:
        disp = d8 * 4
        pool_addr = ((addr + 4) & ~3) + disp
        if pool_addr + 3 < ROM_SIZE:
            val = read_u32(pool_addr)
            mnemonic = "mov.l  @(0x%05X,PC),R%d" % (pool_addr, n_reg)
            if 0xFFFF0000 <= val <= 0xFFFFFFFF:
                comment = "; R%d=0x%08X (RAM)" % (n_reg, val)
            elif val < 0x50000:
                comment = "; R%d=0x%08X (ROM)" % (n_reg, val)
            elif 0x000A0000 <= val <= 0x000FFFFF:
                fv = read_float_at(val)
                comment = "; R%d=0x%08X (CAL, float=%s)" % (n_reg, val, fv)
            else:
                fv = read_float_at(pool_addr)
                if fv is not None and abs(fv) < 1e15 and fv != 0:
                    comment = "; R%d=0x%08X (const, float=%s)" % (n_reg, val, fv)
                else:
                    comment = "; R%d=0x%08X (const)" % (n_reg, val)
        else:
            mnemonic = "mov.l  @(?,PC),R%d" % n_reg
    elif top == 0xE:
        imm = read_s8(d8)
        mnemonic = "mov    #%d,R%d" % (imm, n_reg)
        comment = "; R%d=%d" % (n_reg, imm)
    elif top == 0xF:
        sub = d4
        fn = n_reg
        fm = m_reg
        if sub == 0x0:
            mnemonic = "fadd   FR%d,FR%d" % (fm, fn)
        elif sub == 0x1:
            mnemonic = "fsub   FR%d,FR%d" % (fm, fn)
        elif sub == 0x2:
            mnemonic = "fmul   FR%d,FR%d" % (fm, fn)
        elif sub == 0x3:
            mnemonic = "fdiv   FR%d,FR%d" % (fm, fn)
        elif sub == 0x4:
            mnemonic = "fcmp/eq FR%d,FR%d" % (fm, fn)
        elif sub == 0x5:
            mnemonic = "fcmp/gt FR%d,FR%d" % (fm, fn)
        elif sub == 0x6:
            mnemonic = "fmov.s @(R0,R%d),FR%d" % (m_reg, fn)
        elif sub == 0x7:
            mnemonic = "fmov.s FR%d,@(R0,R%d)" % (fm, fn)
        elif sub == 0x8:
            mnemonic = "fmov.s @R%d,FR%d" % (m_reg, fn)
        elif sub == 0x9:
            mnemonic = "fmov.s @R%d+,FR%d" % (m_reg, fn)
        elif sub == 0xA:
            mnemonic = "fmov.s FR%d,@R%d" % (fm, fn)
        elif sub == 0xB:
            mnemonic = "fmov.s FR%d,@-R%d" % (fm, fn)
        elif sub == 0xC:
            mnemonic = "fmov   FR%d,FR%d" % (fm, fn)
        elif sub == 0xD:
            if fm == 0x0:
                mnemonic = "fsts   FPUL,FR%d" % fn
            elif fm == 0x1:
                mnemonic = "flds   FR%d,FPUL" % fn
            elif fm == 0x2:
                mnemonic = "float  FPUL,FR%d" % fn
            elif fm == 0x3:
                mnemonic = "ftrc   FR%d,FPUL" % fn
            elif fm == 0x4:
                mnemonic = "fneg   FR%d" % fn
            elif fm == 0x5:
                mnemonic = "fabs   FR%d" % fn
            elif fm == 0x6:
                mnemonic = "fsqrt  FR%d" % fn
            elif fm == 0x8:
                mnemonic = "fldi0  FR%d" % fn
            elif fm == 0x9:
                mnemonic = "fldi1  FR%d" % fn
            elif fm == 0xA:
                mnemonic = "lds    R%d,FPUL" % n_reg
            else:
                mnemonic = ".word  0x%04X" % op
        elif sub == 0xE:
            mnemonic = "fmac   FR0,FR%d,FR%d" % (fm, fn)
        else:
            mnemonic = ".word  0x%04X" % op

    if not mnemonic:
        mnemonic = ".word  0x%04X" % op
    return op, mnemonic, comment


def classify_addr(v):
    if 0xFFFF0000 <= v <= 0xFFFFFFFF:
        return "RAM"
    elif v < 0x50000:
        return "ROM"
    elif 0xA0000 <= v < 0x100000:
        return "CAL"
    else:
        return ""

def disasm_word(addr):
    """Quick single-instruction disassembler, returns string."""
    op = read_u16(addr)
    top = (op >> 12) & 0xF
    n = (op >> 8) & 0xF
    m = (op >> 4) & 0xF
    d8 = op & 0xFF
    d4 = op & 0xF

    if op == 0x000B: return "rts"
    if op == 0x0009: return "nop"
    if op == 0x4F22: return "sts.l PR,@-R15"
    if op == 0x4F26: return "lds.l @R15+,PR"

    if top == 0xD:
        disp = d8 * 4
        pool = ((addr + 4) & ~3) + disp
        v = read_u32(pool)
        cls = classify_addr(v)
        if cls == "CAL":
            fv = read_float_at(v)
            return "mov.l @(pool_%05X,PC),R%d  ; 0x%08X (CAL->f=%g)" % (pool, n, v, fv)
        elif cls == "RAM":
            return "mov.l @(pool_%05X,PC),R%d  ; 0x%08X (RAM)" % (pool, n, v)
        elif cls == "ROM":
            return "mov.l @(pool_%05X,PC),R%d  ; 0x%08X (ROM)" % (pool, n, v)
        else:
            fv = read_float_at(pool)
            if fv is not None and 1e-10 < abs(fv) < 1e10:
                return "mov.l @(pool_%05X,PC),R%d  ; 0x%08X (f=%g)" % (pool, n, v, fv)
            return "mov.l @(pool_%05X,PC),R%d  ; 0x%08X" % (pool, n, v)

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
        if sub == 0x7: return "fmov.s FR%d,@(R0,R%d)" % (fm, fn)
        if sub == 0x8: return "fmov.s @R%d,FR%d" % (fm, fn)
        if sub == 0x9: return "fmov.s @R%d+,FR%d" % (fm, fn)
        if sub == 0xA: return "fmov.s FR%d,@R%d" % (fm, fn)
        if sub == 0xB: return "fmov.s FR%d,@-R%d" % (fm, fn)
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
        return ".word 0x%04X" % op

    if top == 0x8:
        sub = n
        def branch_target(d):
            return addr + (d if d < 128 else d-256)*2 + 4
        if sub == 0x9: return "bt 0x%05X" % branch_target(d8)
        if sub == 0xB: return "bf 0x%05X" % branch_target(d8)
        if sub == 0xD: return "bt/s 0x%05X" % branch_target(d8)
        if sub == 0xF: return "bf/s 0x%05X" % branch_target(d8)
        if sub == 0x8: return "cmp/eq #%d,R0" % (d8 if d8 < 128 else d8-256)
        if sub == 0x0: return "mov.b R0,@(%d,R%d)" % (d4, m)
        if sub == 0x4: return "mov.b @(%d,R%d),R0" % (d4, m)
        if sub == 0x5: return "mov.w @(%d,R%d),R0" % (d4*2, m)
        return ".word 0x%04X" % op

    if top == 0x3:
        sub = d4
        ops3 = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",4:"div1",5:"dmulu.l",
                6:"cmp/hi",7:"cmp/gt",8:"sub",0xA:"subc",0xB:"subv",
                0xC:"add",0xD:"dmuls.l",0xE:"addc",0xF:"addv"}
        return "%s R%d,R%d" % (ops3.get(sub, ".word 0x%04X" % op), m, n)

    if top == 0x4:
        low8 = op & 0xFF
        if low8 == 0x22: return "sts.l PR,@-R%d" % n
        if low8 == 0x26: return "lds.l @R%d+,PR" % n
        if low8 == 0x13: return "stc.l GBR,@-R%d" % n
        if low8 == 0x17: return "ldc.l @R%d+,GBR" % n
        if low8 == 0x1E: return "ldc R%d,GBR" % n
        if low8 == 0x0B: return "jsr @R%d" % n
        if low8 == 0x2B: return "jmp @R%d" % n
        if low8 == 0x15: return "cmp/pl R%d" % n
        if low8 == 0x11: return "cmp/pz R%d" % n
        if low8 == 0x10: return "dt R%d" % n
        if low8 == 0x2A: return "lds R%d,PR" % n
        if low8 == 0x0A: return "lds R%d,MACH" % n
        if low8 == 0x1A: return "lds R%d,MACL" % n
        if low8 == 0x09: return "shlr2 R%d" % n
        if low8 == 0x19: return "shlr8 R%d" % n
        if low8 == 0x29: return "shlr16 R%d" % n
        if low8 == 0x08: return "shll2 R%d" % n
        if low8 == 0x18: return "shll8 R%d" % n
        if low8 == 0x28: return "shll16 R%d" % n
        if low8 == 0x01: return "shlr R%d" % n
        if low8 == 0x00: return "shll R%d" % n
        if low8 == 0x21: return "shar R%d" % n
        if low8 == 0x20: return "shal R%d" % n
        return ".word 0x%04X" % op

    if top == 0x6:
        sub = d4
        if sub == 0: return "mov.b @R%d,R%d" % (m, n)
        if sub == 1: return "mov.w @R%d,R%d" % (m, n)
        if sub == 2: return "mov.l @R%d,R%d" % (m, n)
        if sub == 3: return "mov R%d,R%d" % (m, n)
        if sub == 4: return "mov.b @R%d+,R%d" % (m, n)
        if sub == 5: return "mov.w @R%d+,R%d" % (m, n)
        if sub == 6: return "mov.l @R%d+,R%d" % (m, n)
        if sub == 7: return "not R%d,R%d" % (m, n)
        if sub == 8: return "swap.b R%d,R%d" % (m, n)
        if sub == 9: return "swap.w R%d,R%d" % (m, n)
        if sub == 0xA: return "negc R%d,R%d" % (m, n)
        if sub == 0xB: return "neg R%d,R%d" % (m, n)
        if sub == 0xC: return "extu.b R%d,R%d" % (m, n)
        if sub == 0xD: return "extu.w R%d,R%d" % (m, n)
        if sub == 0xE: return "exts.b R%d,R%d" % (m, n)
        if sub == 0xF: return "exts.w R%d,R%d" % (m, n)
        return ".word 0x%04X" % op

    if top == 0x7:
        imm = d8 if d8 < 128 else d8-256
        return "add #%d,R%d" % (imm, n)

    if top == 0xE:
        imm = d8 if d8 < 128 else d8-256
        return "mov #%d,R%d" % (imm, n)

    if top == 0x5:
        disp = d4 * 4
        return "mov.l @(%d,R%d),R%d" % (disp, m, n)

    if top == 0x1:
        disp = d4 * 4
        return "mov.l R%d,@(%d,R%d)" % (m, disp, n)

    if top == 0x2:
        sub = d4
        if sub == 0: return "mov.b R%d,@R%d" % (m, n)
        if sub == 1: return "mov.w R%d,@R%d" % (m, n)
        if sub == 2: return "mov.l R%d,@R%d" % (m, n)
        if sub == 4: return "mov.b R%d,@-R%d" % (m, n)
        if sub == 5: return "mov.w R%d,@-R%d" % (m, n)
        if sub == 6: return "mov.l R%d,@-R%d" % (m, n)
        if sub == 7: return "div0s R%d,R%d" % (m, n)
        if sub == 8: return "tst R%d,R%d" % (m, n)
        if sub == 9: return "and R%d,R%d" % (m, n)
        if sub == 0xA: return "xor R%d,R%d" % (m, n)
        if sub == 0xB: return "or R%d,R%d" % (m, n)
        if sub == 0xE: return "mulu.w R%d,R%d" % (m, n)
        if sub == 0xF: return "muls.w R%d,R%d" % (m, n)
        return ".word 0x%04X" % op

    if top == 0x0:
        sub = d4
        if sub == 4: return "mov.b R%d,@(R0,R%d)" % (m, n)
        if sub == 5: return "mov.w R%d,@(R0,R%d)" % (m, n)
        if sub == 6: return "mov.l R%d,@(R0,R%d)" % (m, n)
        if sub == 0xC: return "mov.b @(R0,R%d),R%d" % (m, n)
        if sub == 0xD: return "mov.w @(R0,R%d),R%d" % (m, n)
        if sub == 0xE: return "mov.l @(R0,R%d),R%d" % (m, n)
        if sub == 7: return "mul.l R%d,R%d" % (m, n)
        if sub == 2 and m == 1: return "stc GBR,R%d" % n
        if sub == 0xA and m == 2: return "sts PR,R%d" % n
        if sub == 0xA and m == 0: return "sts MACH,R%d" % n
        if sub == 0xA and m == 1: return "sts MACL,R%d" % n
        if sub == 3: return "bsrf R%d" % n
        return ".word 0x%04X" % op

    if top == 0xA:
        disp12 = op & 0xFFF
        disp12 = disp12 if disp12 < 2048 else disp12-4096
        return "bra 0x%05X" % (addr+4+disp12*2)

    if top == 0xB:
        disp12 = op & 0xFFF
        disp12 = disp12 if disp12 < 2048 else disp12-4096
        target = addr+4+disp12*2
        return "bsr 0x%05X" % target

    if top == 0xC:
        sub = n
        GBR_BASE = 0xFFFF7450
        if sub == 0: return "mov.b R0,@(0x%02X,GBR)  ; [0x%08X]" % (d8, GBR_BASE+d8)
        if sub == 1: return "mov.w R0,@(0x%03X,GBR)  ; [0x%08X]" % (d8*2, GBR_BASE+d8*2)
        if sub == 2: return "mov.l R0,@(0x%03X,GBR)  ; [0x%08X]" % (d8*4, GBR_BASE+d8*4)
        if sub == 4: return "mov.b @(0x%02X,GBR),R0  ; [0x%08X]" % (d8, GBR_BASE+d8)
        if sub == 5: return "mov.w @(0x%03X,GBR),R0  ; [0x%08X]" % (d8*2, GBR_BASE+d8*2)
        if sub == 6: return "mov.l @(0x%03X,GBR),R0  ; [0x%08X]" % (d8*4, GBR_BASE+d8*4)
        if sub == 7:
            disp = d8*4
            pool = ((addr+4) & ~3) + disp
            return "mova @(pool_%05X,PC),R0" % pool
        if sub == 8: return "tst #0x%02X,R0" % d8
        if sub == 9: return "and #0x%02X,R0" % d8
        if sub == 0xA: return "xor #0x%02X,R0" % d8
        if sub == 0xB: return "or #0x%02X,R0" % d8
        return ".word 0x%04X" % op

    if top == 0x9:
        disp = d8 * 2
        pool = addr + 4 + disp
        if pool+1 < ROM_SIZE:
            v = struct.unpack(">H", rom[pool:pool+2])[0]
            return "mov.w @(pool_%05X,PC),R%d  ; 0x%04X" % (pool, n, v)
        return "mov.w @(?,PC),R%d" % n

    return ".word 0x%04X" % op


def print_range(start, end, mark_addr=None):
    addr = start
    while addr < end and addr < ROM_SIZE:
        op, mn, comment = disasm_one(addr)
        marker = ""
        if addr == mark_addr:
            marker = "  <<<<< WRITE to FFFF79A0"
        line = "  %05X:  %04X    %-40s" % (addr, op, mn)
        if comment:
            line = line + " " + comment
        if marker:
            line = line + marker
        print(line)
        addr += 2


print("=" * 110)
print("DISASSEMBLY: ROM 0x36900 - 0x36AC0")
print("Context: fmov.s FR0,@R2 at 0x36976 writes to FFFF79A0 (R2=FFFF79A0 loaded at 0x36970)")
print("=" * 110)
print()
print_range(0x36900, 0x36AC0, mark_addr=0x36976)

print()
print("=" * 110)
print("LITERAL POOL after function (0x36A74 onward)")
print("=" * 110)
for pool_addr in range(0x36A60, 0x36AB0, 4):
    if pool_addr + 3 < ROM_SIZE:
        val = read_u32(pool_addr)
        fv = read_float_at(pool_addr)
        cls = "?"
        if 0xFFFF0000 <= val <= 0xFFFFFFFF:
            cls = "RAM"
        elif val < 0x50000:
            cls = "ROM"
        elif 0x000A0000 <= val <= 0x000FFFFF:
            cls = "CAL"
        extra = ""
        if cls == "CAL":
            fv2 = read_float_at(val)
            extra = "  (CAL -> float at 0x%05X = %s)" % (val, fv2)
        elif fv is not None and abs(fv) < 1e10 and fv != 0:
            extra = "  (float = %s)" % fv
        print("  %05X:  %08X  %-5s%s" % (pool_addr, val, cls, extra))

print()
print("=" * 110)
print("CALLER DISASSEMBLY: 0x35FC0 - 0x36080 (bsr to 0x36962 at 0x36016 and 0x36064)")
print("=" * 110)
print()
print_range(0x35FC0, 0x36080)

print()
print("=" * 110)
print("TABLE DESCRIPTOR at 0xAD0DC (passed as R4 to table lookup function 0xBE830)")
print("=" * 110)
desc = 0xAD0DC
print("  Count  (word @+0): 0x%04X = %d" % (struct.unpack('>H', rom[desc:desc+2])[0],
                                               struct.unpack('>H', rom[desc:desc+2])[0]))
print("  Format (byte @+2): 0x%02X = %d" % (rom[desc+2], rom[desc+2]))
print("  X-axis ptr (@+4):  0x%08X" % read_u32(desc+4))
print("  Y-axis ptr (@+8):  0x%08X" % read_u32(desc+8))
print("  Extra  (@+12):     0x%08X = float %g" % (read_u32(desc+12), read_float_at(desc+12)))
print()

x_ptr = read_u32(desc+4)
y_ptr = read_u32(desc+8)
count = struct.unpack('>H', rom[desc:desc+2])[0]

print("  X-axis (coolant temp breakpoints, %d floats at 0x%05X):" % (count, x_ptr))
for i in range(count):
    a = x_ptr + i*4
    fv = read_float_at(a)
    print("    X[%2d] @%05X = %g" % (i, a, fv))

print()
print("  Y-axis (%d floats at 0x%05X) -- decay coefficient per coolant temp:" % (count, y_ptr))
for i in range(count):
    a = y_ptr + i*4
    v = read_u32(a)
    fv = read_float_at(a)
    print("    Y[%2d] @%05X = 0x%08X  float=%-15g  (written to FFFF79A0)" % (i, a, v, fv))

print()
print("=" * 110)
print("INIT FUNCTION: ROM 0x36962 - 0x36978 (the actual write path)")
print("=" * 110)
print()
print_range(0x36962, 0x36978, mark_addr=0x36976)
print()
print("Summary:")
print("  0x36964: R2 = 0xFFFF6350 (load coolant temp float into FR4 via fmov.s @R2,FR4)")
print("  0x36968: R4 = 0x000AD0DC (table descriptor address = argument to table lookup)")
print("  0x3696A: R2 = 0x000BE830 (table interpolation function pointer)")
print("  0x3696C: jsr @R2          (call table lookup: FR4=input, R4=desc -> FR0=result)")
print("  0x36970: R2 = 0xFFFF79A0  (target RAM address)")
print("  0x36976: fmov.s FR0,@R2   (WRITE: FFFF79A0 = table_lookup(coolant_temp))")
print()
print("The Y-axis values at 0x%05X are the calibration constants for FFFF79A0." % y_ptr)
print("Changing Y-axis values changes the decay coefficient (and thus CL->OL transition speed).")
