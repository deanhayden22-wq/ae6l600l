#!/usr/bin/env python3
"""
Ignition Timing Subsystem Disassembly - AE5L600L ROM
Disassembles all key ignition timing functions with SH-2A ISA decoder.
Output: ASCII only, no unicode characters.
"""
import struct, sys, os

# Force UTF-8 stdout
sys.stdout.reconfigure(encoding='utf-8')

ROM_PATH = 'C:/Users/Dean/Documents/GitHub/ae6l600l/rom/ae5l600l.bin'
OUT_PATH = 'C:/Users/Dean/Documents/GitHub/ae6l600l/disassembly/analysis/ignition_timing_raw.txt'

with open(ROM_PATH, 'rb') as f:
    rom = f.read()

GBR = 0xFFFF7450

def read_u16(addr):
    return struct.unpack('>H', rom[addr:addr+2])[0]

def read_u32(addr):
    return struct.unpack('>I', rom[addr:addr+4])[0]

def read_float(addr):
    return struct.unpack('>f', rom[addr:addr+4])[0]

def read_s8(val):
    return val - 256 if val > 127 else val

def rn(n):
    return "R%d" % n

def frn(n):
    return "FR%d" % n

def addr_comment(val):
    """Generate a comment for a literal pool value."""
    if 0xFFFF0000 <= val <= 0xFFFFFFFF:
        return "  ; =0x%08X (RAM)" % val
    elif 0x000D0000 <= val <= 0x000FFFFF:
        comment = "  ; =0x%08X (cal)" % val
        try:
            if val + 3 < len(rom):
                fv = read_float(val)
                comment += " val=%.6g" % fv
        except:
            pass
        return comment
    elif val < 0x00100000:
        return "  ; =0x%08X (ROM)" % val
    else:
        return "  ; =0x%08X" % val

def disassemble_range(start, max_insns):
    """Disassemble starting at 'start' for up to max_insns instructions.
    Returns list of (addr, opcode, mnemonic, comment) tuples.
    Also collects RAM refs, ROM refs, CAL refs."""
    lines = []
    ram_refs = set()
    rom_refs = set()
    cal_refs = set()

    addr = start
    count = 0
    found_rts = False
    # after rts we execute one more delay slot instruction
    rts_countdown = -1

    while count < max_insns:
        if addr >= len(rom) - 1:
            break

        op = read_u16(addr)
        nib = [(op >> 12) & 0xF, (op >> 8) & 0xF, (op >> 4) & 0xF, op & 0xF]
        n_reg = nib[1]
        m_reg = nib[2]
        d8 = op & 0xFF
        d4 = op & 0xF
        top = nib[0]

        mnemonic = ""
        comment = ""

        # --- Decode ---
        if op == 0x0009:
            mnemonic = "nop"
        elif op == 0x000B:
            mnemonic = "rts"
            rts_countdown = 1  # one more insn (delay slot)
        elif op == 0x0019:
            mnemonic = "div0u"
        elif op == 0x001B:
            mnemonic = "sleep"
        elif op == 0x0008:
            mnemonic = "clrt"
        elif op == 0x0018:
            mnemonic = "sett"
        elif op == 0x0028:
            mnemonic = "clrmac"
        elif op == 0x0048:
            mnemonic = "clrs"
        elif op == 0x0058:
            mnemonic = "sets"
        elif top == 0x0:
            sub = nib[3]
            if sub == 0x2:
                if m_reg == 0:
                    mnemonic = "stc    SR,%s" % rn(n_reg)
                elif m_reg == 1:
                    mnemonic = "stc    GBR,%s" % rn(n_reg)
                elif m_reg == 2:
                    mnemonic = "stc    VBR,%s" % rn(n_reg)
                else:
                    mnemonic = ".word  0x%04X" % op
            elif sub == 0x3:
                if m_reg == 0:
                    mnemonic = "bsrf   %s" % rn(n_reg)
                elif m_reg == 2:
                    mnemonic = "braf   %s" % rn(n_reg)
                else:
                    mnemonic = ".word  0x%04X" % op
            elif sub == 0x4:
                mnemonic = "mov.b  %s,@(R0,%s)" % (rn(m_reg), rn(n_reg))
            elif sub == 0x5:
                mnemonic = "mov.w  %s,@(R0,%s)" % (rn(m_reg), rn(n_reg))
            elif sub == 0x6:
                mnemonic = "mov.l  %s,@(R0,%s)" % (rn(m_reg), rn(n_reg))
            elif sub == 0x7:
                mnemonic = "mul.l  %s,%s" % (rn(m_reg), rn(n_reg))
            elif sub == 0x8:
                if n_reg == 0 and m_reg == 0:
                    mnemonic = "clrt"
                else:
                    mnemonic = ".word  0x%04X" % op
            elif sub == 0xA:
                if m_reg == 0:
                    mnemonic = "sts    MACH,%s" % rn(n_reg)
                elif m_reg == 1:
                    mnemonic = "sts    MACL,%s" % rn(n_reg)
                elif m_reg == 2:
                    mnemonic = "sts    PR,%s" % rn(n_reg)
                elif m_reg == 5:
                    mnemonic = "sts    FPUL,%s" % rn(n_reg)
                elif m_reg == 6:
                    mnemonic = "sts    FPSCR,%s" % rn(n_reg)
                else:
                    mnemonic = ".word  0x%04X" % op
            elif sub == 0xB:
                mnemonic = "rts"
                rts_countdown = 1
            elif sub == 0xC:
                mnemonic = "mov.b  @(R0,%s),%s" % (rn(m_reg), rn(n_reg))
            elif sub == 0xD:
                mnemonic = "mov.w  @(R0,%s),%s" % (rn(m_reg), rn(n_reg))
            elif sub == 0xE:
                mnemonic = "mov.l  @(R0,%s),%s" % (rn(m_reg), rn(n_reg))
            elif sub == 0xF:
                mnemonic = "mac.l  @%s+,@%s+" % (rn(m_reg), rn(n_reg))
            else:
                mnemonic = ".word  0x%04X" % op

        elif top == 0x1:
            disp = d4 * 4
            mnemonic = "mov.l  %s,@(%d,%s)" % (rn(m_reg), disp, rn(n_reg))
            if n_reg == 15:
                comment = "  ; stack[0x%02X]" % disp

        elif top == 0x2:
            sub = nib[3]
            if sub == 0:
                mnemonic = "mov.b  %s,@%s" % (rn(m_reg), rn(n_reg))
            elif sub == 1:
                mnemonic = "mov.w  %s,@%s" % (rn(m_reg), rn(n_reg))
            elif sub == 2:
                mnemonic = "mov.l  %s,@%s" % (rn(m_reg), rn(n_reg))
            elif sub == 4:
                mnemonic = "mov.b  %s,@-%s" % (rn(m_reg), rn(n_reg))
            elif sub == 5:
                mnemonic = "mov.w  %s,@-%s" % (rn(m_reg), rn(n_reg))
            elif sub == 6:
                mnemonic = "mov.l  %s,@-%s" % (rn(m_reg), rn(n_reg))
            elif sub == 7:
                mnemonic = "div0s  %s,%s" % (rn(m_reg), rn(n_reg))
            elif sub == 8:
                mnemonic = "tst    %s,%s" % (rn(m_reg), rn(n_reg))
            elif sub == 9:
                mnemonic = "and    %s,%s" % (rn(m_reg), rn(n_reg))
            elif sub == 0xA:
                mnemonic = "xor    %s,%s" % (rn(m_reg), rn(n_reg))
            elif sub == 0xB:
                mnemonic = "or     %s,%s" % (rn(m_reg), rn(n_reg))
            elif sub == 0xD:
                mnemonic = "xtrct  %s,%s" % (rn(m_reg), rn(n_reg))
            else:
                mnemonic = ".word  0x%04X" % op

        elif top == 0x3:
            sub = nib[3]
            ops3 = {
                0x0: "cmp/eq", 0x2: "cmp/hs", 0x3: "cmp/ge", 0x4: "div1",
                0x5: "dmulu.l", 0x6: "cmp/hi", 0x7: "cmp/gt", 0x8: "sub",
                0x9: "???3x9", 0xA: "subc", 0xB: "subv", 0xC: "add",
                0xD: "dmuls.l", 0xE: "addc", 0xF: "addv"
            }
            if sub in ops3:
                mnemonic = "%-7s%s,%s" % (ops3[sub], rn(m_reg), rn(n_reg))
            else:
                mnemonic = ".word  0x%04X" % op

        elif top == 0x4:
            low8 = op & 0xFF
            if low8 == 0x00:
                mnemonic = "shll   %s" % rn(n_reg)
            elif low8 == 0x01:
                mnemonic = "shlr   %s" % rn(n_reg)
            elif low8 == 0x02:
                mnemonic = "sts.l  MACH,@-%s" % rn(n_reg)
            elif low8 == 0x04:
                mnemonic = "rotl   %s" % rn(n_reg)
            elif low8 == 0x05:
                mnemonic = "rotr   %s" % rn(n_reg)
            elif low8 == 0x06:
                mnemonic = "lds.l  @%s+,MACH" % rn(n_reg)
            elif low8 == 0x08:
                mnemonic = "shll2  %s" % rn(n_reg)
            elif low8 == 0x09:
                mnemonic = "shlr2  %s" % rn(n_reg)
            elif low8 == 0x0A:
                mnemonic = "lds    %s,MACH" % rn(n_reg)
            elif low8 == 0x0B:
                mnemonic = "jsr    @%s" % rn(n_reg)
            elif low8 == 0x0E:
                mnemonic = "ldc    %s,SR" % rn(n_reg)
            elif low8 == 0x10:
                mnemonic = "dt     %s" % rn(n_reg)
            elif low8 == 0x11:
                mnemonic = "cmp/pz %s" % rn(n_reg)
            elif low8 == 0x12:
                mnemonic = "sts.l  MACL,@-%s" % rn(n_reg)
            elif low8 == 0x13:
                mnemonic = "stc.l  GBR,@-%s" % rn(n_reg)
            elif low8 == 0x15:
                mnemonic = "cmp/pl %s" % rn(n_reg)
            elif low8 == 0x16:
                mnemonic = "lds.l  @%s+,MACL" % rn(n_reg)
            elif low8 == 0x17:
                mnemonic = "ldc.l  @%s+,GBR" % rn(n_reg)
            elif low8 == 0x18:
                mnemonic = "shll8  %s" % rn(n_reg)
            elif low8 == 0x19:
                mnemonic = "shlr8  %s" % rn(n_reg)
            elif low8 == 0x1A:
                mnemonic = "lds    %s,MACL" % rn(n_reg)
            elif low8 == 0x1B:
                mnemonic = "tas.b  @%s" % rn(n_reg)
            elif low8 == 0x1E:
                mnemonic = "ldc    %s,GBR" % rn(n_reg)
            elif low8 == 0x20:
                mnemonic = "shal   %s" % rn(n_reg)
            elif low8 == 0x21:
                mnemonic = "shar   %s" % rn(n_reg)
            elif low8 == 0x22:
                mnemonic = "sts.l  PR,@-%s" % rn(n_reg)
            elif low8 == 0x24:
                mnemonic = "rotcl  %s" % rn(n_reg)
            elif low8 == 0x25:
                mnemonic = "rotcr  %s" % rn(n_reg)
            elif low8 == 0x26:
                mnemonic = "lds.l  @%s+,PR" % rn(n_reg)
            elif low8 == 0x28:
                mnemonic = "shll16 %s" % rn(n_reg)
            elif low8 == 0x29:
                mnemonic = "shlr16 %s" % rn(n_reg)
            elif low8 == 0x2A:
                mnemonic = "lds    %s,PR" % rn(n_reg)
            elif low8 == 0x2B:
                mnemonic = "jmp    @%s" % rn(n_reg)
            elif low8 == 0x2E:
                mnemonic = "ldc    %s,VBR" % rn(n_reg)
            elif low8 == 0x52:
                mnemonic = "sts.l  FPUL,@-%s" % rn(n_reg)
            elif low8 == 0x56:
                mnemonic = "lds.l  @%s+,FPUL" % rn(n_reg)
            elif low8 == 0x5A:
                mnemonic = "lds    %s,FPUL" % rn(n_reg)
            elif low8 == 0x62:
                mnemonic = "sts.l  FPSCR,@-%s" % rn(n_reg)
            elif low8 == 0x66:
                mnemonic = "lds.l  @%s+,FPSCR" % rn(n_reg)
            elif low8 == 0x6A:
                mnemonic = "lds    %s,FPSCR" % rn(n_reg)
            elif (low8 & 0x0F) == 0x0F:
                mnemonic = "mac.w  @%s+,@%s+" % (rn(m_reg), rn(n_reg))
            else:
                mnemonic = ".word  0x%04X  ; 4xxx" % op

        elif top == 0x5:
            disp = d4 * 4
            mnemonic = "mov.l  @(%d,%s),%s" % (disp, rn(m_reg), rn(n_reg))

        elif top == 0x6:
            sub = nib[3]
            ops6 = {
                0x0: "mov.b  @%s,%s",
                0x1: "mov.w  @%s,%s",
                0x2: "mov.l  @%s,%s",
                0x3: "mov    %s,%s",
                0x4: "mov.b  @%s+,%s",
                0x5: "mov.w  @%s+,%s",
                0x6: "mov.l  @%s+,%s",
                0x7: "not    %s,%s",
                0x8: "swap.b %s,%s",
                0x9: "swap.w %s,%s",
                0xA: "negc   %s,%s",
                0xB: "neg    %s,%s",
                0xC: "extu.b %s,%s",
                0xD: "extu.w %s,%s",
                0xE: "exts.b %s,%s",
                0xF: "exts.w %s,%s",
            }
            if sub in ops6:
                mnemonic = ops6[sub] % (rn(m_reg), rn(n_reg))
            else:
                mnemonic = ".word  0x%04X" % op

        elif top == 0x7:
            imm = read_s8(d8)
            mnemonic = "add    #%d,%s" % (imm, rn(n_reg))
            if n_reg == 15:
                comment = "  ; SP += %d" % imm

        elif top == 0x8:
            sub = nib[1]
            if sub == 0x0:
                mnemonic = "mov.b  R0,@(%d,%s)" % (d4, rn(m_reg))
            elif sub == 0x1:
                mnemonic = "mov.w  R0,@(%d,%s)" % (d4 * 2, rn(m_reg))
            elif sub == 0x4:
                mnemonic = "mov.b  @(%d,%s),R0" % (d4, rn(m_reg))
            elif sub == 0x5:
                mnemonic = "mov.w  @(%d,%s),R0" % (d4 * 2, rn(m_reg))
            elif sub == 0x8:
                imm = read_s8(d8)
                mnemonic = "cmp/eq #%d,R0" % imm
            elif sub == 0x9:
                disp = read_s8(d8) * 2 + 4
                target = addr + disp
                mnemonic = "bt     0x%06X" % target
            elif sub == 0xB:
                disp = read_s8(d8) * 2 + 4
                target = addr + disp
                mnemonic = "bf     0x%06X" % target
            elif sub == 0xD:
                disp = read_s8(d8) * 2 + 4
                target = addr + disp
                mnemonic = "bt/s   0x%06X" % target
            elif sub == 0xF:
                disp = read_s8(d8) * 2 + 4
                target = addr + disp
                mnemonic = "bf/s   0x%06X" % target
            else:
                mnemonic = ".word  0x%04X" % op

        elif top == 0x9:
            disp = d8 * 2
            pool_addr = addr + 4 + disp
            if pool_addr + 1 < len(rom):
                val = read_u16(pool_addr)
                mnemonic = "mov.w  @(0x%06X),%s" % (pool_addr, rn(n_reg))
                comment = "  ; =#%d (0x%04X)" % (val, val)
            else:
                mnemonic = "mov.w  @(0x%06X),%s" % (pool_addr, rn(n_reg))

        elif top == 0xA:
            disp12 = op & 0xFFF
            if disp12 > 0x7FF:
                disp12 -= 0x1000
            target = addr + 4 + disp12 * 2
            mnemonic = "bra    0x%06X" % target

        elif top == 0xB:
            disp12 = op & 0xFFF
            if disp12 > 0x7FF:
                disp12 -= 0x1000
            target = addr + 4 + disp12 * 2
            mnemonic = "bsr    0x%06X" % target

        elif top == 0xC:
            sub = nib[1]
            if sub == 0x0:
                disp = d8
                gbr_addr = GBR + disp
                mnemonic = "mov.b  R0,@(0x%02X,GBR)" % disp
                comment = "  ; write [%08X]" % gbr_addr
            elif sub == 0x1:
                disp = d8 * 2
                gbr_addr = GBR + disp
                mnemonic = "mov.w  R0,@(0x%04X,GBR)" % disp
                comment = "  ; write [%08X]" % gbr_addr
            elif sub == 0x2:
                disp = d8 * 4
                gbr_addr = GBR + disp
                mnemonic = "mov.l  R0,@(0x%04X,GBR)" % disp
                comment = "  ; write [%08X]" % gbr_addr
            elif sub == 0x3:
                mnemonic = "trapa  #%d" % d8
            elif sub == 0x4:
                disp = d8
                gbr_addr = GBR + disp
                mnemonic = "mov.b  @(0x%02X,GBR),R0" % disp
                comment = "  ; read [%08X]" % gbr_addr
            elif sub == 0x5:
                disp = d8 * 2
                gbr_addr = GBR + disp
                mnemonic = "mov.w  @(0x%04X,GBR),R0" % disp
                comment = "  ; read [%08X]" % gbr_addr
            elif sub == 0x6:
                disp = d8 * 4
                gbr_addr = GBR + disp
                mnemonic = "mov.l  @(0x%04X,GBR),R0" % disp
                comment = "  ; read [%08X]" % gbr_addr
            elif sub == 0x7:
                disp = d8 * 4
                pool_addr = ((addr + 4) & ~3) + disp
                mnemonic = "mova   @(0x%06X),R0" % pool_addr
            elif sub == 0x8:
                mnemonic = "tst    #0x%02X,R0" % d8
            elif sub == 0x9:
                mnemonic = "and    #0x%02X,R0" % d8
            elif sub == 0xA:
                mnemonic = "xor    #0x%02X,R0" % d8
            elif sub == 0xB:
                mnemonic = "or     #0x%02X,R0" % d8
            elif sub == 0xC:
                mnemonic = "tst.b  #0x%02X,@(R0,GBR)" % d8
            elif sub == 0xD:
                mnemonic = "and.b  #0x%02X,@(R0,GBR)" % d8
            elif sub == 0xE:
                mnemonic = "xor.b  #0x%02X,@(R0,GBR)" % d8
            elif sub == 0xF:
                mnemonic = "or.b   #0x%02X,@(R0,GBR)" % d8
            else:
                mnemonic = ".word  0x%04X  ; Cxxx" % op

        elif top == 0xD:
            disp = d8 * 4
            pool_addr = ((addr + 4) & ~3) + disp
            if pool_addr + 3 < len(rom):
                val = read_u32(pool_addr)
                mnemonic = "mov.l  @(0x%06X),%s" % (pool_addr, rn(n_reg))
                comment = addr_comment(val)
                # Collect refs
                if 0xFFFF0000 <= val <= 0xFFFFFFFF:
                    ram_refs.add(val)
                elif 0x000D0000 <= val <= 0x000FFFFF:
                    cal_refs.add(val)
                elif val < 0x00100000:
                    rom_refs.add(val)
            else:
                mnemonic = "mov.l  @(0x%06X),%s" % (pool_addr, rn(n_reg))

        elif top == 0xE:
            imm = read_s8(d8)
            mnemonic = "mov    #%d,%s" % (imm, rn(n_reg))

        elif top == 0xF:
            sub = nib[3]
            fn = n_reg
            fm = m_reg
            if sub == 0x0:
                mnemonic = "fadd   %s,%s" % (frn(fm), frn(fn))
            elif sub == 0x1:
                mnemonic = "fsub   %s,%s" % (frn(fm), frn(fn))
            elif sub == 0x2:
                mnemonic = "fmul   %s,%s" % (frn(fm), frn(fn))
            elif sub == 0x3:
                mnemonic = "fdiv   %s,%s" % (frn(fm), frn(fn))
            elif sub == 0x4:
                mnemonic = "fcmp/eq %s,%s" % (frn(fm), frn(fn))
            elif sub == 0x5:
                mnemonic = "fcmp/gt %s,%s" % (frn(fm), frn(fn))
            elif sub == 0x6:
                mnemonic = "fmov.s @(R0,%s),%s" % (rn(m_reg), frn(fn))
            elif sub == 0x7:
                mnemonic = "fmov.s %s,@(R0,%s)" % (frn(fm), rn(n_reg))
            elif sub == 0x8:
                mnemonic = "fmov.s @%s,%s" % (rn(m_reg), frn(fn))
            elif sub == 0x9:
                mnemonic = "fmov.s @%s+,%s" % (rn(m_reg), frn(fn))
            elif sub == 0xA:
                mnemonic = "fmov.s %s,@%s" % (frn(fm), rn(n_reg))
            elif sub == 0xB:
                mnemonic = "fmov.s %s,@-%s" % (frn(fm), rn(n_reg))
            elif sub == 0xC:
                mnemonic = "fmov   %s,%s" % (frn(fm), frn(fn))
            elif sub == 0xD:
                if fm == 0x0:
                    mnemonic = "fsts   FPUL,%s" % frn(fn)
                elif fm == 0x1:
                    mnemonic = "flds   %s,FPUL" % frn(fn)
                elif fm == 0x2:
                    mnemonic = "float  FPUL,%s" % frn(fn)
                elif fm == 0x3:
                    mnemonic = "ftrc   %s,FPUL" % frn(fn)
                elif fm == 0x4:
                    mnemonic = "fneg   %s" % frn(fn)
                elif fm == 0x5:
                    mnemonic = "fabs   %s" % frn(fn)
                elif fm == 0x6:
                    mnemonic = "fsqrt  %s" % frn(fn)
                elif fm == 0x8:
                    mnemonic = "fldi0  %s" % frn(fn)
                elif fm == 0x9:
                    mnemonic = "fldi1  %s" % frn(fn)
                else:
                    mnemonic = ".word  0x%04X  ; FPU_xD" % op
            else:
                mnemonic = ".word  0x%04X  ; FPU" % op

        if not mnemonic:
            mnemonic = ".word  0x%04X" % op

        lines.append((addr, op, mnemonic, comment))
        addr += 2
        count += 1

        if rts_countdown > 0:
            rts_countdown -= 1
        elif rts_countdown == 0:
            break

    return lines, ram_refs, rom_refs, cal_refs


# ============================================================
# CALIBRATION REGIONS
# ============================================================
cal_regions = [
    ("task49 base advance cals",     0xD2A50, 0xD2A70),
    ("task30 base timing cals",      0xD2ADC, 0xD2AF4),
    ("task31/32 blend cals",         0xD2B10, 0xD2B20),
    ("task38/39/40/41 ign output cals", 0xD2CB0, 0xD2CD0),
    ("task42 timing comp cals",      0xD2CD4, 0xD2D00),
    ("task45-48 cals",               0xD2D10, 0xD2D50),
    ("task12/task00 cals",           0xD2D60, 0xD2DA4),
    ("task50 cals",                  0xD2974, 0xD2990),
    ("task36 cals",                  0xD2BF0, 0xD2C08),
]

# ============================================================
# FUNCTIONS TO DISASSEMBLE
# ============================================================
functions = [
    ("task30_base_timing",       0x3FCA2, 300),
    ("task49_base_advance",      0x3F00C, 300),
    ("task50_timing_blend_int",  0x3F368, 200),
    ("task48_final_timing",      0x4359C, 200),
    ("task00_timing_percyl",     0x44188, 150),
    ("task29_timing_percyl",     0x44296, 100),
    ("task38_ign_output",        0x42A78, 100),
    ("task42_timing_comp_b",     0x42F48, 200),
    ("task27_knock_timing",      0x46296, 150),
    ("task01_knock_timing_fb",   0x45970, 100),
]

# ============================================================
# Generate output
# ============================================================
out_lines = []

def emit(s=""):
    out_lines.append(s)

emit("=" * 78)
emit("AE5L600L Ignition Timing Subsystem - Raw Disassembly")
emit("=" * 78)
emit("")
emit("ROM: %s" % ROM_PATH)
emit("Generated by disasm_ignition_timing.py")
emit("")

# --- Part 1: Calibration Values ---
emit("=" * 78)
emit("PART 1: CALIBRATION VALUES (Big-Endian IEEE 754 Floats)")
emit("=" * 78)

for name, start, end in cal_regions:
    emit("")
    emit("-" * 60)
    emit("  %s  (0x%05X - 0x%05X)" % (name, start, end))
    emit("-" * 60)
    emit("  %-10s  %-12s  %s" % ("Address", "Raw Hex", "Float Value"))
    emit("  %-10s  %-12s  %s" % ("-------", "-------", "-----------"))
    a = start
    while a <= end:
        if a + 3 < len(rom):
            raw = read_u32(a)
            try:
                fv = read_float(a)
                emit("  0x%05X    0x%08X    %.6g" % (a, raw, fv))
            except:
                emit("  0x%05X    0x%08X    (decode error)" % (a, raw))
        a += 4

# --- Part 2: Function Disassembly ---
emit("")
emit("=" * 78)
emit("PART 2: FUNCTION DISASSEMBLY (SH-2A ISA)")
emit("=" * 78)

for func_name, func_addr, max_insns in functions:
    emit("")
    emit("=" * 78)
    emit("  FUNCTION: %s" % func_name)
    emit("  Address:  0x%06X" % func_addr)
    emit("  Max insns: %d" % max_insns)
    emit("=" * 78)
    emit("")

    lines, ram_refs, rom_refs, cal_refs = disassemble_range(func_addr, max_insns)

    for a, op, mn, cm in lines:
        emit("  %06X: %04X  %-40s%s" % (a, op, mn, cm))

    emit("")
    emit("  --- References Summary for %s ---" % func_name)

    if ram_refs:
        emit("  RAM addresses referenced:")
        for r in sorted(ram_refs):
            emit("    0x%08X" % r)
    else:
        emit("  RAM addresses referenced: (none)")

    if rom_refs:
        emit("  ROM/code addresses referenced:")
        for r in sorted(rom_refs):
            emit("    0x%08X" % r)
    else:
        emit("  ROM/code addresses referenced: (none)")

    if cal_refs:
        emit("  Calibration addresses referenced:")
        for r in sorted(cal_refs):
            try:
                fv = read_float(r)
                emit("    0x%08X  = %.6g" % (r, fv))
            except:
                emit("    0x%08X" % r)
    else:
        emit("  Calibration addresses referenced: (none)")

    emit("")

# --- Write output ---
os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
with open(OUT_PATH, 'w', encoding='utf-8') as f:
    for line in out_lines:
        f.write(line + "\n")

print("Output written to: %s" % OUT_PATH)
print("Total lines: %d" % len(out_lines))
