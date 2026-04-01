"""Disassemble task54 idle control and related subfunctions from ROM bytes."""
import struct
import sys

ROM_PATH = "disassembly/ghidra/AE5L600L Ghidra Export.bytes"

with open(ROM_PATH, "rb") as f:
    rom = f.read()

def read32(addr):
    return struct.unpack(">I", rom[addr:addr+4])[0]

def read16(addr):
    return struct.unpack(">H", rom[addr:addr+2])[0]

def read8(addr):
    return rom[addr]

def decode(hw, addr):
    n = (hw >> 8) & 0xF
    m = (hw >> 4) & 0xF

    if hw == 0x000B: return "rts"
    if hw == 0x0009: return "nop"
    if hw == 0x0019: return "div0u"
    if hw == 0x001B: return "sleep"
    if (hw & 0xF0FF) == 0x0029: return "movt    R%d" % n

    if (hw >> 12) == 0xD:
        disp = hw & 0xFF
        return "mov.l   @(0x%02X,PC),R%d" % (disp*4, n)
    if (hw >> 12) == 0x9:
        disp = hw & 0xFF
        return "mov.w   @(0x%02X,PC),R%d" % (disp*2, n)
    if (hw >> 12) == 0xE:
        imm = hw & 0xFF
        if imm & 0x80: imm -= 256
        return "mov     #%d,R%d" % (imm, n)
    if (hw >> 8) == 0xC4: return "mov.b   @(0x%02X,GBR),R0" % (hw & 0xFF)
    if (hw >> 8) == 0xC5: return "mov.w   @(0x%02X,GBR),R0" % ((hw & 0xFF)*2)
    if (hw >> 8) == 0xC6: return "mov.l   @(0x%02X,GBR),R0" % ((hw & 0xFF)*4)
    if (hw >> 8) == 0xC0: return "mov.b   R0,@(0x%02X,GBR)" % (hw & 0xFF)
    if (hw >> 8) == 0xC1: return "mov.w   R0,@(0x%02X,GBR)" % ((hw & 0xFF)*2)
    if (hw >> 8) == 0xC2: return "mov.l   R0,@(0x%02X,GBR)" % ((hw & 0xFF)*4)
    if (hw >> 8) == 0xCA: return "xor     #0x%02X,R0" % (hw & 0xFF)
    if (hw >> 8) == 0xCB: return "or      #0x%02X,R0" % (hw & 0xFF)
    if (hw >> 8) == 0xC9: return "and     #0x%02X,R0" % (hw & 0xFF)
    if (hw >> 8) == 0xC8: return "tst     #0x%02X,R0" % (hw & 0xFF)
    if (hw >> 8) == 0x88:
        imm = hw & 0xFF
        if imm & 0x80: imm -= 256
        return "cmp/eq  #%d,R0" % imm

    for prefix, name in [(0x89,"bt"), (0x8B,"bf"), (0x8D,"bt/s"), (0x8F,"bf/s")]:
        if (hw >> 8) == prefix:
            d = hw & 0xFF
            if d & 0x80: d -= 256
            return "%-7s  0x%06X" % (name, addr + 4 + d*2)

    if (hw >> 12) == 0xB:
        d = hw & 0xFFF
        if d & 0x800: d = d - 0x1000
        return "bsr     0x%06X" % (addr + 4 + d*2)
    if (hw >> 12) == 0xA:
        d = hw & 0xFFF
        if d & 0x800: d = d - 0x1000
        return "bra     0x%06X" % (addr + 4 + d*2)

    if (hw & 0xF0FF) == 0x401E: return "ldc     R%d,GBR" % n
    if (hw & 0xF0FF) == 0x0012: return "stc     GBR,R%d" % n
    if (hw & 0xF0FF) == 0x400B: return "jsr     @R%d" % n
    if (hw & 0xF0FF) == 0x002A: return "sts     PR,R%d" % n
    if (hw & 0xF0FF) == 0x402A: return "lds     R%d,PR" % n
    if (hw & 0xF0FF) == 0x4015: return "cmp/pl  R%d" % n
    if (hw & 0xF0FF) == 0x4011: return "cmp/pz  R%d" % n
    if (hw & 0xF0FF) == 0x4010: return "dt      R%d" % n
    if (hw & 0xF0FF) == 0x4024: return "rotcl   R%d" % n
    if (hw & 0xF0FF) == 0x4004: return "rotl    R%d" % n
    if (hw & 0xF0FF) == 0x4005: return "rotr    R%d" % n
    if (hw & 0xF0FF) == 0x4020: return "shal    R%d" % n
    if (hw & 0xF0FF) == 0x4021: return "shar    R%d" % n
    if (hw & 0xF0FF) == 0x4000: return "shll    R%d" % n
    if (hw & 0xF0FF) == 0x4001: return "shlr    R%d" % n
    if (hw & 0xF0FF) == 0x4008: return "shll2   R%d" % n
    if (hw & 0xF0FF) == 0x4009: return "shlr2   R%d" % n
    if (hw & 0xF0FF) == 0x4018: return "shll8   R%d" % n
    if (hw & 0xF0FF) == 0x4019: return "shlr8   R%d" % n
    if (hw & 0xF0FF) == 0x4028: return "shll16  R%d" % n
    if (hw & 0xF0FF) == 0x4029: return "shlr16  R%d" % n

    if (hw & 0xF00F) == 0x6003: return "mov     R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x6000: return "mov.b   @R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x6001: return "mov.w   @R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x6002: return "mov.l   @R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x600C: return "extu.b  R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x600D: return "extu.w  R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x600E: return "exts.b  R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x600F: return "exts.w  R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x6006: return "mov.l   @R%d+,R%d" % (m, n)
    if (hw & 0xF00F) == 0x6004: return "mov.b   @R%d+,R%d" % (m, n)
    if (hw & 0xF00F) == 0x6005: return "mov.w   @R%d+,R%d" % (m, n)
    if (hw & 0xF00F) == 0x600A: return "negc    R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x600B: return "neg     R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x6007: return "not     R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x6009: return "swap.w  R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x6008: return "swap.b  R%d,R%d" % (m, n)

    if (hw & 0xF00F) == 0x2000: return "mov.b   R%d,@R%d" % (m, n)
    if (hw & 0xF00F) == 0x2001: return "mov.w   R%d,@R%d" % (m, n)
    if (hw & 0xF00F) == 0x2002: return "mov.l   R%d,@R%d" % (m, n)
    if (hw & 0xF00F) == 0x2004: return "mov.b   R%d,@-R%d" % (m, n)
    if (hw & 0xF00F) == 0x2005: return "mov.w   R%d,@-R%d" % (m, n)
    if (hw & 0xF00F) == 0x2006: return "mov.l   R%d,@-R%d" % (m, n)
    if (hw & 0xF00F) == 0x2008: return "tst     R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x2009: return "and     R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x200A: return "xor     R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x200B: return "or      R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x200C: return "cmp/str R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x200D: return "xtrct   R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x200E: return "mulu.w  R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x200F: return "muls.w  R%d,R%d" % (m, n)

    if (hw & 0xF00F) == 0x300C: return "add     R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x3000: return "cmp/eq  R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x3002: return "cmp/hs  R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x3003: return "cmp/ge  R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x3006: return "cmp/hi  R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x3007: return "cmp/gt  R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x3008: return "sub     R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x300E: return "addc    R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x300A: return "subc    R%d,R%d" % (m, n)
    if (hw & 0xF00F) == 0x3004: return "div1    R%d,R%d" % (m, n)

    if (hw >> 12) == 0x5:
        return "mov.l   @(0x%02X,R%d),R%d" % ((hw & 0xF)*4, m, n)
    if (hw >> 12) == 0x1:
        return "mov.l   R%d,@(0x%02X,R%d)" % (m, (hw & 0xF)*4, n)
    if (hw >> 12) == 0x7:
        imm = hw & 0xFF
        if imm & 0x80: imm -= 256
        return "add     #%d,R%d" % (imm, n)

    # FPU
    if (hw & 0xF00F) == 0xF00C: return "fmov    FR%d,FR%d" % (m, n)
    if (hw & 0xF00F) == 0xF008: return "fmov.s  @R%d,FR%d" % (m, n)
    if (hw & 0xF00F) == 0xF00A: return "fmov.s  FR%d,@R%d" % (m, n)
    if (hw & 0xF00F) == 0xF009: return "fmov.s  @R%d+,FR%d" % (m, n)
    if (hw & 0xF00F) == 0xF00B: return "fmov.s  FR%d,@-R%d" % (m, n)
    if (hw & 0xF00F) == 0xF000: return "fadd    FR%d,FR%d" % (m, n)
    if (hw & 0xF00F) == 0xF001: return "fsub    FR%d,FR%d" % (m, n)
    if (hw & 0xF00F) == 0xF002: return "fmul    FR%d,FR%d" % (m, n)
    if (hw & 0xF00F) == 0xF003: return "fdiv    FR%d,FR%d" % (m, n)
    if (hw & 0xF00F) == 0xF004: return "fcmp/eq FR%d,FR%d" % (m, n)
    if (hw & 0xF00F) == 0xF005: return "fcmp/gt FR%d,FR%d" % (m, n)
    if (hw & 0xF00F) == 0xF00E: return "fmac    FR0,FR%d,FR%d" % (m, n)
    if (hw & 0xF0FF) == 0xF02D: return "float   FPUL,FR%d" % n
    if (hw & 0xF0FF) == 0xF03D: return "ftrc    FR%d,FPUL" % n
    if (hw & 0xF0FF) == 0xF05D: return "fabs    FR%d" % n
    if (hw & 0xF0FF) == 0xF04D: return "fneg    FR%d" % n
    if (hw & 0xF0FF) == 0xF06D: return "fsqrt   FR%d" % n
    if (hw & 0xF0FF) == 0xF01D: return "flds    FR%d,FPUL" % n
    if (hw & 0xF0FF) == 0xF00D: return "fsts    FPUL,FR%d" % n
    if (hw & 0xF00F) == 0xF006: return "fmov.s  @(R0,R%d),FR%d" % (m, n)
    if (hw & 0xF00F) == 0xF007: return "fmov.s  FR%d,@(R0,R%d)" % (m, n)

    # MOV.B @(disp,Rm),R0 etc
    if (hw & 0xFF00) == 0x8400:
        return "mov.b   @(0x%02X,R%d),R0" % (hw & 0xF, m)
    if (hw & 0xFF00) == 0x8500:
        return "mov.w   @(0x%02X,R%d),R0" % ((hw & 0xF)*2, m)
    if (hw & 0xFF00) == 0x8000:
        return "mov.b   R0,@(0x%02X,R%d)" % (hw & 0xF, m)
    if (hw & 0xFF00) == 0x8100:
        return "mov.w   R0,@(0x%02X,R%d)" % ((hw & 0xF)*2, m)

    if (hw & 0xF00F) == 0x000C: return "mov.b   @(R0,R%d),R%d" % (m, n)
    if (hw & 0xF00F) == 0x000D: return "mov.w   @(R0,R%d),R%d" % (m, n)
    if (hw & 0xF00F) == 0x000E: return "mov.l   @(R0,R%d),R%d" % (m, n)
    if (hw & 0xF00F) == 0x0004: return "mov.b   R%d,@(R0,R%d)" % (m, n)
    if (hw & 0xF00F) == 0x0005: return "mov.w   R%d,@(R0,R%d)" % (m, n)
    if (hw & 0xF00F) == 0x0006: return "mov.l   R%d,@(R0,R%d)" % (m, n)

    if (hw & 0xF0FF) == 0x000A: return "sts     MACH,R%d" % n
    if (hw & 0xF0FF) == 0x001A: return "sts     MACL,R%d" % n

    return ".word   0x%04X" % hw


def resolve_literal(hw, addr):
    """Resolve PC-relative literal load."""
    if (hw >> 12) == 0xD:
        disp = hw & 0xFF
        pc_al = (addr & ~3) + 4
        lit_addr = pc_al + disp * 4
        if lit_addr < len(rom) - 3:
            val = read32(lit_addr)
            tag = ""
            if 0xFFFF0000 <= val <= 0xFFFFFFFF:
                tag = " (RAM)"
            elif 0x000D0000 <= val <= 0x000DFFFF:
                tag = " (CAL)"
            elif 0x000A0000 <= val <= 0x000BFFFF:
                tag = " (DESC/ROM)"
            elif 0x00000000 < val < 0x00100000:
                tag = " (CODE)"
            return "= 0x%08X%s" % (val, tag)
    if (hw >> 12) == 0x9:
        disp = hw & 0xFF
        pc_al = (addr & ~1) + 4
        lit_addr = pc_al + disp * 2
        if lit_addr < len(rom) - 1:
            val = struct.unpack(">H", rom[lit_addr:lit_addr+2])[0]
            return "= 0x%04X" % val
    return ""


def disasm_range(start, end):
    lines = []
    i = start
    while i < end:
        hw = read16(i)
        instr = decode(hw, i)
        lit = resolve_literal(hw, i)
        comment = ""
        if lit:
            comment = "; " + lit

        # BSR target comment
        if (hw >> 12) == 0xB:
            d = hw & 0xFFF
            if d & 0x800: d = d - 0x1000
            target = i + 4 + d * 2
            comment = "; -> 0x%06X" % target

        lines.append("  %06X: %04X  %-32s%s" % (i, hw, instr, comment))
        i += 2
    return lines


def print_section(title, start, end):
    print("=" * 80)
    print(title)
    print("=" * 80)
    for l in disasm_range(start, end):
        print(l)
    print()


# Main task54 wrapper
print_section("task54_idle_control @ 0x04BC20 (wrapper)", 0x4BC20, 0x4BC28)

# Main body
print_section("FUN_0004bc28 @ 0x04BC28 (idle control main body)", 0x4BC28, 0x4BCEC)

# Literal pool
print("--- Literal Pool (0x4BDF4 - 0x4BE20) ---")
for a in range(0x4BDF4, 0x4BE24, 4):
    v = read32(a)
    tag = ""
    if 0xFFFF0000 <= v <= 0xFFFFFFFF:
        tag = " RAM 0x%04X" % (v & 0xFFFF)
    elif 0x000D0000 <= v <= 0x000DFFFF:
        tag = " CAL"
    elif 0x000A0000 <= v <= 0x000BFFFF:
        tag = " DESC/ROM"
    elif 0 < v < 0x100000:
        tag = " CODE"
    print("  %06X: %08X  %s" % (a, v, tag))
print()

# Now disassemble the continuation functions that Ghidra found
# FUN_0004bd7a (small helper)
print_section("FUN_0004bd7a @ 0x04BD7A (idle helper)", 0x4BD7A, 0x4BD7E + 2)

# FUN_0004c01a (idle sub-function)
print_section("FUN_0004c01a @ 0x04C01A (idle sub-function)", 0x4C01A, 0x4C086)

# Look for the deeper idle functions called from this region
# Search for functions in the 0x4BC-0x4D6 range
print("=" * 80)
print("Scanning for BSR/JSR call targets from idle region 0x4BC20-0x4BCEC")
print("=" * 80)
targets = set()
for i in range(0x4BC20, 0x4BCEC, 2):
    hw = read16(i)
    if (hw >> 12) == 0xB:  # BSR
        d = hw & 0xFFF
        if d & 0x800: d = d - 0x1000
        target = i + 4 + d * 2
        targets.add(target)
    if (hw & 0xF0FF) == 0x400B:  # JSR
        # Need to find what register holds - check preceding mov.l
        pass
    if (hw >> 12) == 0xD:  # mov.l @(disp,PC),Rn - might be JSR target
        disp = hw & 0xFF
        pc_al = (i & ~3) + 4
        lit_addr = pc_al + disp * 4
        if lit_addr < len(rom) - 3:
            val = read32(lit_addr)
            if 0 < val < 0x100000:
                rn = (hw >> 8) & 0xF
                # Check if next instruction is JSR @Rn
                if i + 2 < 0x4BCEC:
                    next_hw = read16(i + 2)
                    if (next_hw & 0xF0FF) == 0x400B and ((next_hw >> 8) & 0xF) == rn:
                        targets.add(val)
                # Also check i+4 (delay slot skip)
                if i + 4 < 0x4BCEC:
                    next_hw = read16(i + 4)
                    if (next_hw & 0xF0FF) == 0x400B and ((next_hw >> 8) & 0xF) == rn:
                        targets.add(val)

for t in sorted(targets):
    print("  Call target: 0x%06X" % t)
