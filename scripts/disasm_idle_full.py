"""Full disassembly of idle control subsystem (GBR=0xFFFF837E handlers)."""
import struct

ROM_PATH = "disassembly/ghidra/AE5L600L Ghidra Export.bytes"

with open(ROM_PATH, "rb") as f:
    rom = f.read()

def r32(a): return struct.unpack(">I", rom[a:a+4])[0]
def r16(a): return struct.unpack(">H", rom[a:a+2])[0]


def decode(hw, addr):
    n = (hw >> 8) & 0xF
    m = (hw >> 4) & 0xF
    if hw == 0x000B: return "rts"
    if hw == 0x0009: return "nop"
    if hw == 0x0019: return "div0u"
    if (hw & 0xF0FF) == 0x0029: return "movt    R%d" % n
    if (hw >> 12) == 0xD: return "mov.l   @(0x%02X,PC),R%d" % ((hw&0xFF)*4, n)
    if (hw >> 12) == 0x9: return "mov.w   @(0x%02X,PC),R%d" % ((hw&0xFF)*2, n)
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
    if (hw >> 8) == 0xCF: return "or.b    #0x%02X,@(R0,GBR)" % (hw & 0xFF)
    if (hw >> 8) == 0xCD: return "and.b   #0x%02X,@(R0,GBR)" % (hw & 0xFF)
    if (hw >> 8) == 0xCE: return "xor.b   #0x%02X,@(R0,GBR)" % (hw & 0xFF)
    if (hw >> 8) == 0xCC: return "tst.b   #0x%02X,@(R0,GBR)" % (hw & 0xFF)
    if (hw >> 8) == 0x88:
        imm = hw & 0xFF
        if imm & 0x80: imm -= 256
        return "cmp/eq  #%d,R0" % imm
    for pref, name in [(0x89,"bt"), (0x8B,"bf"), (0x8D,"bt/s"), (0x8F,"bf/s")]:
        if (hw >> 8) == pref:
            d = hw & 0xFF
            if d & 0x80: d -= 256
            return "%-7s  0x%06X" % (name, addr + 4 + d*2)
    if (hw >> 12) == 0xB:
        d = hw & 0xFFF
        if d & 0x800: d -= 0x1000
        return "bsr     0x%06X" % (addr + 4 + d*2)
    if (hw >> 12) == 0xA:
        d = hw & 0xFFF
        if d & 0x800: d -= 0x1000
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
    if (hw & 0xF0FF) == 0x4000: return "shll    R%d" % n
    if (hw & 0xF0FF) == 0x4001: return "shlr    R%d" % n
    if (hw & 0xF0FF) == 0x4008: return "shll2   R%d" % n
    if (hw & 0xF0FF) == 0x4009: return "shlr2   R%d" % n
    if (hw & 0xF0FF) == 0x4018: return "shll8   R%d" % n
    if (hw & 0xF0FF) == 0x4019: return "shlr8   R%d" % n
    if (hw & 0xF0FF) == 0x4028: return "shll16  R%d" % n
    if (hw & 0xF0FF) == 0x4029: return "shlr16  R%d" % n
    if (hw & 0xF0FF) == 0x4020: return "shal    R%d" % n
    if (hw & 0xF0FF) == 0x4021: return "shar    R%d" % n
    if hw == 0x4F22: return "sts.l   PR,@-R15"
    if hw == 0x4F17: return "lds.l   @R15+,PR"
    if hw == 0x4F13: return "stc.l   GBR,@-R15"
    if hw == 0x4F26: return "ldc.l   @R15+,GBR"
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
    if (hw >> 12) == 0x5: return "mov.l   @(0x%02X,R%d),R%d" % ((hw&0xF)*4, m, n)
    if (hw >> 12) == 0x1: return "mov.l   R%d,@(0x%02X,R%d)" % (m, (hw&0xF)*4, n)
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
    if (hw & 0xFF00) == 0x8400: return "mov.b   @(0x%02X,R%d),R0" % (hw & 0xF, m)
    if (hw & 0xFF00) == 0x8500: return "mov.w   @(0x%02X,R%d),R0" % ((hw & 0xF)*2, m)
    if (hw & 0xFF00) == 0x8000: return "mov.b   R0,@(0x%02X,R%d)" % (hw & 0xF, m)
    if (hw & 0xFF00) == 0x8100: return "mov.w   R0,@(0x%02X,R%d)" % ((hw & 0xF)*2, m)
    if (hw & 0xF00F) == 0x000C: return "mov.b   @(R0,R%d),R%d" % (m, n)
    if (hw & 0xF00F) == 0x000D: return "mov.w   @(R0,R%d),R%d" % (m, n)
    if (hw & 0xF00F) == 0x000E: return "mov.l   @(R0,R%d),R%d" % (m, n)
    if (hw & 0xF00F) == 0x0004: return "mov.b   R%d,@(R0,R%d)" % (m, n)
    if (hw & 0xF00F) == 0x0005: return "mov.w   R%d,@(R0,R%d)" % (m, n)
    if (hw & 0xF00F) == 0x0006: return "mov.l   R%d,@(R0,R%d)" % (m, n)
    if (hw & 0xF0FF) == 0x000A: return "sts     MACH,R%d" % n
    if (hw & 0xF0FF) == 0x001A: return "sts     MACL,R%d" % n
    return ".word   0x%04X" % hw


def resolve(hw, addr):
    if (hw >> 12) == 0xD:
        disp = hw & 0xFF
        pc_al = (addr & ~3) + 4
        la = pc_al + disp * 4
        if la < len(rom) - 3:
            v = r32(la)
            tag = ""
            if 0xFFFF0000 <= v: tag = " RAM:%04X" % (v & 0xFFFF)
            elif 0xD0000 <= v <= 0xDFFFF: tag = " CAL"
            elif 0xA0000 <= v <= 0xBFFFF: tag = " DESC"
            elif 0 < v < 0x100000: tag = " CODE"
            return "; =0x%08X%s" % (v, tag)
    return ""


def disasm_block(start, end):
    i = start
    while i < end:
        hw = r16(i)
        ins = decode(hw, i)
        lit = resolve(hw, i)
        print("  %06X: %04X  %-34s%s" % (i, hw, ins, lit))
        i += 2


# Find all GBR=0xFFFF837E set points and disassemble blocks around them
gbr_sets = []
for addr in range(0x4CA4E, 0x4E06C, 2):
    hw = r16(addr)
    if (hw >> 12) == 0xD and ((hw >> 8) & 0xF) == 0:
        if addr + 2 < len(rom):
            nxt = r16(addr + 2)
            if nxt == 0x401E:
                disp = hw & 0xFF
                pc_al = (addr & ~3) + 4
                la = pc_al + disp * 4
                if la < len(rom) - 3 and r32(la) == 0xFFFF837E:
                    gbr_sets.append(addr)

# Now find the parent function for the dispatch.
# Look for the dispatcher structure - likely FUN_0004c828
print("=" * 80)
print("FUN_0004c828 - Idle Control Dispatcher")
print("Range: 0x4C828-0x4C84D, 0x4C878-0x4CA4D")
print("=" * 80)
disasm_block(0x4C828, 0x4C84E)
print("  ...")
disasm_block(0x4C878, 0x4CA4E)

# Print literal pool for this function
print("\n--- Literals near end of FUN_0004c828 ---")
# Scan for data after 0x4CA4E
for a in range(0x4CA50, 0x4CB00, 4):
    v = r32(a)
    if v == 0: continue
    tag = ""
    if 0xFFFF0000 <= v: tag = " RAM:%04X" % (v & 0xFFFF)
    elif 0xD0000 <= v <= 0xDFFFF: tag = " CAL"
    elif 0xA0000 <= v <= 0xBFFFF: tag = " DESC"
    elif 0 < v < 0x100000: tag = " CODE"
    print("  %06X: %08X%s" % (a, v, tag))

# Now disassemble the first few GBR handler blocks (the ones writing to +0x00, +0x5C etc)
print("\n" + "=" * 80)
print("ISC OUTPUT HANDLER BLOCKS (GBR=0xFFFF837E)")
print("=" * 80)

for i, gs in enumerate(gbr_sets[:8]):
    # Find a reasonable start - look backwards for a label/entry
    # Start from the GBR set instruction and go back to find the block start
    # Simple heuristic: find the nearest RTS or data boundary before this point
    block_start = gs - 0x30  # go back ~48 bytes
    block_end = gs + 0x60    # go forward ~96 bytes

    # Trim to not overlap with data
    if block_end > 0x4E06C:
        block_end = 0x4E06C

    print("\n--- Handler block %d (GBR set at 0x%06X) ---" % (i, gs))
    disasm_block(block_start, block_end)

    # Show relevant literal pool entries
    # Find mov.l @(disp,PC) instructions and resolve them
    for a in range(block_start, block_end, 2):
        hw = r16(a)
        if (hw >> 12) == 0xD:
            disp = hw & 0xFF
            pc_al = (a & ~3) + 4
            la = pc_al + disp * 4
            if la < len(rom) - 3:
                v = r32(la)
                if v != 0xFFFF837E:  # skip the GBR value itself
                    tag = ""
                    if 0xFFFF0000 <= v: tag = " RAM:%04X" % (v & 0xFFFF)
                    elif 0xD0000 <= v <= 0xDFFFF: tag = " CAL"
                    elif 0xA0000 <= v <= 0xBFFFF: tag = " DESC"
                    elif 0 < v < 0x100000: tag = " CODE"
                    if tag:
                        print("    Lit@%06X: 0x%08X%s" % (la, v, tag))

print("\n\nAll GBR=0xFFFF837E set points:")
for gs in gbr_sets:
    print("  0x%06X" % gs)
print("Total: %d handler blocks" % len(gbr_sets))
