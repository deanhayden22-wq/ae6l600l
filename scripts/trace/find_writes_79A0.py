#!/usr/bin/env python3
"""Find all write sites for FFFF79A0 and trace calibration values."""

import struct

ROM_PATH = 'C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin'
with open(ROM_PATH, 'rb') as f:
    rom = f.read()

def read_u16(addr): return struct.unpack('>H', rom[addr:addr+2])[0]
def read_u32(addr): return struct.unpack('>I', rom[addr:addr+4])[0]
def read_s8(v): return v - 256 if v > 127 else v
def read_float(addr): return struct.unpack('>f', rom[addr:addr+4])[0]

GBR_BASE = 0xFFFF7450

def disasm_one(addr, r12_base=0xFFFF79F0, r6_base=None):
    if addr + 2 > len(rom): return "???"
    op = read_u16(addr)
    n_r = (op >> 8) & 0xF
    m_r = (op >> 4) & 0xF
    d8 = op & 0xFF
    d4 = op & 0xF
    top4 = (op >> 12) & 0xF

    asm = ""
    comment = ""

    if op == 0x0009: asm = "nop"
    elif op == 0x000B: asm = "rts"
    elif op == 0x0048: asm = "clrs"
    elif op == 0x0008: asm = "clrt"
    elif op == 0x0018: asm = "sett"
    elif top4 == 0xF:
        fn, fm = n_r, m_r
        if d4 == 0: asm = f"fadd   FR{fm},FR{fn}"
        elif d4 == 1: asm = f"fsub   FR{fm},FR{fn}"
        elif d4 == 2: asm = f"fmul   FR{fm},FR{fn}"
        elif d4 == 3: asm = f"fdiv   FR{fm},FR{fn}"
        elif d4 == 4: asm = f"fcmp/eq FR{fm},FR{fn}"
        elif d4 == 5: asm = f"fcmp/gt FR{fm},FR{fn}"
        elif d4 == 6:
            asm = f"fmov.s @(R0,R{m_r}),FR{fn}"
            prev = read_u16(addr - 2) if addr >= 2 else 0
            if (prev >> 12) == 0xE and ((prev >> 8) & 0xF) == 0:
                r0 = read_s8(prev & 0xFF)
                if m_r == 12 and r12_base: eff = (r12_base + r0) & 0xFFFFFFFF; comment = f"FR{fn}=[{eff:08X}]"
                elif m_r == 6 and r6_base: eff = (r6_base + r0) & 0xFFFFFFFF; comment = f"FR{fn}=[{eff:08X}]"
        elif d4 == 7:
            asm = f"fmov.s FR{fm},@(R0,R{n_r})"
            prev = read_u16(addr - 2) if addr >= 2 else 0
            if (prev >> 12) == 0xE and ((prev >> 8) & 0xF) == 0:
                r0 = read_s8(prev & 0xFF)
                if n_r == 12 and r12_base: eff = (r12_base + r0) & 0xFFFFFFFF; comment = f"[{eff:08X}]=FR{fm}"
                elif n_r == 6 and r6_base: eff = (r6_base + r0) & 0xFFFFFFFF; comment = f"[{eff:08X}]=FR{fm}"
        elif d4 == 8: asm = f"fmov.s @R{m_r},FR{fn}"
        elif d4 == 9: asm = f"fmov.s @R{m_r}+,FR{fn}"
        elif d4 == 0xA: asm = f"fmov.s FR{fm},@R{n_r}"
        elif d4 == 0xB: asm = f"fmov.s FR{fm},@-R{n_r}"
        elif d4 == 0xC: asm = f"fmov   FR{fm},FR{fn}"
        elif d4 == 0xE: asm = f"fmac   FR0,FR{fm},FR{fn}"
        elif d4 == 0xD:
            if fm == 8: asm = f"fldi0  FR{fn}"
            elif fm == 9: asm = f"fldi1  FR{fn}"
            else: asm = f".word  0x{op:04X}"
        else: asm = f".word  0x{op:04X}"
    elif top4 == 0xE: asm = f"mov    #{read_s8(d8)},R{n_r}"
    elif top4 == 0xD:
        pa = ((addr + 4) & ~3) + d8 * 4
        if pa + 3 < len(rom):
            v = read_u32(pa)
            asm = f"mov.l  @(PC+0x{((pa-addr-4)):03X}),R{n_r}"
            comment = f"R{n_r}=0x{v:08X}"
            if v == 0xFFFF79A0: comment += " [FFFF79A0!]"
            elif v == 0xFFFF79F0: comment += " [FFFF79F0 base]"
        else: asm = f"mov.l  @(disp,PC),R{n_r}"
    elif top4 == 0xC:
        s = n_r
        if s == 4: asm = f"mov.b  @(0x{d8:02X},GBR),R0"; comment = f"[{GBR_BASE+d8:08X}]"
        elif s == 5: asm = f"mov.w  @(0x{d8*2:03X},GBR),R0"; comment = f"[{GBR_BASE+d8*2:08X}]"
        elif s == 6: asm = f"mov.l  @(0x{d8*4:03X},GBR),R0"; comment = f"[{GBR_BASE+d8*4:08X}]"
        elif s == 0: asm = f"mov.b  R0,@(0x{d8:02X},GBR)"
        elif s == 1: asm = f"mov.w  R0,@(0x{d8*2:03X},GBR)"
        elif s == 2: asm = f"mov.l  R0,@(0x{d8*4:03X},GBR)"
        elif s == 7:
            pa = ((addr + 4) & ~3) + d8 * 4
            asm = f"mova   @(PC+0x{((pa-addr-4)):03X}),R0"; comment = f"R0=0x{pa:08X}"
        else: asm = f".word  0x{op:04X}"
    elif top4 == 0x4:
        low8 = op & 0xFF
        if low8 == 0x0B: asm = f"jsr    @R{n_r}"
        elif low8 == 0x2B: asm = f"jmp    @R{n_r}"
        elif low8 == 0x22: asm = f"sts.l  PR,@-R{n_r}"
        elif low8 == 0x26: asm = f"lds.l  @R{n_r}+,PR"
        elif low8 == 0x17: asm = f"ldc.l  @R{n_r}+,GBR"
        elif low8 == 0x15: asm = f"cmp/pl R{n_r}"
        elif low8 == 0x11: asm = f"cmp/pz R{n_r}"
        elif low8 == 0x10: asm = f"dt     R{n_r}"
        elif low8 == 0x16: asm = f"lds    R{n_r},FPSCR"
        elif low8 == 0x56: asm = f"lds.l  @R{n_r}+,FPSCR"
        elif low8 == 0x5A: asm = f"lds.l  @R{n_r}+,FPSCR"
        elif low8 == 0x6A: asm = f"lds.l  @R{n_r}+,FPUL"
        elif low8 == 0x06: asm = f"lds    R{n_r},FPUL"
        elif low8 == 0x0A: asm = f"lds    R{n_r},PR"
        else: asm = f".word  0x{op:04X}"
    elif top4 == 0x0:
        sub = d4
        if sub == 0x7: asm = f"mul.l  R{m_r},R{n_r}"
        elif sub == 0xA:
            if m_r == 2: asm = f"sts    PR,R{n_r}"
            elif m_r == 0: asm = f"sts    MACH,R{n_r}"
            elif m_r == 1: asm = f"sts    MACL,R{n_r}"
            else: asm = f".word  0x{op:04X}"
        elif sub == 0x2:
            if m_r == 1: asm = f"stc    GBR,R{n_r}"
            elif m_r == 0: asm = f"stc    SR,R{n_r}"
            else: asm = f".word  0x{op:04X}"
        elif sub == 0xC: asm = f"mov.b  @(R0,R{m_r}),R{n_r}"
        elif sub == 0xD: asm = f"mov.w  @(R0,R{m_r}),R{n_r}"
        elif sub == 0xE: asm = f"mov.l  @(R0,R{m_r}),R{n_r}"
        elif sub == 0x4: asm = f"mov.b  R{m_r},@(R0,R{n_r})"
        elif sub == 0x5: asm = f"mov.w  R{m_r},@(R0,R{n_r})"
        elif sub == 0x6: asm = f"mov.l  R{m_r},@(R0,R{n_r})"
        elif sub == 0x3: asm = f"bsrf   R{n_r}"
        else: asm = f".word  0x{op:04X}"
    elif top4 == 0x2:
        sub = d4
        if sub == 0: asm = f"mov.b  R{m_r},@R{n_r}"
        elif sub == 1: asm = f"mov.w  R{m_r},@R{n_r}"
        elif sub == 2: asm = f"mov.l  R{m_r},@R{n_r}"
        elif sub == 8: asm = f"tst    R{m_r},R{n_r}"
        elif sub == 9: asm = f"and    R{m_r},R{n_r}"
        elif sub == 0xA: asm = f"xor    R{m_r},R{n_r}"
        elif sub == 0xB: asm = f"or     R{m_r},R{n_r}"
        elif sub == 4: asm = f"div0s  R{m_r},R{n_r}"
        elif sub == 0xF: asm = f"muls.w R{m_r},R{n_r}"
        elif sub == 0xE: asm = f"mulu.w R{m_r},R{n_r}"
        else: asm = f".word  0x{op:04X}"
    elif top4 == 0x3:
        sub = d4
        if sub == 0: asm = f"cmp/eq R{m_r},R{n_r}"
        elif sub == 2: asm = f"cmp/hs R{m_r},R{n_r}"
        elif sub == 3: asm = f"cmp/ge R{m_r},R{n_r}"
        elif sub == 4: asm = f"div1   R{m_r},R{n_r}"
        elif sub == 6: asm = f"cmp/hi R{m_r},R{n_r}"
        elif sub == 7: asm = f"cmp/gt R{m_r},R{n_r}"
        elif sub == 8: asm = f"sub    R{m_r},R{n_r}"
        elif sub == 0xC: asm = f"add    R{m_r},R{n_r}"
        elif sub == 0xE: asm = f"addc   R{m_r},R{n_r}"
        else: asm = f".word  0x{op:04X}"
    elif top4 == 0x6:
        sub = d4
        if sub == 0: asm = f"mov.b  @R{m_r},R{n_r}"
        elif sub == 1: asm = f"mov.w  @R{m_r},R{n_r}"
        elif sub == 2: asm = f"mov.l  @R{m_r},R{n_r}"
        elif sub == 3: asm = f"mov    R{m_r},R{n_r}"
        elif sub == 4: asm = f"mov.b  @R{m_r}+,R{n_r}"
        elif sub == 5: asm = f"mov.w  @R{m_r}+,R{n_r}"
        elif sub == 6: asm = f"mov.l  @R{m_r}+,R{n_r}"
        elif sub == 7: asm = f"not    R{m_r},R{n_r}"
        elif sub == 8: asm = f"swap.b R{m_r},R{n_r}"
        elif sub == 9: asm = f"swap.w R{m_r},R{n_r}"
        elif sub == 0xA: asm = f"negc   R{m_r},R{n_r}"
        elif sub == 0xB: asm = f"neg    R{m_r},R{n_r}"
        elif sub == 0xC: asm = f"extu.b R{m_r},R{n_r}"
        elif sub == 0xD: asm = f"extu.w R{m_r},R{n_r}"
        elif sub == 0xE: asm = f"exts.b R{m_r},R{n_r}"
        elif sub == 0xF: asm = f"exts.w R{m_r},R{n_r}"
        else: asm = f".word  0x{op:04X}"
    elif top4 == 0x5: asm = f"mov.l  @({d4*4},R{m_r}),R{n_r}"
    elif top4 == 0x1: asm = f"mov.l  R{m_r},@({d4*4},R{n_r})"
    elif top4 == 0x7: asm = f"add    #{read_s8(d8)},R{n_r}"
    elif top4 == 0x8:
        s = n_r
        if s == 0: asm = f"mov.b  R0,@({d4},R{m_r})"
        elif s == 1: asm = f"mov.w  R0,@({d4*2},R{m_r})"
        elif s == 4: asm = f"mov.b  @({d4},R{m_r}),R0"
        elif s == 5: asm = f"mov.w  @({d4*2},R{m_r}),R0"
        elif s == 8: asm = f"cmp/eq #{read_s8(d8)},R0"
        elif s == 9: asm = f"bt     0x{addr+4+read_s8(d8)*2:05X}"
        elif s == 0xB: asm = f"bf     0x{addr+4+read_s8(d8)*2:05X}"
        elif s == 0xD: asm = f"bt/s   0x{addr+4+read_s8(d8)*2:05X}"
        elif s == 0xF: asm = f"bf/s   0x{addr+4+read_s8(d8)*2:05X}"
        else: asm = f".word  0x{op:04X}"
    elif top4 == 0x9:
        pa = ((addr + 4) & ~1) + d8 * 2
        if pa + 1 < len(rom):
            v = read_u16(pa); vs = v - 65536 if v > 32767 else v
            asm = f"mov.w  @(PC+0x{(pa-addr-4):03X}),R{n_r}"; comment = f"R{n_r}={vs}"
        else: asm = f"mov.w  @(disp,PC),R{n_r}"
    elif top4 == 0xA:
        disp = op & 0xFFF; disp = disp - 4096 if disp >= 2048 else disp
        asm = f"bra    0x{addr+4+disp*2:05X}"
    elif top4 == 0xB:
        disp = op & 0xFFF; disp = disp - 4096 if disp >= 2048 else disp
        asm = f"bsr    0x{addr+4+disp*2:05X}"
    else: asm = f".word  0x{op:04X}"

    return asm, comment

def disasm_range(label, start, end, r12_base=0xFFFF79F0, r6_base=None, highlight=None):
    print(f"\n{'='*100}")
    print(f"{label}")
    print(f"{'='*100}")
    for addr in range(start, end, 2):
        if addr + 2 > len(rom): break
        result = disasm_one(addr, r12_base, r6_base)
        if isinstance(result, tuple):
            asm, comment = result
        else:
            asm, comment = result, ""

        marker = ""
        if highlight and addr in highlight: marker = "  <<<<<"
        if "79A0" in comment: marker = "  <<< FFFF79A0"

        cmt = f"  ; {comment}" if comment else ""
        print(f"  {addr:05X}: {read_u16(addr):04X}  {asm:42s}{cmt}{marker}")


# ============================================================
# WRITE SITE 1: 0x2B9DA
# ============================================================
disasm_range("WRITE SITE 1: 0x2B9DA (fmov.s FR8,@(R0,R12))",
             0x2B990, 0x2BA20, highlight=[0x2B9DA])

# ============================================================
# WRITE SITE 2: 0x3F91C
# ============================================================
disasm_range("WRITE SITE 2: 0x3F91C (fmov.s FR14,@(R0,R12))",
             0x3F8D0, 0x3F960, highlight=[0x3F91C])

# ============================================================
# WRITE SITE 3: 0x60C52
# ============================================================
disasm_range("WRITE SITE 3: 0x60C52 (fmov.s FR0,@(R0,R12))",
             0x60C10, 0x60C80, highlight=[0x60C52])

# ============================================================
# WRITE SITE 4: 0x8A9BA
# ============================================================
disasm_range("WRITE SITE 4: 0x8A9BA (fmov.s FR0,@(R0,R12))",
             0x8A970, 0x8AA10, highlight=[0x8A9BA])

# ============================================================
# LITERAL POOL 0x36A74 = 0xFFFF79A0
# Who loads it?
# ============================================================
print(f"\n{'='*100}")
print("LITERAL POOL AT 0x36A74 = 0xFFFF79A0 -- find who loads it")
print(f"{'='*100}")
pool_addr = 0x36A74
print(f"  Value at 0x36A74: 0x{read_u32(pool_addr):08X}")

# Scan back for mov.l @(disp,PC),Rn that resolves to 0x36A74
for src in range(0x36800, pool_addr, 2):
    op = read_u16(src)
    if (op >> 12) == 0xD:
        rn = (op >> 8) & 0xF
        disp = op & 0xFF
        target = ((src + 4) & ~3) + disp * 4
        if target == pool_addr:
            print(f"  Loaded at 0x{src:05X}: mov.l @(PC+0x{(target-src-4):03X}),R{rn} -> R{rn}=0xFFFF79A0")

# ============================================================
# Also check the function around 0x36A74 to understand context
# ============================================================
disasm_range("CODE AROUND LITERAL 0x36A74 (0x36990-0x36AE0)",
             0x36990, 0x36AE0, highlight=[0x36A74])
