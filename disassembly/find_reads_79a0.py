#!/usr/bin/env python3
"""Find all READ accesses to FFFF79A0 and verify what value is stored there."""
import struct

ROM_PATH = 'C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin'
with open(ROM_PATH, 'rb') as f:
    rom = f.read()

def read_u32(a): return struct.unpack('>I', rom[a:a+4])[0]
def read_u16(a): return struct.unpack('>H', rom[a:a+2])[0]
def read_float(a): return struct.unpack('>f', rom[a:a+4])[0]

TARGET = 0xFFFF79A0

# === SECTION 1: Verify actual Y-axis values in BEB6C ===
# BEB6C does:
# 1. fldi0 FR2 = 0.0
# 2. shll R0 (R0 = element_index * 2, byte offset for uint16 array)
# 3. fcmp/eq FR0,FR2 (T = interp_frac==0)
# 4. add R0,R1 (R1 = Y_ptr + index*2)
# 5. mov.w @R1+,R0 (R0 = uint16_Y[index], R1 += 2)
# 6. extu.w R0,R0
# 7. lds R0,FPUL
# 8. bt/s to rts (delay: float FPUL,FR2 -> FR2 = float(Y[index]))
# 9. [if interpolating]: read Y[index+1], compute fmac
# 10. rts: nop; result in FR2

# Then in BE830:
# fmov FR2,FR1 (delay slot of bt/s)
# if clamped (R3==0 from bsearch): rts -> FR0=FR1=FR2=float(Y[index])
# if interpolating: FR0=scale*interpolated_Y

# But wait: bsearch 0xBECA8 at BECD0/BECD6 are CLAMPED high/low
# For clamped-high: shlr2 R0, rts -> R0 = (n-1), R3 = whatever
# For clamped-low: R0 = 0, rts
# These are NOT the same R3=0 path. Let me check R3.

# After the bsearch, R3 in 0xBECA8 - checking the path that reaches BECCC (normal interp):
# The tst R0,R0 at BECBE: sets T if R0==0. BT/S to BECD6 if R0==0.
# Otherwise BECC0: fsub FR1,FR0; add #4,R0; etc.
# At rts BECCC: R3 was set by extu.b at BE83E (format=8) before the call.
# The binary search preserves R3 (doesn't modify it).
# So R3 = 8 throughout.

# Back in 0xBE830: tst R3,R3 -> T = (R3==0) = (8==0) = FALSE
# So the clamped path (bt/s to 0xBE858) is NEVER taken via this T check.
# Instead, the code ALWAYS falls through to the scale path!

print("=== CRITICAL INSIGHT ===")
print("R3 = format_byte = 8 (set at BE83E as extu.b of format 0x08)")
print("tst R3,R3 at BE84A -> T = (R3==0) = FALSE")
print("bt/s to 0xBE858 NOT taken -> ALWAYS goes through scale path!")
print()
print("Scale path:")
print("  add #12,R4: R4 = 0xAD0DC + 12 = 0xAD0E8")
print("  fmov.s @R4+,FR0 -> FR0 = float at 0xAD0E8")
print("  fmov.s @R4,FR1  -> FR1 = float at 0xAD0EC")
print("  fmac FR0,FR2,FR1 -> FR1 = FR1 + FR0 * FR2 = Y_base + scale * Y_interp")
print()

desc = 0xAD0DC
scale_val = read_float(desc + 12)  # 0xAD0E8
base_val = read_float(desc + 12 + 4)  # 0xAD0EC
print("  scale (at 0xAD0E8) = %g" % scale_val)
print("  base  (at 0xAD0EC) = %g" % base_val)
print()
print("  FR2 = float(uint16_Y[i]) after BEB6C")
print("  Final FR0 = base + scale * FR2 = %g + %g * float(Y[i])" % (base_val, scale_val))
print()

# For 80C: Y[12] = uint16 at 0xCE6E4 = 0x8000 = 32768
# FR2 = 32768.0
# FR0 = 0.0 + 3.05e-5 * 32768 = 0.0 + 1.0 = 1.0
# For 50C: Y[9] at 0xCE6DE
y9_raw = read_u16(0xCE6DE)
y_val_50 = base_val + scale_val * float(y9_raw)
print("  At 50C: Y_uint16 = %d, FFFF79A0 = %g" % (y9_raw, y_val_50))
y12_raw = read_u16(0xCE6E4)
y_val_80 = base_val + scale_val * float(y12_raw)
print("  At 80C: Y_uint16 = %d, FFFF79A0 = %g" % (y12_raw, y_val_80))
y0_raw = read_u16(0xCE6CC)
y_val_m40 = base_val + scale_val * float(y0_raw)
print("  At -40C: Y_uint16 = %d, FFFF79A0 = %g" % (y0_raw, y_val_m40))

print()
print("  But WAIT: 0.0 + 3.05e-5 * float(Y) where Y in [0..32768] gives [0.0, 1.0]")
print("  That is a COOLANT TEMP CORRECTION FACTOR, not a decay coefficient directly!")
print()

# So FFFF79A0 gets a value between 0 and 1 based on coolant temp.
# At 80C: FFFF79A0 = 1.0
# At 0C:  FFFF79A0 = 0.389
# This is likely a MULTIPLIER on some base decay coefficient.
# The ACTUAL decay coefficient is computed from FFFF79A0 elsewhere.

# Let me now PROPERLY find reads of FFFF79A0 to understand how it's used.
print("="*80)
print("Finding fmov.s @(R0,Rm),FRn that reads FFFF79A0")
print("="*80)
print()

results = []
for addr in range(0, len(rom)-1, 2):
    op = read_u16(addr)
    if (op & 0xF00F) != 0xF006:
        continue
    m_reg = (op >> 4) & 0xF
    n_reg = (op >> 8) & 0xF

    regs = {}
    for prev in range(max(0, addr-120), addr, 2):
        pop = read_u16(prev)
        ptop = (pop >> 12) & 0xF
        pn = (pop >> 8) & 0xF
        pm = (pop >> 4) & 0xF
        pd8 = pop & 0xFF
        pd4 = pop & 0xF

        if ptop == 0xD:
            pdisp = pd8 * 4
            ppool = ((prev + 4) & ~3) + pdisp
            if ppool + 3 < len(rom):
                regs[pn] = read_u32(ppool)
        elif ptop == 0xE:
            imm = pd8 if pd8 < 128 else pd8 - 256
            regs[pn] = imm & 0xFFFFFFFF
        elif ptop == 0x7:
            imm = pd8 if pd8 < 128 else pd8 - 256
            if pn in regs:
                regs[pn] = (regs[pn] + imm) & 0xFFFFFFFF
        elif ptop == 0x6 and pd4 == 3:
            if pm in regs:
                regs[pn] = regs[pm]

    base = regs.get(m_reg)
    r0 = regs.get(0)

    if base is not None and r0 is not None:
        r0_s = r0 if r0 < 0x80000000 else r0 - 0x100000000
        effective = (base + r0_s) & 0xFFFFFFFF
        if effective == TARGET:
            results.append((addr, op, m_reg, n_reg, base, r0_s))

print("READ accesses to FFFF79A0 (fmov.s @(R0,Rm),FRn):")
for addr, op, m_reg, n_reg, base, r0_s in results:
    print("  ROM 0x%05X: fmov.s @(R0,R%d),FR%d  [R%d=0x%08X, R0=%d]" % (
        addr, m_reg, n_reg, m_reg, base, r0_s))

print()
print("Also checking fmov.s @Rn,FRm reads:")
results2 = []
for addr in range(0, len(rom)-1, 2):
    op = read_u16(addr)
    if (op & 0xF00F) != 0xF008:
        continue
    m_reg = (op >> 4) & 0xF
    n_reg = (op >> 8) & 0xF

    regs = {}
    for prev in range(max(0, addr-80), addr, 2):
        pop = read_u16(prev)
        ptop = (pop >> 12) & 0xF
        pn = (pop >> 8) & 0xF
        pm = (pop >> 4) & 0xF
        pd8 = pop & 0xFF

        if ptop == 0xD:
            pdisp = pd8 * 4
            ppool = ((prev + 4) & ~3) + pdisp
            if ppool + 3 < len(rom):
                regs[pn] = read_u32(ppool)
        elif ptop == 0xE:
            imm = pd8 if pd8 < 128 else pd8 - 256
            regs[pn] = imm & 0xFFFFFFFF
        elif ptop == 0x7:
            imm = pd8 if pd8 < 128 else pd8 - 256
            if pn in regs:
                regs[pn] = (regs[pn] + imm) & 0xFFFFFFFF
        elif ptop == 0x6 and (pd8 & 0xF) == 3:
            if pm in regs:
                regs[pn] = regs[pm]

    base = regs.get(m_reg)
    if base == TARGET:
        results2.append((addr, op, m_reg, n_reg, base))

for addr, op, m_reg, n_reg, base in results2:
    print("  ROM 0x%05X: fmov.s @R%d,FR%d  [R%d=0x%08X]" % (addr, m_reg, n_reg, m_reg, base))

# Also find direct load: mov.l @R2 where R2=FFFF79A0 then lds R,FPUL+float
print()
print("Also checking direct pointer reads to FFFF79A0:")
results3 = []
for addr in range(0, len(rom)-1, 2):
    op = read_u16(addr)
    if (op & 0xF00F) != 0xF008:
        continue
    m_reg = (op >> 4) & 0xF
    n_reg = (op >> 8) & 0xF

    regs = {}
    for prev in range(max(0, addr-40), addr, 2):
        pop = read_u16(prev)
        ptop = (pop >> 12) & 0xF
        pn = (pop >> 8) & 0xF
        pm = (pop >> 4) & 0xF
        pd8 = pop & 0xFF

        if ptop == 0xD:
            pdisp = pd8 * 4
            ppool = ((prev + 4) & ~3) + pdisp
            if ppool + 3 < len(rom):
                regs[pn] = read_u32(ppool)

    base = regs.get(m_reg)
    if base == TARGET:
        print("  ROM 0x%05X: fmov.s @R%d,FR%d  [R%d loaded from pool = FFFF79A0]" % (
            addr, m_reg, n_reg, m_reg))
