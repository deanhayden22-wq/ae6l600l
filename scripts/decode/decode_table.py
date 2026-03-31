#!/usr/bin/env python3
"""Decode the FFFF79A0 decay coefficient table at descriptor 0xAD0DC."""
import struct

ROM_PATH = 'C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin'
with open(ROM_PATH, 'rb') as f:
    rom = f.read()

def read_u32(a):
    return struct.unpack('>I', rom[a:a+4])[0]

def read_u16(a):
    return struct.unpack('>H', rom[a:a+2])[0]

def read_s16(a):
    return struct.unpack('>h', rom[a:a+2])[0]

def read_float(a):
    return struct.unpack('>f', rom[a:a+4])[0]

# Table descriptor at 0xAD0DC:
desc = 0xAD0DC
count = read_u16(desc)           # 16
fmt   = rom[desc+2]              # 8
x_ptr = read_u32(desc+4)        # 0xCC624
y_ptr = read_u32(desc+8)        # 0xCE6CC
extra = read_float(desc+12)     # 3.05e-5 = 1/32768

print("="*80)
print("Table descriptor at ROM 0x%05X" % desc)
print("  count = %d, format = 0x%02X, extra = %g (1/32768)" % (count, fmt, extra))
print("  X-axis ptr = 0x%05X (float32 temps)" % x_ptr)
print("  Y-axis ptr = 0x%05X" % y_ptr)
print("="*80)
print()

# The function 0xBEB6C (format=8, dispatch offset 8) does:
# - fldi0 FR2  (FR2 = 0.0)
# - shll R0    (R0 = index * 2, byte offset into int16 array)
# - fcmp/eq FR0,FR2  (check if interpolation fraction == 0)
# - add R0,R1   (R1 = Y_ptr + index*2)
# - mov.w @R1+,R0  (R0 = int16 Y[index], R1 advances by 2)
# - extu.w R0,R0   (zero-extend to 32-bit)
# Then:
# - bt/s if fraction==0: exact match, load int16 Y[index] only
# - else: load Y[index], Y[index+1], compute interpolated value
# Then converts int16 -> float using scale factor (extra = 1/32768)
# OR: the int16 value IS the result and gets multiplied by extra somewhere?

# Actually let me look at the scale factor path more carefully.
# The fmac path: fmac FR0,FR2,FR1 -> FR1 = FR1 + FR0*FR2
# Here FR2 = Y fraction (delta), FR0 = interp_frac, FR1 = Y[index]
# But Y values must be floats for this to work as interpolation.
# Unless the int16 is first converted to float via lds+float instruction...

# Let me look at BEB6C more carefully with correct decoding:
print("=== BEB6C float reader function ===")
addr = 0xBEB6C
for i in range(18):
    op = read_u16(addr)
    top = (op >> 12) & 0xF
    n = (op >> 8) & 0xF
    m = (op >> 4) & 0xF
    d8 = op & 0xFF
    d4 = op & 0xF

    if op == 0x000B:
        s = "rts"
    elif op == 0x0009:
        s = "nop"
    elif top == 0xF:
        sub = d4
        fn = n; fm = m
        if sub == 0x0: s = "fadd FR%d,FR%d" % (fm, fn)
        elif sub == 0x1: s = "fsub FR%d,FR%d" % (fm, fn)
        elif sub == 0x2: s = "fmul FR%d,FR%d" % (fm, fn)
        elif sub == 0x3: s = "fdiv FR%d,FR%d" % (fm, fn)
        elif sub == 0x4: s = "fcmp/eq FR%d,FR%d" % (fm, fn)
        elif sub == 0x5: s = "fcmp/gt FR%d,FR%d" % (fm, fn)
        elif sub == 0x6: s = "fmov.s @(R0,R%d),FR%d" % (m, fn)
        elif sub == 0x7: s = "fmov.s FR%d,@(R0,R%d)" % (fm, fn)
        elif sub == 0x8: s = "fmov.s @R%d,FR%d" % (fm, fn)
        elif sub == 0x9: s = "fmov.s @R%d+,FR%d" % (fm, fn)
        elif sub == 0xA: s = "fmov.s FR%d,@R%d" % (fm, fn)
        elif sub == 0xB: s = "fmov.s FR%d,@-R%d" % (fm, fn)
        elif sub == 0xC: s = "fmov FR%d,FR%d" % (fm, fn)
        elif sub == 0xE: s = "fmac FR0,FR%d,FR%d" % (fm, fn)
        elif sub == 0xD:
            if fm == 0: s = "fsts FPUL,FR%d" % fn
            elif fm == 1: s = "flds FR%d,FPUL" % fn
            elif fm == 2: s = "float FPUL,FR%d" % fn
            elif fm == 3: s = "ftrc FR%d,FPUL" % fn
            elif fm == 4: s = "fneg FR%d" % fn
            elif fm == 5: s = "fabs FR%d" % fn
            elif fm == 6: s = "fsqrt FR%d" % fn
            elif fm == 8: s = "fldi0 FR%d" % fn
            elif fm == 9: s = "fldi1 FR%d" % fn
            elif fm == 0xA: s = "lds R%d,FPUL" % fn
            else: s = ".word 0x%04X" % op
        else:
            s = ".word 0x%04X" % op
    elif top == 0x4:
        low8 = op & 0xFF
        if low8 == 0x08: s = "shll2 R%d" % n
        elif low8 == 0x18: s = "shll8 R%d" % n
        elif low8 == 0x00: s = "shll R%d" % n
        elif low8 == 0x01: s = "shlr R%d" % n
        elif low8 == 0x09: s = "shlr2 R%d" % n
        elif low8 == 0x0B: s = "jsr @R%d" % n
        elif low8 == 0x2B: s = "jmp @R%d" % n
        elif low8 == 0x2A: s = "lds R%d,PR" % n
        elif low8 == 0x0A: s = "lds R%d,MACH" % n
        elif low8 == 0x1A: s = "lds R%d,MACL" % n
        else: s = ".word 0x%04X (4xxx)" % op
    elif top == 0x3:
        sub = d4
        ops3 = {0:"cmp/eq",8:"sub",0xC:"add"}
        s = "%s R%d,R%d" % (ops3.get(sub, ".word 0x%04X" % op), m, n)
    elif top == 0x6:
        sub = d4
        if sub == 3: s = "mov R%d,R%d" % (m, n)
        elif sub == 2: s = "mov.l @R%d,R%d" % (m, n)
        elif sub == 6: s = "mov.l @R%d+,R%d" % (m, n)
        elif sub == 5: s = "mov.w @R%d+,R%d" % (m, n)
        elif sub == 1: s = "mov.w @R%d,R%d" % (m, n)
        elif sub == 0: s = "mov.b @R%d,R%d" % (m, n)
        elif sub == 0xC: s = "extu.b R%d,R%d" % (m, n)
        elif sub == 0xD: s = "extu.w R%d,R%d" % (m, n)
        elif sub == 0xE: s = "exts.b R%d,R%d" % (m, n)
        else: s = ".word 0x%04X" % op
    elif top == 0x8:
        sub = n
        if sub == 0x9:
            disp = (d8 if d8 < 128 else d8-256)*2+4
            s = "bt 0x%05X" % (addr+disp)
        elif sub == 0xD:
            disp = (d8 if d8 < 128 else d8-256)*2+4
            s = "bt/s 0x%05X" % (addr+disp)
        elif sub == 0xF:
            disp = (d8 if d8 < 128 else d8-256)*2+4
            s = "bf/s 0x%05X" % (addr+disp)
        elif sub == 0xB:
            disp = (d8 if d8 < 128 else d8-256)*2+4
            s = "bf 0x%05X" % (addr+disp)
        else: s = ".word 0x%04X" % op
    elif top == 0x0:
        sub = d4
        if sub == 0xA and m == 2: s = "sts PR,R%d" % n
        else: s = ".word 0x%04X" % op
    elif top == 0x2:
        sub = d4
        if sub == 8: s = "tst R%d,R%d" % (m, n)
        elif sub == 2: s = "mov.l R%d,@R%d" % (m, n)
        else: s = ".word 0x%04X" % op
    elif top == 0x5:
        disp = d4 * 4
        s = "mov.l @(%d,R%d),R%d" % (disp, m, n)
    else:
        s = ".word 0x%04X" % op

    print("  %05X: %04X  %s" % (addr, op, s))
    addr += 2

print()
print("="*80)
print("INTERPRETATION:")
print("="*80)
print()
print("BEB6C (called with R0=index, R1=Y_ptr=0xCE6CC, FR0=interp_frac):")
print("  fldi0 FR2         ; FR2 = 0.0")
print("  shll R0           ; R0 = index * 2 (byte offset for int16 array)")
print("  fcmp/eq FR0,FR2   ; T = (interp_frac == 0)")
print("  add R0,R1         ; R1 = Y_ptr + index*2")
print("  mov.w @R1+,R0     ; R0 = int16 Y[index], R1 += 2")
print("  extu.w R0,R0      ; zero-extend")
print("  lds R0,MACH? ...")
print()
print("Y-axis is INT16 at 0xCE6CC, scaled by the 'extra' field (3.05e-5 = 1/32768):")
print()

y_ptr2 = 0xCE6CC
count2 = 16
scale = 1.0 / 32768.0
x_ptr2 = 0xCC624

print("  X-temp  Y-int16   Y-scaled (= FFFF79A0 value)")
print("  -------  -------   --------------------------------")
for i in range(count2):
    x_a = x_ptr2 + i*4
    y_a = y_ptr2 + i*2
    xv = read_float(x_a)
    yv = read_s16(y_a)
    ys = yv * scale
    print("  %5.0f C   %6d    %.8f" % (xv, yv, ys))

print()
print("NOTE: Negative/zero scaled values make no sense as decay coefficients.")
print("This Y-axis at 0xCE6CC is likely shared with ANOTHER table (RPM data starts at index 9).")
print("Check if the Y-axis pointer 0xCE6CC is incorrect or points to a different struct layout.")
print()

# Alternative: maybe the Y-axis is NOT at offset +8 of the descriptor.
# Let me look at the actual function to find the true Y-axis pointer.
# Going back to BEB6C: it receives R1 = whatever was loaded in the jsr delay slot.
# The jsr delay slot: mov.l @(8,R4),R1 -> R1 = [0xAD0DC+8] = [0xAD0E4] = 0x000CE6CC
# So CONFIRMED: R1 = 0xCE6CC is the Y-axis pointer.
# But these values don't look like decay coefficients.

# NEW HYPOTHESIS: Maybe the INIT function at 0x36962 is NOT for FFFF79A0 decay coefficient.
# Instead, FFFF79A0 might be written elsewhere, and the Y-axis table IS sensible
# for whatever quantity it sets at FFFF79A0 initialization.
#
# The question is: what is FFFF79A0 ACTUALLY used for?
# From the context: it's a float written during init via table lookup of coolant temp.
# The result from the table with coolant temp in [-40..110] maps to...
# At typical coolant temp 80C: Y[12] = int16 value 0xCE6FC = 0x44C80000 ?
# Wait! If the Y-axis is float32 DESPITE my decoding showing int16 reads...
#
# Let me reconsider. The dispatch value 8 -> index 8 bytes into table -> 0xBEB6C
# What if the dispatch INDEX is the FORMAT VALUE DIVIDED BY 4?
# Format = 8 -> index = 8/4 = 2 -> dispatch[2] = @(0xBE860+8) = 0xBEB6C
# Same result.
#
# OK, let me just try TREATING 0xCE6CC as float32 for the range that makes sense.
# At index 12 (80C coolant): 0xCE6CC + 12*4 = 0xCE6FC = 0x44C80000 = 1600.0 ???
# That can't be the decay coefficient.
#
# WAIT. Let me reconsider the ENTIRE chain.
# The init function at 0x36962:
#   FR4 = float from 0xFFFF6350
#   Table lookup with X=coolant_temp -> returns FR0
#   Store FR0 to FFFF79A0
#
# What if 0xFFFF6350 is NOT coolant temp?
# Let me check what FFFF6350 is.

print("="*80)
print("Checking what writes to FFFF6350 (source of FR4 in init function)")
print("="*80)

# Search for pool entries containing 0xFFFF6350
for addr in range(0, len(rom)-3, 4):
    v = read_u32(addr)
    if v == 0xFFFF6350:
        print("  Pool @0x%05X = 0xFFFF6350" % addr)

# Also check for GBR-relative access: GBR=0xFFFF7450, offset=(6350-7450)=-256 (too large for GBR)
print()
print("FFFF6350 - FFFF7450 = 0x%X (offset from GBR base)" % (0xFFFF6350 - 0xFFFF7450))
print("(GBR offsets max at +/-255 bytes for mov.b or +/-510 for mov.w)")
print("So FFFF6350 is NOT accessible via GBR directly.")
