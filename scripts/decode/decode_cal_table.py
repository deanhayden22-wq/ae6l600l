#!/usr/bin/env python3
"""
Decode the calibration table at 0xAD090 that controls the decay delta written to FFFF79E0.
"""
import struct
ROM_PATH = 'C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin'
with open(ROM_PATH, 'rb') as f:
    rom = f.read()

def ru16(a): return struct.unpack('>H', rom[a:a+2])[0]
def ru32(a): return struct.unpack('>I', rom[a:a+4])[0]
def rf32(a): return struct.unpack('>f', rom[a:a+4])[0]

# Descriptor format at 0xAD090 (used with lookup function 0xBE830):
#   +0  u16: element count (low byte)
#   +2  u8:  interpolation type
#   +4  ptr: axis table pointer
#   +8  ptr: value table pointer
#   +12 f32: scale factor (sometimes)
desc = 0xAD090
count = ru16(desc) & 0xFF
interp_type = (ru16(desc) >> 8) & 0xFF
axis_ptr = ru32(desc + 4)
val_ptr = ru32(desc + 8)
scale = rf32(desc + 12)

print("=" * 70)
print("Calibration table descriptor at 0xAD090")
print("(This produces FR0 = decay delta written to FFFF79E0)")
print("=" * 70)
print(f"Count:          {count}")
print(f"Interp type:    0x{interp_type:02X}")
print(f"Axis ptr:       0x{axis_ptr:05X}")
print(f"Value ptr:      0x{val_ptr:05X}")
print(f"Scale:          {scale:.8f} (= 1/{1.0/scale:.0f})")
print()

# The function 0xBE830 with type 0x08:
# byte[2] = 0x08 -> jump table index 2 -> sub 0xBEB6C
# But wait: extu.b R0,R3 gives R3=0x08
# mova @(0xBE860,PC),R0  -- jump table base
# 023E  mov.l @(R0,R3),R2  -- fetch R2 = jump_table[R3/4] if R3 is an index
# Actually R3=0x08 -> index 8/4=2 -> jump_table[2]
# But R3=0x08 could also be used directly as byte index into the table
# Let me check: mova points to 0xBE860, and 023E = mov.l @(R0,R3),R2
# R0 = 0xBE860, R3 = 0x08 -> address = 0xBE860 + 0x08 = 0xBE868 -> ru32(0xBE868) = 0x000BEB6C
jt_entry = ru32(0xBE860 + interp_type)
print(f"Jump table entry at 0xBE860 + 0x{interp_type:02X} = 0x{jt_entry:08X}")
print(f"  This calls sub_0x{jt_entry:05X} for interpolation")
print()

# The axis entries: for type 0x08 (=8), looking at sub_0xBEB6C
# Let's decode axis assuming it's the standard float format
print(f"Axis values at 0x{axis_ptr:05X} ({count} entries, as float32):")
axis_vals = []
for i in range(count):
    a = axis_ptr + i * 4
    if a + 3 < len(rom):
        fv = rf32(a)
        axis_vals.append(fv)
        print(f"  [{i:2d}] @0x{a:05X}: {fv:.4f}")

print()
print(f"Output values at 0x{val_ptr:05X} ({count} entries, as float32):")
val_vals = []
for i in range(count):
    a = val_ptr + i * 4
    if a + 3 < len(rom):
        fv = rf32(a)
        val_vals.append(fv)
        print(f"  [{i:2d}] @0x{a:05X}: {fv:.8f}")

print()
print("Axis/Value pairs:")
for i in range(min(len(axis_vals), len(val_vals))):
    print(f"  {axis_vals[i]:.4f} -> {val_vals[i]:.8f}")

# Now also decode the "second half" of the descriptor (at +16 = 0xAD0A0)
print()
print("=" * 70)
print("Second table descriptor at 0xAD0A4 (offset +20 from 0xAD090)")
print("=" * 70)
desc2 = 0xAD0A4
count2 = ru16(desc2) & 0xFF
interp_type2 = (ru16(desc2) >> 8) & 0xFF
axis_ptr2 = ru32(desc2 + 4)
val_ptr2 = ru32(desc2 + 8)
try:
    scale2 = rf32(desc2 + 12)
except:
    scale2 = 0

print(f"Count:          {count2}")
print(f"Interp type:    0x{interp_type2:02X}")
print(f"Axis ptr:       0x{axis_ptr2:05X}")
print(f"Value ptr:      0x{val_ptr2:05X}")
print(f"Scale:          {scale2:.8f}")
print()

print(f"Axis values at 0x{axis_ptr2:05X} ({count2} entries, as float32):")
for i in range(count2):
    a = axis_ptr2 + i * 4
    if a + 3 < len(rom):
        fv = rf32(a)
        print(f"  [{i:2d}] @0x{a:05X}: {fv:.4f}")

print()
print(f"Output values at 0x{val_ptr2:05X} ({count2} entries, as float32):")
for i in range(count2):
    a = val_ptr2 + i * 4
    if a + 3 < len(rom):
        fv = rf32(a)
        print(f"  [{i:2d}] @0x{a:05X}: {fv:.8f}")

# ============================================================
# The key fact we need:
# The data at CE5A4 and CE5B8 appear to be 0x00640064, 0x40800000=4.0 etc.
# Let's try reading the value table as u16 pairs
# ============================================================
print()
print("=" * 70)
print("Reading value table at 0xCE5A4 as u16 pairs:")
print("=" * 70)
for i in range(10):
    a = 0xCE5A4 + i * 2
    v = ru16(a)
    sv = struct.unpack('>h', rom[a:a + 2])[0]
    print(f"  [{i:2d}] @0x{a:05X}: 0x{v:04X} = {sv} (signed)")

# Also check if CE5A4 is interpreted as u8 values
print()
print("Reading value table at 0xCE5A4 as u8 pairs:")
for i in range(20):
    print(f"  [{i:2d}] 0x{rom[0xCE5A4 + i]:02X} = {rom[0xCE5A4 + i]}")

# The values 0x64, 0x64, 0x64, 0x64, 0x64, 0x32, 0x32, 0x25, 0x25, 0x00, 0x00, 0x00
# 0x64 = 100, 0x32 = 50, 0x25 = 37, these look like percentage or 1/100 values?
# If these are u8 values (0..255) and the function uses them as floats:
# 100 * scale?

print()
print("Interpreting u8 values as percentages (0-100 scale):")
vals_u8 = [rom[0xCE5A4 + i] for i in range(count)]
for i in range(min(count, len(axis_vals))):
    print(f"  axis={axis_vals[i]:.2f} -> {vals_u8[i]} (0x{vals_u8[i]:02X})")

print()
print("=" * 70)
print("Now checking the axis at 0xCE580 more carefully:")
print("The axis entries from BE830: @(0,R4)=0x0009, axis=R1=@(4,R4)")
print("bsr 0xBECA8 with R0=0x0009, R1=axis_ptr, FR0=input")
print()

# From BECA8 analysis - it's a search function that:
# - Reads from R1 (axis table), compares with FR0 (input)
# - Returns FR1=fractional position, R0=integer index
# Let's look at what format BECA8 reads

# From the disassembly of BECA8 (need to check), the axis data format:
# In SH2 ECU ROM (Subaru), typical formats:
# - u16 big-endian integers
# - f32 IEEE floats
# The fact that 0xCE580 shows 0x0000, 0x447A, 0x44FA, 0x453B, 0x457A, 0x459C
# as u16 PAIRS suggests float32: 0x00000000=0.0, 0x447A0000=1000.0, etc.
# But the earlier byte-by-byte showed:
# 0xCE580: 0x00, 0x00, 0x00, 0x00 -> 0.0
# 0xCE584: 0x44, 0x7A, 0x00, 0x00 -> 1000.0
# So the axis IS float32 values: 0.0, 1000.0, 2000.0, ...?

print("Reading axis at 0xCE580 as consecutive floats (4 bytes each):")
for i in range(count + 2):
    a = 0xCE580 + i * 4
    if a + 3 < len(rom):
        fv = rf32(a)
        print(f"  [{i:2d}] @0x{a:05X}: {fv:.4f}")

print()
print("Checking if bytes 0xCE580 are really float32:")
import struct
raw = rom[0xCE580:0xCE580+40]
print("Hex dump of 0xCE580..0xCE5A7:")
for i in range(0, 40, 4):
    b = raw[i:i+4]
    fv = struct.unpack('>f', b)[0]
    print(f"  {0xCE580+i:05X}: {b.hex()} -> float {fv:.4f}")
