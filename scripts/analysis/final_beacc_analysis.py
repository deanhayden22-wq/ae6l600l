#!/usr/bin/env python3
"""
Final analysis of BEACC + the descriptor at 0xAD090.
Key finding: 0xCE5A4 bytes are NOT valid f32 (00640064...).
This means either:
1. The val_ptr in descriptor at 0xAD090+8 does NOT point to 0xCE5A4
2. BEACC reads the table differently (e.g. lds Rn,FPUL then float FPUL,FRn for u16->float)
3. There's a scale factor applied

Let me re-read the descriptor and re-check.
"""
import struct
ROM_PATH = 'C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin'
with open(ROM_PATH, 'rb') as f:
    rom = f.read()

def ru16(a): return struct.unpack('>H', rom[a:a+2])[0]
def ru32(a): return struct.unpack('>I', rom[a:a+4])[0]
def rf32(a): return struct.unpack('>f', rom[a:a+4])[0]
def rs16(a): return struct.unpack('>h', rom[a:a+2])[0]

print("="*70)
print("DESCRIPTOR at 0xAD090 - full 16 bytes:")
print("="*70)
desc = 0xAD090
for i in range(0, 16, 2):
    v = ru16(desc + i)
    print(f"  +{i:2d} @{desc+i:05X}: 0x{v:04X} = {v}")
print()
print("As 32-bit words:")
for i in range(0, 16, 4):
    v = ru32(desc + i)
    fv = struct.unpack('>f', rom[desc+i:desc+i+4])[0]
    print(f"  +{i:2d} @{desc+i:05X}: 0x{v:08X}  (f32={fv:.6g})")
print()

# The descriptor format from BE830:
# +0  word: count (in low byte) + interp_type (in high byte)? Or the other way?
# Wait: BE832 reads mov.b @(2,R4) -> R0 for the count passed to BECA8
# Actually: the first disasm showed BE830 at 8540 which I decoded as "mov.b @(2,R4),R0"
# Let me check 0x8540:
op = ru16(0xBE832)
print(f"Opcode at 0xBE832: 0x{op:04X}")
print(f"  = {op:016b}")
# 8540 = 1000 0101 0100 0000
# Group 8: 1000 = 0x8
# Subgroup: bits 11-8 = 0101 = 5 -> mov.w @(disp,Rn) with R0
# Actually: group 8xxx:
# 8000 = mov.b R0,@(disp,Rm)
# 8100 = mov.w R0,@(disp,Rm)
# 8400 = mov.b @(disp,Rm),R0
# 8500 = mov.w @(disp,Rm),R0
# 8540 = mov.w @(4*2, R4),R0 = mov.w @(8,R4),R0 -> sign-extend word
# disp = (0x40 & 0xF) * 2 = 0 * 2 = 0?? No: 8540 = 1000 0101 0100 0000
# opcode[11:8] = 0101 = 5 -> mov.w @(disp,Rm),R0
# Rm = (opcode[7:4]) = 4
# disp = opcode[3:0] = 0 -> scaled by 2 -> disp_bytes = 0
# Wait: disp8 in group 8 is 8 bits (opcode[7:0] = 0x40)?
# Actually: format is 1000 0101 RRRR DDDD where R=Rm, D=disp (not scaled here?)
# Let me check: SH-2 mov.w @(disp,Rn),R0: opcode 0x8500 | (Rn<<4) | disp
# 8540: 0x85 = 1000 0101, sub=5=mov.w; 0x40 = 0100 0000
# Rn = (0x40>>4) & 0xF = 4
# disp = 0x40 & 0xF = 0 (scaled by 2 = 0 bytes??)
# Hmm: mov.w @(0,R4),R0 -> reads word from R4+0
# But if +0 has count/interp_type as u16, it could be reading the first word
print(f"BE832: 0x8540 = mov.w @(0,R4),R0  ; R0 = word at desc+0")
print(f"  desc+0 = 0x{ru16(desc):04X} = {ru16(desc)}")
print(f"  high byte = 0x{ru16(desc)>>8:02X} = {ru16(desc)>>8}  (passed to BECA8 as count?)")
print(f"  low byte = 0x{ru16(desc)&0xFF:02X} = {ru16(desc)&0xFF}  (interp type?)")
print()

# Wait, the earlier analysis said:
# count = ru16(desc) & 0xFF = 9 (low byte)
# interp_type = (ru16(desc) >> 8) & 0xFF = 0
# axis_ptr = ru32(desc+4)
# val_ptr = ru32(desc+8)
# So: desc+0 word = 0x0009 -> count=9, interp_type=0
#
# But the descriptor read I need to double-check:
# BE832: reads mov.w @(0,R4) -> R0 = 0x0009
# This R0 is then passed to BECA8 as "count"
# Then BE83C: 8442 = mov.w @(4,R4),R0 -> R0 = word at desc+4
# Then BE83E: 630C extu.b -> R3 = lower byte = interp_type

v_at_0 = ru16(desc + 0)  # 0x0009
v_at_4 = ru16(desc + 4)  # first word of axis_ptr
print(f"desc+0: 0x{v_at_0:04X} -> count passed to BECA8 = {v_at_0} (i.e. as R0 directly)")
print(f"  BUT BECA8: add #-1,R0 -> count-1 = {v_at_0-1}")
print()

# For BE83C: mov.w @(4,R4),R0
# But wait: desc+4 would be the first 2 bytes of the axis_ptr (which is 0x000CE580)
# @(4,0xAD090) = @0xAD094 = two bytes = 0x000C (high word of 0x000CE580)
# Actually the axis_ptr is at desc+4 as 4 bytes: 0x000CE580
# As a u16 from @(4,R4): 0x000C
# extu.b -> R3 = 0x0C = 12 -> interp_type = 12??
# That contradicts earlier analysis.

print("Checking descriptor layout more carefully:")
print(f"  @(0,desc) u16 = 0x{ru16(desc+0):04X}")
print(f"  @(2,desc) u16 = 0x{ru16(desc+2):04X}")
print(f"  @(4,desc) u32 = 0x{ru32(desc+4):08X} (axis_ptr?)")
print(f"  @(4,desc) u16 = 0x{ru16(desc+4):04X}")
print(f"  @(8,desc) u32 = 0x{ru32(desc+8):08X} (val_ptr?)")
print(f"  @(12,desc) f32 = {rf32(desc+12):.8f} (scale?)")
print()

# Hmm. Earlier I assumed:
# count = @(+0,desc) & 0xFF = 9
# interp_type = (@(+0,desc) >> 8) & 0xFF = 0
# axis_ptr = @(+4,desc) = 0x000CE580
# val_ptr = @(+8,desc) = 0x000CE5A4
#
# But actually BE830 does:
# "mov.b @(2,R4),R0"  (R0 = count as byte at desc+2) -- OR
# "mov.w @(0,R4),R0"  (R0 = word at desc+0)
# then bsr BECA8 with FR0=input

# The opcode 0x8540: let me re-decode this properly
# Group 8: opcodes 0x8000-0x8FFF
# 8000-80FF: mov.b R0,@(disp,Rn)  -- store
# 8100-81FF: mov.w R0,@(disp,Rn)  -- store
# 8400-84FF: mov.b @(disp,Rn),R0  -- load byte, sign-extend
# 8500-85FF: mov.w @(disp,Rn),R0  -- load word, sign-extend
# 8800-88FF: cmp/eq #imm,R0
# 8900-89FF: bt
# 8B00-8BFF: bf
# 8D00-8DFF: bt/s
# 8F00-8FFF: bf/s
#
# 0x8540: 1000 0101 0100 0000
# bits[15:8] = 0x85 -> group 85xx = mov.w @(disp,Rn),R0
# bits[7:4] = 4 -> Rn = 4
# bits[3:0] = 0 -> disp = 0 * 2 = 0
# So: mov.w @(0,R4),R0 -- reads word at R4+0

print("CORRECT decode of BE832 (0x8540):")
print("  mov.w @(0,R4),R0  (load word from desc+0)")
print(f"  value = 0x{ru16(desc):04X}")
print()
# BE830 passes R0 to BECA8. BECA8 does "add #-1,R0" -> count for search
# desc+0 = 0x0009 -> passed as count=9
# BUT: for BECA8, R0 is also the axis_ptr? No: R1=axis_ptr
# So R0 = 0x0009 -> count
# Also R1 = axis_ptr from 5141: mov.l @(4,R4),R1

# After BECA8 returns:
# BE83A: 6103 mov R0,R1 -> R1 = return_index_from_BECA8
# BE83C: 8442 -> mov.b @(2,R4),R0 OR mov.w @(4,R4),R0?
op_83c = ru16(0xBE83C)
print(f"Opcode at 0xBE83C: 0x{op_83c:04X}")
# 8442 = 1000 0100 0100 0010
# bits[15:8] = 0x84 -> group 84xx = mov.b @(disp,Rn),R0 (load byte, sign extend? or zero extend?)
# Actually: SH-2 mov.b @(disp,Rn),R0 zero-extends? Let me check:
# SH-2 "MOV.B @(disp,Rn),R0" transfers byte with SIGN EXTENSION
# bits[7:4] = 4 -> Rn = 4
# bits[3:0] = 2 -> disp = 2 * 1 = 2
# So: mov.b @(2,R4),R0  (load signed byte at desc+2)
print(f"  = mov.b @(2,R4),R0  (sign-extended byte at desc+2)")
print(f"  desc+2 byte = 0x{rom[desc+2]:02X} = {rom[desc+2]}")
print()

# Hmm: 0x8442 = 0x84 prefix, Rn=4, disp=2
# So the byte at desc+2 is the interp_type
# desc+2 = ?

# Let me print all the bytes:
print("Descriptor at 0xAD090 byte-by-byte:")
for i in range(16):
    print(f"  +{i:2d} @{desc+i:05X}: 0x{rom[desc+i]:02X} = {rom[desc+i]}")
print()

# So:
# +0: 0x00 or 0x09?
# +2: interp_type
# +4: axis_ptr (u32)
# +8: val_ptr (u32)
# +12: scale (f32)
b0 = rom[desc+0]; b1 = rom[desc+1]
interp_byte = rom[desc+2]
axis_ptr_real = ru32(desc+4)
val_ptr_real = ru32(desc+8)
scale_real = rf32(desc+12)
print(f"Corrected descriptor layout:")
print(f"  +0 byte = 0x{b0:02X} = {b0}  (count?)")
print(f"  +1 byte = 0x{b1:02X} = {b1}  (?)")
print(f"  +2 byte = 0x{interp_byte:02X} = {interp_byte}  (interp_type)")
print(f"  +4 u32  = 0x{axis_ptr_real:08X} = axis_ptr")
print(f"  +8 u32  = 0x{val_ptr_real:08X} = val_ptr")
print(f"  +12 f32 = {scale_real:.8f} = scale")
print()

# But wait -- BE832 is "mov.w @(0,R4),R0" which reads 2 bytes.
# R0 = word at desc+0. This is passed to BECA8 as count.
# The word could have count in both bytes, or count in one half.
# BECA8 does "add #-1,R0" -> if R0=0x0009, then 0x0008.
# Then shll2 -> 0x0020 = last axis byte offset.
# That makes perfect sense for 9 entries.
# So count = 9 is correct.

# Now for interp_type: BE83C is 0x8442 = mov.b @(2,R4),R0
# Then BE83E: extu.b R0,R3 -> R3 = interp_type
# desc+2 byte = ?
print(f"Interp type from desc+2: 0x{rom[desc+2]:02X}")
print()

# And BE848 delay slot: 5142 = mov.l @(0x08,R4),R1
# 5142: 0101 0001 0100 0010
# n=1, m=4, disp=2 -> mov.l @(2*4, R4),R1 = mov.l @(8,R4),R1
# R1 = val_ptr = ru32(desc+8) = 0x000CE5A4
print(f"val_ptr from desc+8: 0x{val_ptr_real:08X}")
print()

# Now: BECA8 entry with R0=9, R1=axis_ptr=0xCE580, FR0=input(RPM)
# BECA8: add #-1,R0 -> 8
# shll2 R0 -> 32 (= 8*4 = last f32 offset)
# fmov.s @R1,FR1 -> FR1 = axis[0] = 0.0
# fmov.s @(R0,R1),FR0 -> FR0 = axis[8] = 8000.0

# This overwrites FR0! So the input RPM value is gone???
# Wait - that's the compare target, not the input.
# Actually let me re-read BECA8 properly:

print("="*70)
print("BECA8 COMPLETE TRACE with annotation:")
print("="*70)
print("Entry: R0=count=9, R1=axis_ptr=CE580, FR0=input_RPM")
print()
print("  BECA8: 70FF  add #-1,R0            ; R0 = 8 (last index)")
print("  BECAA: 4008  shll2 R0              ; R0 = 32 = 8*4 (last byte offset)")
print("  BECAC: F116  fmov.s @R1,FR1        ; FR1 = f32@CE580 = axis[0] = 0.0")
print("  BECAE: F105  fmov.s @(R0,R1),FR0   ; FR0 = f32@(CE580+32) = axis[8] = 8000.0")
print("  ;; NOTE: input RPM was in FR0, now OVERWRITTEN with axis[last]!")
print("  ;; So how does it compare? It seems BECA8 doesn't use original FR0...")
print("  ;; Actually wait - let me re-read. The input was in FR4 at BE830.")
print("  ;; BE836: bsr BECA8, delay slot: FR0 = FR4")
print("  ;; So at BECA8 entry: FR0 = input_RPM (just set in delay slot)")
print("  ;; BECAC sets FR1 = axis[0]")
print("  ;; BECAE sets FR0 = axis[last]  -- OVERWRITES input!")
print()
print("  HMMMM: BECA8 overwrites FR0 with axis[last] immediately after entry.")
print("  This can't be right for a comparison-based search.")
print("  Let me check: F116 and F105 again...")
print()

# F116 = 1111 0001 0001 0110
# n=1, m=1, sub=6 -> fmov.s @R1,FR1? sub=6 is @Rm -> FRn
# n=1 (destination), m=1 (source Rm=R1), sub=6 -> fmov.s @R1,FR1 -> YES

# F105 = 1111 0001 0000 0101
# n=1, m=0, sub=5 -> fmov.s @(R0,R0),FR1?
# No: fmov.s @(R0,Rm),FRn with n=1, m=0 -> fmov.s @(R0,R0),FR1?
# That's addr = R0+R0 = 2*R0 = 64 -> @(CE580+64)??
# Wait: n=1 -> FRn=FR1 (dest), m=0 -> Rm=R0 (base), sub=5 -> @(R0,Rm)
# sub=5: fmov.s @(R0,Rn),FRm -- NO that has different field mapping
# SH-2 fmov.s @(R0,Rn),FRm: 1111mmmmnnn10101
# Actually I need to be more careful.

print("Re-decoding F105:")
op2 = 0xF105
# SH-2 FPU encoding: 1111nnnnmmmm_type
# type field = bits[3:0]
# sub=5: fmov.s @(R0,Rn),FRm -- wait, different sources say different things
# Let me check by function:
# Opcode 0xF105:
# Binary: 1111 0001 0000 0101
# If sub=5 means "fmov.s @(R0,Rn),FRm":
#   Standard encoding: n field = destination register?
#   0xF105 -> n_bits = (F105>>8)&F = 1, m_bits = (F105>>4)&F = 0
#   Interpretation depends on which is n (Rn) and which is m (FRm)
# For fmov.s @(R0,Rm),FRn (SH-2 manual):
#   Opcode: 1111nnnnmmmm0101
#   n = FRn (float dest), m = Rm (int reg for address)
#   So F105: n=1 (FR1 dest), m=0 (R0 for address) -> fmov.s @(R0,R0),FR1
#   addr = R0 + R0 = 2*32 = 64 -> @(CE580+64)?? That seems wrong.
#
# WAIT - there are TWO forms:
# 0xF005: 1111nnnnmmmm0101 = fmov.s @(R0,Rm),FRn  -> @(R0+Rm) -> FRn
#   0xF005: n=0, m=0 -> fmov.s @(R0,R0),FR0
#   0xF105: n=1, m=0 -> fmov.s @(R0,R0),FR1  ??? (uses R0 as both index and base?)
# That's weird. Maybe R0 here was already set to 0 from before?

print(f"  0xF105: n=1, m=0, sub=5")
print(f"  fmov.s @(R0,R0),FR1  -- addr = R0+R0 = 2*32 = 64")
print(f"  @(CE580+64) = f32@{0xCE580+64:05X}")
print(f"  value = {rf32(0xCE580+64):.4f}")
print()
print("  WAIT: If R0=32 at this point, @(R0+R0)=@(CE580+64) = axis[16] which is OUT OF BOUNDS")
print("  For a 9-entry table! This cannot be right.")
print()
print("  ALTERNATIVE DECODE: In SH-2, fmov.s @(R0,Rn),FRm vs fmov.s @(R0,Rm),FRn")
print("  SH-2 programmer manual says: FMOV.S @(R0,Rn),FRm with opcode 1111mmmmnnnnn0101")
print("  i.e. n is the INT reg, m is the FLOAT reg")
print("  0xF105: m=1 (FR1), n=0 (R0)?  -> fmov.s @(R0,R0),FR1 -- still R0+R0")
print()

# Actually: SH-2 manual says for fmov.s:
# Format: FMOV.S @(R0,Rn),FRm
# Encoding: 1111 mmmm nnnn 0101
# where m = FRm (float dest register), n = Rn (base int register)
# 0xF105 = 1111 0001 0000 0101 -> m=1 (FR1), n=0 (R0)
# addr = R0 + R0 = 2*R0
# BUT: R0 at this point was just set to 32 by shll2 R0
# So addr = 32+32 = 64??
# That gives axis[16] for a 9-entry table -- impossible.
#
# MAYBE: R0 is RESET to something between BECAA and BECAE?
# Let me check: the delay slot of bf/s at BECB0 is 2008 = tst R0,R0
# But that's AFTER BECAE, not before.
#
# UNLESS: The first scan is for the LAST axis entry:
# At entry: R0 = count-1 (byte offset), R1 = axis_ptr
# BECAC: FR1 = axis[0]
# BECAE: addr = R0 + R1? No, addr = R0 + R0 (both R0)???
#
# Wait - I think I'm confusing the encoding. Let me look at this differently:
# fmov.s @(R0,Rn),FRm:
# SH-2 manual encoding: 1111mmmm(0)nnnn0101 but there are only 4 bits for n
# 0xF105:
# bits [15:12] = F = 1111 (FPU group)
# bits [11:8]  = 1 = 0001 -> this is n (the general reg part)?
# bits [7:4]   = 0 = 0000 -> this is m (the float reg part)?
# bits [3:0]   = 5 = 0101 -> sub-opcode
#
# From SH-2/SH7058 manual:
# FMOV.S @(R0,Rn),FRm: 1111mmmmnnnnn0101
# The field layout: FRm in bits[11:8], Rn in bits[7:4]
# So 0xF105: FRm = bits[11:8] = 1 (FR1), Rn = bits[7:4] = 0 (R0)
# addr = R0 + R0... same result.
#
# UNLESS the SH-2 uses a DIFFERENT field mapping where:
# FRm is in [7:4] and Rn is in [11:8]
# 0xF105: Rn=1 (R1), FRm=0 (FR0) -> fmov.s @(R0,R1),FR0
# addr = R0 + R1 = 32 + CE580 = CE5A0
# axis value at CE5A0?

print("Alternative: if Rn is in bits[11:8] and FRm is in bits[7:4]:")
print(f"  0xF105: Rn = bits[11:8] = 1 -> R1")
print(f"  FRm = bits[7:4] = 0 -> FR0")
print(f"  addr = R0 + R1 = 32 + 0xCE580 = 0xCE5A0")
v_at_CE5A0 = rf32(0xCE5A0)
print(f"  f32 at 0xCE5A0 = {v_at_CE5A0:.4f}")
print()

# This would be axis[8] = 8000.0 if CE5A0 = CE580 + 0x20 = CE580 + 32 (= index 8 * 4)
# CE580 + 32 = CE5A0 -> YES! That's axis[8] = 8000.0
print(f"  CE580 + 32 = 0x{0xCE580+32:05X} = 0xCE5A0 -> axis[8] = 8000.0? {rf32(0xCE5A0):.4f}")
print()
print("AHA! So the correct decoding is:")
print("  F105: fmov.s @(R0,R1),FR0  (Rn=R1, FRm=FR0)")
print("  addr = R0 + R1 = 32 + CE580 = CE5A0 = last axis entry")
print("  FR0 = axis[last] = 8000.0")
print()
print("This makes sense! The axis search first loads FR1=axis[0]=0.0, FR0=axis[last]=8000.0")
print("Then searches by scanning backwards")
print()

# So the correct SH-2 encoding for fmov.s @(R0,Rn),FRm is:
# bits[11:8] = Rn (base int register)
# bits[7:4]  = FRm (float destination)
#
# Similarly for BEACC F219:
# 0xF219 = 1111 0010 0001 1001
# sub=9: fmov.s @(R0+Rn),FRm? Or post-increment?
# sub=9 does NOT match 0101 for @(R0,Rn).
# Let me check what sub=9 is:
# From SH-2 manual:
# 1001 = fmov.s @Rm+,FRn -> post-increment load
# So F219: n=2 (FR2), m=1 (R1), sub=9 -> fmov.s @R1+,FR2?
# But wait: encoding for fmov.s @Rm+,FRn is 1111nnnnmmmm1000
# sub=8 for post-increment: 0xF218 would be fmov.s @R1+,FR2
# sub=9: fmov.s @(R0,Rn),FRm? That's sub=5...

print("="*70)
print("SH-2 FPU sub-opcode table:")
print("="*70)
print("  0 = fadd   FRm,FRn")
print("  1 = fmul   FRm,FRn")
print("  2 = fdiv   FRm,FRn")
print("  3 = fcmp/eq FRm,FRn")
print("  4 = fcmp/lt FRm,FRn (or fcmp/gt depending on field order)")
print("  5 = fmov.s @(R0,Rn),FRm  [Rn=bits[11:8], FRm=bits[7:4]]")
print("  6 = fmov.s @Rn,FRm")
print("  7 = fmov.s FRm,@(R0,Rn)")
print("  8 = fmov.s @Rm+,FRn  (post-increment)")
print("  9 = fmov.s @-Rn,FRm  (pre-decrement store?) -- hmm")
print(" OR: 9 = fmov.s @(R0,Rn),FRm  different form?")
print()
print("Checking SH-2 opcode F219 more carefully:")
op4 = 0xF219
n4 = (op4>>8)&0xF  # 2
m4 = (op4>>4)&0xF  # 1
sub4 = op4&0xF     # 9
print(f"  0xF219: n={n4}, m={m4}, sub={sub4}")
print()
# SH-2 sub=9: FMOV instruction
# From the SH-2 programmer's manual:
# FMOV @(R0,Rn),FRm: 1111 mmmm nnnn 0110  -- wait, that's sub=6
# Let me use the actual table:
# FMOV.S @(R0,Rn),FRm: 1111mmmmnnnnn0101  sub=5
# FMOV.S @Rm,FRn:      1111nnnnmmmm0110   sub=6
# FMOV.S @Rm+,FRn:     1111nnnnmmmm1000   sub=8 (post-increment Rm+=4)
# FMOV.S FRm,@Rn:      1111nnnnmmmm1010   sub=A
# FMOV.S FRm,@-Rn:     1111nnnnmmmm1011   sub=B (pre-decrement Rn-=4)
# FMOV.S FRm,@(R0,Rn): 1111nnnnmmmm0111   sub=7
# FMOV FRm,FRn:        1111nnnnmmmm1100   sub=C
# sub=9 is NOT a standard fmov?
# Maybe sub=9 is: fmov.s @Rn+,FRm (with Rn in bits[11:8], FRm in bits[7:4])?

print("F219 with sub=9: checking if this is @Rm+,FRn where m and n swap:")
print(f"  If n_field=bits[11:8]=2, m_field=bits[7:4]=1: @R{m4}+,FR{n4} = @R1+,FR2?")
print(f"  OR: if sub=9 = fmov.s @(R0,Rn),FRm with different encoding?")
print()

# Let me just look at what makes semantic sense in BEACC:
# We're in the value table interpolation routine:
# R0 = index * 4 (after shll2)
# R1 = val_ptr + index*4 (after add R0,R1)
# We need to read val[index] and val[index+1] for linear interpolation
#
# fmov.s @(R0,R1),FR2 [if sub=5, or rather sub=9]:
#   if addr = R0+R1 = index*4 + (val_ptr+index*4) = val_ptr + 2*index*4
#   That's val[2*index] which is wrong
#
# fmov.s @R1+,FR1 [sub=8]:
#   FR1 = f32 at R1, R1 += 4
#   = f32 at val_ptr + index*4 = val[index]
#
# fmov.s @R1,FR2 [sub=6]:
#   FR2 = f32 at R1+4 (after post-increment above) = val[index+1]
#
# So the sequence should be:
# @R1+,FR1 -> FR1 = val[index], R1 points to val[index+1]
# @R1,FR2  -> FR2 = val[index+1]
# fmul + fmac for linear interp

# Looking at BEACC again:
# BEACC: F28D -> fldi0 FR2  (FR2 = 0.0)
# BEACE: 4008 -> shll2 R0   (R0 = index*4)
# BEAD0: 310C -> add R0,R1  (R1 = val_ptr + index*4)
# BEAD2: F204 -> fcmp/lt FR0,FR2 (compare FR0 vs FR2=0.0)
# BEAD4: 8D03 -> bt/s -> if T (FR2<FR0 i.e. 0<FR0 i.e. FR0>0), branch to BEADE (rts)
#               delay slot: F219 ??
# BEAD8: F118 -> fmov.s @R1+,FR1  (FR1 = val[index], R1+=4)
# BEADA: F121 -> fmul FR2,FR1     (FR1 = FR1 * FR2 = val[index] * fractional)
# BEADC: F21E -> fmac FR0,FR1,FR2 (FR2 = FR0*FR1 + FR2)

# WAIT: fmac is FR2 = FR0 * FR1 + FR2 (before fmul step above)?
# But that would be: FR2 = FR0 * (val[index] * frac) + FR2
# where FR2 was 0.0 initially -> FR2 = FR0 * val[index] * frac

# Hmm, that doesn't look right for linear interpolation.
# Standard linear interp: result = val[i] + frac * (val[i+1] - val[i])
#                                 = val[i] * (1-frac) + val[i+1] * frac

# Let me reconsider what's in FR0 at BEACC entry.
# BECA8 returns: R0 = index, and also modifies FR0/FR1
# Looking at BECA8 more carefully...

print("="*70)
print("Re-analyzing BECA8 return values:")
print("="*70)
print()
print("BECA8 last few instructions (just before rts):")
print("  BECC0: F011  fmul FR1,FR0  -- FR0 = FR0 * FR1")
print("  BECC2: 7004  add #4,R0     -- R0 += 4 (??)")
print("  BECC4: F216  fmov.s @R2,FR1 -- but R2 is not defined!?")
print("  ...this doesn't make sense.")
print()
print("WAIT: Looking at the bf/s branches more carefully:")
print("  BECB0: 8F0E  bf/s 0xBECD0  -- branch if T=0")
print("         delay slot: tst R0,R0 -> T=1 if R0==0")
print("  So: tst R0,R0; bf/s BECD0 -> if R0!=0, take branch to BECD0")
print()
print("At BECCD0:")
print("  BECD0: 4009  shlr2 R0  -- R0 >>= 2 (= last_index)")
print("  BECD2: 000B  rts")
print("  BECD4: F08D  fldi0 FR0 -- delay slot: FR0 = 0.0")
print()
print("  So if R0 != 0 (count > 1), branch to BECD0 which returns R0=index, FR0=0.0??")
print()
print("At BECCD6 (other branch):")
print("  BECD6: E000  mov #0,R0  -> R0 = 0")
print()
print("Hmm, this branch analysis is getting complex. Let me focus on the")
print("main path (input in range [axis[0], axis[last]])...")

# Actually looking at this again, I think BECA8 is a backward linear scan:
# It loads axis values backwards, comparing with the input (original FR0)
# When it finds the bracket, it sets FR1 = fractional, R0 = index
# The branches handle out-of-range cases

# The key question is: after BECA8 returns AND after BE83C reloads R0,
# what is in FR0 and FR1 when BEACC is called?

print()
print("="*70)
print("CRITICAL: What is FR0 when BEACC is entered?")
print("="*70)
print()
print("Flow from BECA8 call to BEACC call:")
print("  BE836: bsr BECA8; delay FR0=FR4=RPM")
print("  -- BECA8 runs, modifying FR0 and FR1 --")
print("  BE83A: mov R0,R1    (R1 = return_index)")
print("  BE83C: mov.b @(2,R4),R0  (R0 = interp_type byte from desc)")
print("  BE83E: extu.b R0,R3  (R3 = interp_type)")
print("  BE840: mova ->R0 = jump_table_base")
print("  BE842: mov.l @(R0,R3),R2  (R2 = handler fn ptr)")
print("  BE844: mov R1,R0  (R0 = return_index)")
print("  BE846: jsr @R2;  delay: mov.l @(8,R4),R1  (R1 = val_ptr)")
print()
print("  So FR0 at BEACC entry = whatever BECA8 returned in FR0")
print("  And FR1 at BEACC entry = whatever BECA8 returned in FR1")
print()
print("  From BECA8 analysis, when input is in range:")
print("  It uses the main loop path - let's trace that carefully")
print()

# BECA8 main path when input is IN RANGE (between axis values):
# Entry: R0=9, R1=axis_ptr=CE580, FR0=RPM
# BECA8: add #-1,R0 -> R0=8
# shll2 R0 -> R0=32 (last byte offset)
# fmov.s @R1,FR1 -> FR1 = axis[0] = 0.0
# fmov.s @(R0,R1),FR0 -> ... wait, this OVERWRITES the input RPM in FR0!
#
# Unless... the check at BECB0 is: does the input (original FR0, now overwritten)
# compare against axis[last]?
# But FR0 was overwritten by BECAE!
#
# AH WAIT: Maybe BECA8 doesn't get the input in FR0.
# Let's re-read: BE836 is "bsr 0xBECA8" with delay slot "fmov FR4,FR0"
# The delay slot EXECUTES BEFORE the bsr takes effect.
# So FR0 = FR4 = RPM BEFORE BECA8 starts.
#
# But then BECAE does fmov.s @(R0,R1),FR0 which overwrites it!
#
# UNLESS the scan works differently:
# Maybe BECA8 first stores the input FR0 somewhere, then does the search.
# Looking at opcodes again:
# F116: fmov.s @R1,FR1 -> FR1 = axis[0]
# F105: fmov.s @(R0,R1),FR0 -> ...
#
# Wait: I decoded F105 wrong earlier. Let me be precise.
# F116 = 1111 0001 0001 0110 -> sub=6 (fmov.s @Rm,FRn): n=1(FR1), m=1(R1) -> fmov.s @R1,FR1
# F105 = 1111 0001 0000 0101 -> sub=5 (fmov.s @(R0,Rn),FRm):
#   If bits[11:8] = Rn (base) and bits[7:4] = FRm (dest):
#   Rn=1 (R1), FRm=0 (FR0) -> fmov.s @(R0,R1),FR0
#   addr = R0+R1 = 32+CE580 = CE5A0
#   CE5A0 = CE580 + 32 = axis[8] = 8000.0
#
# But this overwrites FR0 (the input)!
#
# ALTERNATIVE: Maybe R0 was SET to something before BECA8 call that I missed.
# No - the delay slot is "fmov FR4,FR0" which is a float move, not R0.

print("CONCLUSION from BECA8 analysis:")
print("BECA8 appears to compare axis entries against each other, not against")
print("the original FR0 input. The input must be stored in FPUL via ftrc")
print("or some other mechanism BEFORE the search loop.")
print()
print("Looking at BECA8 in context of BE830 more carefully:")
print("At BECA8 entry: R0=9 (count), R1=axis_ptr, FR0=input (from delay slot)")
print("The function does NOT save FR0 first... so the input IS the compare target?")
print()
print("Let me look at what 0x2008 (tst R0,R0) in the delay slots does:")
print("BECB2 (delay slot of bf/s at BECB0): tst R0,R0")
print("  R0 at this point = 32 (from shll2 R0=8)")
print("  tst 32,32 -> T = 0 (non-zero) -> bf/s goes to BECD0")
print("  So immediately: shlr2 R0 -> R0=8, rts with delay fldi0 FR0 -> FR0=0.0")
print()
print("WAIT - bf/s means 'branch if False (T=0)'. If T=0 (R0!=0), branch to BECD0.")
print("R0=32 (non-zero) -> T=0 -> branch TAKEN -> goes to BECD0")
print("BECD0: shlr2 R0 -> R0 = 8 = last_index (= count-1)")
print("BECD2: rts")
print("BECD4: fldi0 FR0  (delay: FR0 = 0.0)")
print()
print("So BECA8 ALWAYS takes the bf/s at BECB0 if R0 (count-1)*4 != 0?!")
print("That means it only returns after 2 comparisons: axis[0] vs FR0, axis[last] vs ??")
print()
print("This seems like the function checks if input < axis[0] (-> return 0, FR0=0)")
print("or input >= axis[last] (-> return last_index, FR0=??)")
print("and the MAIN path goes to the backward scan at BECB4...")

# Let me trace more carefully:
# At BECA8: R0=9, R1=axis_ptr, FR0=input_RPM
# add #-1,R0 -> R0=8
# shll2 R0 -> R0=32
# fmov.s @R1,FR1 -> FR1=axis[0]=0.0
# fmov.s @(R0,R1),FR0 -> FR0=axis[last]=8000.0  -- OVERWRITES input!
#
# OH WAIT - I think I've been wrong about the instruction.
# Let me decode F105 from scratch using the SH-2 hardware manual:
#
# SH-2/SH7058 FPU instructions:
# FMOV.S @(R0,Rm),FRn: Format 1111nnnnmmmm0101
#   where n = FRn (destination float), m = Rm (general reg, base addr)
#   effective addr = R0 + Rm
#
# 0xF105 = 1111 0001 0000 0101
#   n_field (bits[11:8]) = 0001 = 1 -> FRn = FR1 (destination)
#   m_field (bits[7:4])  = 0000 = 0 -> Rm = R0 (base)
#   sub = 0101 = 5
#   addr = R0 + R0 = 2*R0 = 64
#   FR1 = f32@(axis_ptr + 64) = axis[16]??? NO, this is wrong
#
# ALTERNATIVELY:
# FMOV.S @(R0,Rm),FRn: some sources say format 1111nnnn(0)mmm0101
# where Rm is the base and FRn is the destination
# but both n and m are 4-bit fields in 0xF105...

print()
print("="*70)
print("Let me look at the fcmp result and branch conditions more carefully")
print("to understand BECA8's algorithm:")
print("="*70)
print()
# Let me just look at the opcodes around the bf/s BECB0 differently:
# BECAC: F116 fmov.s @R1,FR1    -- FR1 = axis[0] = 0.0
# BECAE: F1XX -> something
# BECB0: 8F0E bf/s BECD0        -- delay slot BECB2 sets T
# BECB2: 2008 tst R0,R0         -- T=1 if R0==0 (= last_byte_offset==0 = only 1 entry)
#
# If input is already after BECB0 went to BECD0 (T=0 i.e. count>1):
# BECD0: shlr2 R0 -> R0 = last_index = 8
# rts with FR0 = 0.0
#
# Hmm, if the function ALWAYS jumps to BECD0 when count>1, that means it always
# returns R0=last_index... which doesn't make sense for an axis search.
#
# I must be misreading the branch condition. Let me reconsider:
# BECB0: 8F0E bf/s 0xBECD0 -> disp = 0E, addr = BECB0+4 + 0E*2 = BECB4 + 28 = BECD0 (correct)
# bf/s = branch if false (T=0) with delay slot
# Delay slot BECB2: tst R0,R0 -> SETS T based on R0 AT THE TIME of BECB2, not BECB0
# Since tst is in the DELAY SLOT, it executes BEFORE the branch is taken.
# So: T = (R0==0) ? 1 : 0
# bf/s branches if T==0 (i.e. R0!=0) -> branch BECD0
#
# R0 = 32 (from shll2 R0=8) != 0 -> T=0 -> branch to BECD0 TAKEN
# This returns immediately with shlr2 R0 (R0=8), FR0=0.0
#
# BUT WAIT: what if BECAE SETS R0 to 0 as a side-effect?
# BECAE: fmov.s @(R0,R1),FR0 or @(R0,R0),FR1 -- this is a FLOAT instruction, doesn't change R0
# So R0 stays 32.
#
# THEREFORE BECA8 always returns immediately for count>1 tables:
# R0 = last_index = count-1 = 8
# FR0 = 0.0
# This makes NO sense for an axis search.
#
# CONCLUSION: I must be misidentifying the branch target.
# Let me recalculate BECB0 offset:
# 8F0E: 1000 1111 0000 1110
# sub=8F, disp=0E, signed: 0E = 14 -> positive
# addr = BECB0 + 4 + 14*2 = BECB4 + 28 = BECD0
print(f"BECB0: bf/s to {0xBECB0+4+0x0E*2:05X}")
# 0xBECB0 + 4 + 28 = 0xBECCC... let me recalc
print(f"  = 0x{0xBECB0+4+0x0E*2:05X}")

# 0xBECB0 = 0xBECB0
# + 4 = 0xBECB4
# + 14*2 = 28 = 0x1C
# = 0xBECD0
# YES BECD0 is correct.

# WAIT: bf/s means "Branch if False, with delay slot"
# FALSE = T flag is 0 = not set
# But the delay slot tst R0,R0 SETS T.
#
# For bf/s, the T flag is evaluated AFTER the delay slot executes.
# So: delay slot runs (tst R0,R0 sets T to 1 if R0==0, 0 if R0!=0)
# THEN: branch taken if T==0 (i.e. R0!=0) -> goes to BECD0
# With R0=32: T=0 -> branch taken -> BECD0 immediately
#
# This really does seem to always branch. Unless BECAE changes R0?
# BECAE is fmov.s which should NOT change integer registers.
#
# WAIT - could the branch be: BECB4 (not BECD0)?
# No, I calculated BECD0 correctly.
#
# Let me just accept that for the main path with RPM in range:
# BECA8 returns R0=8 (last_index), FR0=0.0
# Then BEACC would look up val[8] = 37
# That's actually reasonable for RPM=8000 (top of range)
# But for RPM=1000, it should return index=1, fraction=0.0
#
# I think my decoding of F1XX must be wrong, OR
# BECA8 has more logic than I see.
#
# Let me try: what if BECA8 does a linear search comparing FR0 against each axis entry?
# The scan at BECB4-BECBC looks like the real search loop.
# Maybe the first branch (bf/s BECB0) is a FORWARD JUMP past the initial check?
# bf/s would branch FORWARD if T=0. 0E*2=28 bytes forward = BECD0.
# But maybe I should read it as bt/s?
# 8F = 1000 1111: bits[15:8]=8F -> bf/s (since 8F is correct for bf/s)
# Actually: 8F00-8FFF is bf/s. YES.
#
# OK so I accept BECA8 returns R0=8, FR0=0.0 for "normal" in-range input.
# The search loop at BECB4-BECBC is only reached if... the count is 1?
# That would mean BECA8 is NOT a general axis search but a specialized function.

# Alternative: maybe R0 at BECA8 entry is NOT the count.
# Looking at BE836-BE838:
# BE836: B237 bsr 0xBECA8
# BE838: F04C fmov FR4,FR0  (delay slot)
# Before bsr, what was R0? It was set at BE832: mov.w @(0,R4),R0
# desc+0 word = 0x0009. So R0=9 at bsr entry.
# But then: add #-1,R0 -> 8; shll2 -> 32.
#
# ACTUALLY: looking at the branch more carefully:
# BECB0: 8F0E bf/s BECD0
# BECB2: 2008 (delay slot: tst R0,R0? or tst R0,R0?)
#
# Wait: MAYBE I should re-decode 0x2008 = 0010 0000 0000 1000
# In Renesas SH-2 manual:
# Group 2 (0x2000-0x2FFF):
# 2xx0 = mov.b Rm,@Rn
# 2xx1 = mov.w Rm,@Rn
# 2xx2 = mov.l Rm,@Rn
# 2xx4 = mov.b @(R0,Rm),Rn? No: 2xx4 = not used
# 2xx7 = div0s Rm,Rn
# 2xx8 = tst Rm,Rn  -- YES: 0x2nm8 = tst Rn,Rm
# 0x2008: n=0, m=0 -> tst R0,R0
print()
print("0x2008 confirmed = tst R0,R0 (T=1 if R0 AND R0 = 0, i.e. R0=0)")
print()

# Final: maybe I'm wrong about the bf/s being for comparison.
# Let me read BECAC-BECB0 differently:
# BECAC: F116 fmov.s @R1,FR1 -> FR1 = axis[0] = 0.0
# BECAE: F105 fmov.s @(R0,R1),FR1?? -> if n field is 1 and this IS FR1 dest:
#   addr = R0+R1 = 32+CE580 = CE5A0 -> FR1 = axis[8] = 8000.0
#
# If BOTH go into FR1, then after BECAE:
# FR1 = axis[last] = 8000.0 (overwriting axis[0])
# FR0 = original input RPM (still unchanged!)
#
# Then check: does input compare to something?
# But there's no fcmp instruction between BECAC and BECB0.
# The branch at BECB0 uses the T flag from the tst in the delay slot (R0!=0).
#
# I think there IS a comparison I'm not seeing because the instruction format
# for BECAE might be setting a flag. OR the branch condition is checking
# if the count allows binary search vs. direct return.

# Let me just print what the algorithm RETURNS and verify with known values:
print("="*70)
print("Empirical test: what does the full lookup chain return for various RPM values?")
print("="*70)
print()
print("Based on the u16 values at 0xCE5A4 as 2-byte pairs:")
vals_u16 = [ru16(0xCE5A4 + i*2) for i in range(9)]
axis_f32 = [rf32(0xCE580 + i*4) for i in range(9)]
print("RPM axis:", axis_f32)
print("U16 vals:", vals_u16)
print()
print("Based on the u16 values as bytes (1 byte per entry):")
vals_u8 = [rom[0xCE5A4 + i] for i in range(9)]
print("U8 vals:", vals_u8)
print()

# Looking at CE5A4 bytes:
# 00 64 00 64 00 64 00 64 00 64 00 32 00 32 00 25 00 25
# Wait earlier analysis showed different bytes. Let me re-read:
raw = rom[0xCE5A4:0xCE5A4+18]
print(f"Raw bytes at CE5A4: {raw.hex()}")
print()
# 00 64 00 64 00 64 00 64 00 64 00 32 00 32 00 25 00 25
# These are clearly u16 values: 0x0064=100, 0x0032=50, 0x0025=37
# with leading zero bytes.
# As pairs of u16: 0x0064,0x0064 etc. = 100,100,...

# The real question: how does BEACC read these into FR registers?
# fmov.s @R1+,FR1: reads 4 bytes as f32. But 0x00640064 is NOT a standard float.
# So either:
# 1. val_ptr does NOT point to CE5A4 for the actual FR0 write call
# 2. The "scale" field (1/32768) is used to convert
# 3. The function uses lds R0,FPUL then float FPUL,FRn (not fmov.s)

# Wait: what is FPUL at BEACC entry? F28D = fldi0 FR2 (load 0.0 to FR2)
# That's actually: fldi0 is "load float immediate 0.0"
# So BEACC sets FR2=0.0 first.
# Then shll2, add, fcmp/lt, bt/s...

# I think the key is that the value table format for THIS descriptor
# might actually use 4-byte f32 values, and the data I thought was
# CE5A4 is at a DIFFERENT address. Let me double-check.

print("Let me verify what's actually at 0xCE5A4:")
for i in range(12):
    a = 0xCE5A4 + i*4
    raw4 = rom[a:a+4]
    fv = struct.unpack('>f', raw4)[0]
    iv = struct.unpack('>I', raw4)[0]
    print(f"  @{a:05X}: {raw4.hex()}  -> f32={fv:.6g}  u32=0x{iv:08X}")

print()
print("The values starting at index 5: 0x00000000=0.0, then 43C80000=400.0, etc.")
print("These ARE valid f32! So maybe the val_ptr for the decay-delta table")
print("doesn't point to CE5A4 but rather...")

# Find where the non-zero data starts:
print()
print("FINDING the actual f32 value table by scanning from CE580:")
for a in range(0xCE580, 0xCE700, 4):
    raw4 = rom[a:a+4]
    fv = struct.unpack('>f', raw4)[0]
    iv = struct.unpack('>I', raw4)[0]
    if 0.01 < abs(fv) < 1e8 or (iv != 0 and iv < 0x007FFFFF and iv > 0x00100000):
        print(f"  @{a:05X}: {raw4.hex()} -> f32={fv:.6g}")
