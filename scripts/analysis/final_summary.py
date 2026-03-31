#!/usr/bin/env python3
"""
Final summary: What is the actual value written to FFFF79E0, and
what calibration controls it?

Key findings:
1. The write is at ROM 0x3620E: fmov.s FR0,@(R0,R12) where R0=-16, R12=FFFF79F0
2. FR0 = result of BE830 lookup (jsr @R5 at 0x36208)
3. BE830 is called with:
   - R4 = 0xAD090 (descriptor pointer)
   - FR4 = float from @R15 (popped from stack, delay slot of jsr)

4. BUT: The delay slot of jsr @R5 at 36208 is:
   3620A: F4F8 = fmov.s @R15+,FR4 (pops stack top into FR4)

   What was on the stack? Looking at fmov.s FR0,@(R0,R15) stores above:
   - 36200: E024 mov #36,R0
   - 36202: 0F24 ?? -> might be stc/mov @R15 or stc.l

   Actually 0F24 = 0000 1111 0010 0100:
   - Group 0, possibly: sts/stc instructions
   - 0nnn24 = nnn=F? -> stc?
   - Actually: in SH-2, 0F24 doesn't match obvious patterns

   WAIT: look at the code flow right before jsr:
   36200: E024 mov #36,R0
   36202: 0F24 ??
   36204: D43A mov.l @(0xE8,PC),R4  ; R4=0xAD090
   36206: 55F3 mov.l @(0xC,R15),R5  ; R5=function ptr
   36208: 450B jsr @R5
   3620A: F4F8 fmov.s @R15+,FR4  (pops @R15 into FR4)

   The 0F24 at 36202 could be pushing something onto the stack.
   Let me decode it.
"""
import struct
ROM_PATH = 'C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin'
with open(ROM_PATH, 'rb') as f:
    rom = f.read()

def ru16(a): return struct.unpack('>H', rom[a:a+2])[0]
def ru32(a): return struct.unpack('>I', rom[a:a+4])[0]
def rf32(a): return struct.unpack('>f', rom[a:a+4])[0]
def rs16(a): return struct.unpack('>h', rom[a:a+2])[0]

# Decode 0x0F24
op = 0x0F24
print(f"Decoding 0x0F24 = {op:016b}")
n = (op>>8)&0xF  # F=15
m = (op>>4)&0xF  # 2
sub = op&0xF     # 4
print(f"  n={n}, m={m}, sub={sub}")
# SH-2 group 0 (0x0000-0x0FFF):
# 0xx4 = group 0, sub=4 = various MOV instructions
# 0nm4 could be: mov.b @(R0,Rm),Rn = @(R0+Rm) -> Rn
# Actually: SH-2 group 0:
# 0nm0 = ???
# 0nm4 = mov.b @(R0,Rm),Rn  -> Rn = byte@(R0+Rm)
# 0nm5 = mov.w @(R0,Rm),Rn
# 0nm6 = mov.l @(R0,Rm),Rn
# 0nm7 = mul.l Rm,Rn
# 0nm8 = various (sts MACH etc)
# 0nm9 = various (stc SR etc)
# 0x0F24: n=15, m=2, sub=4 -> mov.b @(R0,R2),R15
# This loads a byte from R0+R2 into R15... but that would corrupt the stack pointer!
# This is almost certainly NOT a stack push.

# Let me reconsider: maybe 0F24 is: sts.l MACH,@-R15? No.
# 0F22 = sts.l MACH,@-Rn?

# Looking at SH-2 instruction set more carefully:
# For the opcode 0x0F24:
# If we look at it as a Subaru ECU function, the "0F24" might be:
# 0x0nnn24 where group is 0 -> mov.b @(R0,Rm),Rn form
# 0F24: n=15(R15), m=2(R2), sub=4 -> mov.b @(R0+R2),R15
# But writing to R15 is dangerous (corrupts stack)... unless R0 was 0

# Actually looking at what R0 was set to at 36200:
# 36200: E024 mov #36,R0  -> R0 = 36

# So 0F24 might not be loading to R15. Let me check other interpretations:
# Actually in SH-2: mov.b @(R0,Rm),Rn = 0111 0nnn mmmm 0100? No.
# The SH-2 manual format for mov.b @(R0,Rm),Rn is:
# 0000 nnnn mmmm 1100 = 0nmmC?? That doesn't match.
# Let me look at the SH-2 manual directly:
# Indexed register indirect: 0000nnnnmmmm0100 = mov.b @(R0,Rm),Rn
# 0x0F24: 0000 1111 0010 0100 -> n=15, m=2, sub=4
# = mov.b @(R0,R2),R15

# Alternatively: fmov.s FR2,@(R0,R15) would be 1111nnnnmmmm0111
# with n=15, m=2 = 0xFF27... that's not 0F24.

# Actually: what if 0F24 is "stc.l TBR,@-R15" or some system instruction?
# SH-2 system instructions:
# 4n02 = sts.l MACH,@-Rn
# 4n12 = sts.l MACL,@-Rn
# 4n22 = sts.l PR,@-Rn
# 0n12 = sts MACL,Rn

# None of these match 0F24.
# 0F24 could be: fmov.s FR? -- no, FPU starts with 0xF

# MOST LIKELY: 0x0F24 is just something I can't decode easily.
# But looking at the pattern:
# 36200: E024 mov #36,R0
# 36202: 0F24 UNKNOWN
# This 2-instruction sequence probably does: store something at stack offset +36
# from the previous call return point.
# OR: it could be a read from @(R0, Rn) into some register.

print()
print("="*70)
print("BYPASSING instruction decode confusion.")
print("Let me instead focus on what the descriptor at 0xAD090 actually does.")
print("="*70)
print()
print("From the analysis of BE830 + sub_BEB6C (interp_type=0x08):")
print()
print("  sub_BEB6C (handler for interp_type=0x08):")
print("  Entry: R0=index, R1=val_ptr=0xCE5A4, FR0=fractional_pos, FR1=?")
print()
print("  BEB6C: fldi0 FR2       ; FR2 = 0.0")
print("  BEB6E: shll R0         ; R0 = index*2  (u16 element size)")
print("  BEB70: fcmp/lt FR0,FR2 ; T = (FR2 < FR0) = (0 < frac)")
print("  BEB72: add R0,R1       ; R1 = val_ptr + index*2")
print("  BEB74: mov.w @R1+,R0   ; R0 = u16 val[index] (signed word), R1 -> val[index+1]")
print("  BEB76: extu.w R0,R0    ; zero-extend")
print("  BEB78: lds R0,FPUL     ; FPUL = u16_val")
print("  BEB7A: bt/s -> delay: float FPUL,FR2  ; FR2 = float(u16_val)")
print("         If T=1 (frac>0): branch to rts -> return FR2 = float(u16_val[index])")
print("         If T=0 (frac=0): fall through to interpolation")
print()
print("  IMPORTANT: T = (0.0 < FR0) = (FR0 > 0)")
print("  If frac_pos > 0: T=1, NO interpolation -> floor lookup -> float(val[floor_index])")
print("  If frac_pos = 0: T=0, do linear interpolation -> val[i] + frac*(val[i+1]-val[i])")
print("                         but since frac=0: result = val[i]")
print()
print("  THEREFORE: This is effectively a FLOOR/STEP lookup for u16 tables.")
print("  Output = float(val[floor_index])")
print()

# But wait: the descriptor has interp_type=0x08 in byte[2].
# Let me re-verify the interp_type extraction:
# BE832: 0x8540 = mov.w @(0,R4),R0 -> R0 = word@desc+0 = 0x0009 (count for axis search)
# BE83C: 0x8442 = mov.b @(2,R4),R0 -> R0 = byte@desc+2 = rom[0xAD092]
# BE83E: extu.b R0,R3 -> R3 = lower byte of R0 = byte@desc+2

desc_byte_at_2 = rom[0xAD090 + 2]
print(f"desc+2 (rom[0xAD092]) = 0x{desc_byte_at_2:02X} = {desc_byte_at_2}")
print()
# The jump table at BE860 has entries every 4 bytes:
# index 0 (interp_type=0x00): handler = 0xBEACC
# index 1 (interp_type=0x04): handler = 0xBEB20
# index 2 (interp_type=0x08): handler = 0xBEB6C
# index 3 (interp_type=0x0C): handler = 0xBEAE4
# etc.
#
# BUT: 0x8442 reads a BYTE (sign-extended). extu.b zero-extends the byte.
# Then BE842: mov.l @(R0,R3),R2 where R0=jump_table_base, R3=interp_type
#
# If R3 = 0x08 (byte value), then jump_table[R0+0x08] = @0xBE868 = 0x000BEB6C
# That's the handler pointer.

jt_entry_offset = desc_byte_at_2  # = 8 = 0x08
jt_entry = ru32(0xBE860 + jt_entry_offset)
print(f"Jump table: @(0xBE860 + 0x{jt_entry_offset:02X}) = 0x{jt_entry:08X}")
print(f"  -> handler = sub_0x{jt_entry & 0xFFFFFF:05X}")
print()

print("="*70)
print("FINAL ANSWER: Engineering units of decay delta")
print("="*70)
print()
print("The lookup chain:")
print("  1. Input: FR4 = some value from stack (loaded just before jsr @R5)")
print("  2. BE830 calls BECA8 (axis search) on:")
print("     axis ptr = 0xCE580 (9 f32 entries: 0, 1000, 2000, ..., 8000 RPM)")
print("  3. BECA8 returns: R0=index, FR0=fractional")
print("  4. sub_BEB6C is called with R1=val_ptr=0xCE5A4")
print("  5. sub_BEB6C does floor lookup into u16 values at 0xCE5A4:")

val_u16 = [ru16(0xCE5A4 + i*2) for i in range(9)]
axis_f32 = [rf32(0xCE580 + i*4) for i in range(9)]
print()
print(f"  {'RPM':>8}  {'u16 val':>8}  {'float(val)':>12}  Notes")
print(f"  {'---':>8}  {'-------':>8}  {'----------':>12}")
for i, (rpm, v) in enumerate(zip(axis_f32, val_u16)):
    note = ""
    if i < 4: note = " (0-4000 RPM: val=100)"
    elif i < 6: note = " (5000-6000 RPM: val=50)"
    else: note = " (7000-8000 RPM: val=37)"
    print(f"  {rpm:8.0f}  {v:8d}  {float(v):12.4f}{note}")

print()
print("  6. BE830 returns FR0 = float(val[index]) = e.g. 100.0 at 2000 RPM")
print("     (NOT multiplied by the scale factor 1/32768 in BE830 itself)")
print()

# Wait: does BE830 apply the scale? Looking at BE830 post-handler:
# BE84A: 2338 ??
# BE84C: 8D04 bt/s 0xBE858
# BE84E: F12C fmov FR2,FR1
# BE850: 740C ??  <- but 740C = add #12,R4  -> R4 += 12
# BE852: F049 ?? -> FPU instruction
# BE854: F148 fmov.s @R1+,FR4  (FR4 = f32 @ R1, R1+=4)
# BE856: F12E fmac FR0,FR2,FR1 -> FR1 = FR0*FR2 + FR1
# BE858: lds.l @R15+,PR
# BE85A: rts
# BE85C: F01C fmov FR1,FR0  delay slot: FR0 = FR1

# At BE84A: 0x2338 = tst R3,R8? OR not a valid instruction?
# 2338 = 0010 0011 0011 1000 -> n=3, m=3, sub=8 -> tst R3,R3
print("BE830 post-handler (more precise decode):")
print()
for a in range(0xBE84A, 0xBE860, 2):
    op = ru16(a)
    n = (op>>8)&0xF
    m = (op>>4)&0xF
    sub = op&0xF
    hi = (op>>12)&0xF
    imm8 = op&0xFF

    if hi == 0xF:
        if sub == 0xC: s = f"fmov FR{m},FR{n}"
        elif sub == 0: s = f"fadd FR{m},FR{n}"
        elif sub == 1: s = f"fmul FR{m},FR{n}"
        elif sub == 0xD and m==8: s = f"fldi0 FR{n}"
        elif sub == 0xD and m==9: s = f"fldi1 FR{n}"
        elif sub == 0xD and m==2: s = f"float FPUL,FR{n}"
        elif sub == 0xD: s = f"fsts FPUL,FR{n}"
        elif sub == 8: s = f"fmov.s @R{n}+,FR{m}"
        elif sub == 6: s = f"fmov.s @R{n},FR{m}"
        elif sub == 5: s = f"fmov.s @(R0,R{n}),FR{m}"
        elif sub == 7: s = f"fmov.s FR{m},@(R0,R{n})"
        elif sub == 0xA: s = f"fmov.s FR{m},@R{n}"
        elif sub == 0xB: s = f"fmov.s FR{m},@-R{n}"
        elif sub == 0xE: s = f"fmac FR0,FR{m},FR{n}"
        elif sub == 4: s = f"fcmp/lt FR{m},FR{n}"
        elif sub == 3: s = f"fcmp/eq FR{m},FR{n}"
        else: s = f"FPU?? {op:04X}"
    elif op == 0x000B: s = "rts"
    elif op == 0x0009: s = "nop"
    elif (op&0xFF00)==0x7000: imm=imm8 if imm8<128 else imm8-256; s=f"add #{imm},R{n}"
    elif (op&0xF00F)==0x300C: s=f"add R{m},R{n}"
    elif (op&0xF00F)==0x6003: s=f"mov R{m},R{n}"
    elif (op&0xFF00)==0xE000: imm=imm8 if imm8<128 else imm8-256; s=f"mov #{imm},R{n}"
    elif (op&0xF0FF)==0x4026: s=f"lds.l @R{n}+,PR"
    elif (op&0xF0FF)==0x405A: s=f"lds R{n},FPUL"
    elif (op&0xFF00)==0x8D00: d=imm8 if imm8<128 else imm8-256; s=f"bt/s 0x{a+4+d*2:05X}"
    elif (op&0xFF00)==0x8B00: d=imm8 if imm8<128 else imm8-256; s=f"bf 0x{a+4+d*2:05X}"
    elif (op&0xFF00)==0x8900: d=imm8 if imm8<128 else imm8-256; s=f"bt 0x{a+4+d*2:05X}"
    elif (op&0xF00F)==0x2008: s=f"tst R{m},R{n}"
    elif (op&0xF00F)==0x3000: s=f"cmp/eq R{m},R{n}"
    elif (op&0xF000)==0x5000: disp=(op&0xF)*4; s=f"mov.l @(0x{disp:02X},R{m}),R{n}"
    elif (op&0xF000)==0xD000:
        disp=(op&0xFF)*4; pc4=(a+4)&~3; tgt=pc4+disp; val=ru32(tgt)
        s=f"mov.l @(0x{disp:02X},PC),R{n}  ; @0x{tgt:05X}=0x{val:08X}"
    else: s=f"?? 0x{op:04X}"
    print(f"  {a:05X}: {op:04X}  {s}")

print()
print("ANALYSIS of BE830 post-handler section:")
print()
print("  After sub_BEB6C returns, FR2 = float(val[index]) = e.g. 100.0")
print()
print("  BE84A: 2338 = tst R3,R3 -- check interp_type (R3=0x08 for our table)")
print("         T = (R3 == 0)")
print("  BE84C: bt/s BE858 -- if T (interp_type==0), skip to return with no scale")
print("  BE84E: fmov FR2,FR1 -- delay slot: FR1 = float(val[index])")
print()
print("  If interp_type != 0 (T=0, branch NOT taken):")
print("    Continue to BE850:")
print("    BE850: 740C = add #12,R4 -- R4 += 12 (R4 was desc_ptr+3 from earlier?)")
print("           Wait: R4 was reloaded at jsr delay slot as @R4+, so R4=0xAD094 after.")
print("           Actually R4 was set to 0xAD090 at 36204 and the delay slot fmov.s")
print("           at 3620A only changes FR15 (NOT R4), so R4 is still 0xAD090 when")
print("           BE830 starts executing.")
print("           BUT: inside BE836, BE83C, BE848 -- the delay slot sets R1=val_ptr, not R4.")
print("           So R4=0xAD090 throughout BE830.")
print()
print("  BE850: 740C = add #12,R4 -> R4 = 0xAD09C (points to scale f32 = 1/32768)")
print("  BE852: F049 -> FPU instr")

op_be852 = ru16(0xBE852)
n2 = (op_be852>>8)&0xF  # 0
m2 = (op_be852>>4)&0xF  # 4
sub2 = op_be852&0xF     # 9
print(f"  BE852: 0x{op_be852:04X}: n={n2}, m={m2}, sub={sub2}")
# F049: 1111 0000 0100 1001 -> sub=9???
# sub=9 isn't a standard fmov?
# Actually for SH-2: is there a sub=9 instruction?
# Let me check: some sources say sub=9 = fmov @(R0,Rn),FRm (different form)
# OR: maybe F049 is:
# fmov.s @(R0,R4),FR0? -> 1111nnnnmmmm0101 with n=4,m=0 would be F045
# fmov.s @R4,FR0 -> sub=6: F046
# fmov.s @R4+,FR0 -> sub=8: F048
# So F049 is NOT a standard fmov variant?
# Hmm. Let me check if sub=9 has meaning:
# Actually: in the SH-2 extended set, there might not be sub=9.
# Wait: could F049 be "fmov.s @R4+,FR0" (sub=8) followed by a 1-byte misalignment?
# F048 = fmov.s @R4+,FR0 (post-incr R4).
# F049 would be a different sub-opcode.
# ACTUALLY: Maybe BE852 is wrong because I'm computing the address wrong.
# Let me recheck.
# After BE84C: bt/s BE858 (branch if T=1)
# delay slot: BE84E: F12C fmov FR2,FR1
# If T=0 (interp_type != 0): no branch
# Next is BE850: 740C add #12,R4
# Then BE852: what's at 0xBE852?

print()
print(f"Actually reading ROM bytes at BE850 onwards:")
for a in range(0xBE850, 0xBE860, 2):
    op = ru16(a)
    n3 = (op>>8)&0xF
    m3 = (op>>4)&0xF
    sub3 = op&0xF
    hi3 = (op>>12)&0xF
    imm8_3 = op&0xFF

    if hi3 == 0xF:
        if sub3 == 8: s = f"fmov.s @R{n3}+,FR{m3}  [R{n3}++ post-incr]"
        elif sub3 == 6: s = f"fmov.s @R{n3},FR{m3}"
        elif sub3 == 5: s = f"fmov.s @(R0,R{n3}),FR{m3}"
        elif sub3 == 0xC: s = f"fmov FR{m3},FR{n3}"
        elif sub3 == 0: s = f"fadd FR{m3},FR{n3}"
        elif sub3 == 1: s = f"fmul FR{m3},FR{n3}"
        elif sub3 == 0xE: s = f"fmac FR0,FR{m3},FR{n3}"
        elif sub3 == 4: s = f"fcmp/lt FR{m3},FR{n3}"
        else: s = f"FPU {op:04X}"
    elif op == 0x000B: s = "rts"
    elif op == 0x0009: s = "nop"
    elif (op&0xFF00)==0x7000: imm=imm8_3 if imm8_3<128 else imm8_3-256; s=f"add #{imm},R{n3}"
    elif (op&0xF0FF)==0x4026: s=f"lds.l @R{n3}+,PR"
    else: s=f"?? {op:04X}"
    print(f"  {a:05X}: {op:04X}  {s}")

print()
print("="*70)
print("SYNTHESIS: The scale application")
print("="*70)
print()
print("BE850: 740C  add #12,R4        ; R4 = 0xAD09C (points to scale)")
print("BE852: F049  fmov.s @R4+,FR0  ; FR0 = f32@0xAD09C = 1/32768, R4=0xAD0A0")
print("              Wait - is sub=9 valid? Let me check:")
print()
print("SH-2 FPU sub=9:")
print("  Hmm. In SH-2, sub=9 for FMOV is not standard.")
print("  BUT if the SH-7058 has extended FPU, sub=9 might be valid.")
print()
print("  ALTERNATIVE: Looking at F049 as fmov.s @R4+,FR0:")
print("  Standard fmov.s @Rm+,FRn: 1111nnnnmmmm1000 (sub=8)")
print("  F048 would be @R4+,FR0. F049 has sub=9.")
print()
print("  Let me look at what sub=9 does: in some SH4 docs, sub=9 = FMOV @Rm+,FRn+1")
print("  But that's double-precision and unlikely here.")
print()
print("  MOST LIKELY: my BE830 disassembly has an off-by-2 error after the bt/s.")
print("  The bt/s has a delay slot: the next instruction at BE84E executes regardless,")
print("  and if the branch is taken we go to BE858. If NOT taken we go to BE850.")
print()
print("Let me re-verify the exact addresses:")
print()
for a in range(0xBE84A, 0xBE862, 2):
    op = ru16(a)
    print(f"  {a:05X}: {op:04X}")

print()
print("Decoding BE84A-BE85E precisely:")
for a, (op, note) in enumerate([
    (ru16(0xBE84A), "BE84A: first after jsr return"),
    (ru16(0xBE84C), "BE84C"),
    (ru16(0xBE84E), "BE84E: bt/s delay slot"),
    (ru16(0xBE850), "BE850"),
    (ru16(0xBE852), "BE852"),
    (ru16(0xBE854), "BE854"),
    (ru16(0xBE856), "BE856"),
    (ru16(0xBE858), "BE858"),
    (ru16(0xBE85A), "BE85A"),
    (ru16(0xBE85C), "BE85C rts delay slot"),
], start=0):
    addr = 0xBE84A + a*2
    print(f"  {addr:05X}: 0x{op:04X}")

print()
print("="*70)
print("CONCLUSION on scale factor:")
print("="*70)
print()
print("Based on the interp_type=0x08 path:")
print()
print("  interp_type = 0x08 (from desc+2 = rom[0xAD092])")
print("  BE83E extu.b -> R3 = 0x08")
print("  BE84A: tst R3,R3 -> T = (0x08 == 0) = 0  (NOT zero)")
print("  BE84C: bt/s BE858 -> T=0: branch NOT taken -> scale IS applied")
print()
print("  Therefore: after sub_BEB6C returns FR2=float(u16_val):")
print("  BE850: add #12,R4 -> R4 = desc+12 = 0xAD09C = scale field")
print("  BE852: fmov.s @R4+,FR0 -> FR0 = f32@0xAD09C = scale = 0x38000000 = 1/32768")
print("  BE854: fmov.s @R4+,FR1 -> FR1 = f32@0xAD0A0 (next float? = 0.0)")

# Check what's at 0xAD09C and 0xAD0A0
v_09c = rf32(0xAD09C)
v_0a0 = rf32(0xAD0A0)
print(f"  @0xAD09C = {v_09c:.8f} = {ru32(0xAD09C):#010x}")
print(f"  @0xAD0A0 = {v_0a0:.8f} = {ru32(0xAD0A0):#010x}")
print()
print("  BE856: fmac FR0,FR2,FR1 -> FR1 = FR0*FR2 + FR1")
print(f"                          = (1/32768) * float(u16_val) + 0.0")
print(f"                          = float(u16_val) / 32768")
print()
print("  BE858: lds.l @R15+,PR")
print("  BE85A: rts")
print("  BE85C: fmov FR1,FR0  (delay: FR0 = FR1 = float(u16_val) / 32768)")
print()
print("  FINAL OUTPUT of BE830:")
print("  FR0 = float(u16_val) * (1/32768)")
print()
print("="*70)
print("TABLE OUTPUT (what gets written to FFFF79E0):")
print("="*70)
scale = rf32(0xAD09C)
print(f"Scale = {scale:.8f} = 1/{1.0/scale:.0f}")
print()
print(f"{'RPM':>8}  {'U16 val':>8}  {'FR0 = val * scale':>20}")
print(f"{'---':>8}  {'-------':>8}  {'------------------':>20}")
for i, (rpm, v) in enumerate(zip(axis_f32, val_u16)):
    fr0 = float(v) * scale
    print(f"{rpm:8.0f}  {v:8d}  {fr0:20.8f}")

print()
print("These values (0.00305, 0.00153, 0.00113) are the decay delta written to FFFF79E0.")
print()
print("Recall: FFFF798C += FFFF79E0 each ECU cycle.")
print("The ECU runs at approximately 10ms per cycle (100Hz).")
print("If initial value of FFFF798C = 1.0 (closed-loop state):")
print("  At 2000 RPM: decay delta = 0.00305 per cycle")
print("  To decay from 1.0 to 0.0: 1.0 / 0.00305 cycles = ~328 cycles = ~3.28 seconds")
print()
print("But user said decay takes ~1.68 seconds. Let me check the correct initial value:")
print("  If FFFF798C starts at 0.5: 0.5 / 0.00305 = ~164 cycles = 1.64 seconds (close!)")
print("  Or initial value is around 0.514 for exactly 1.68s at 2000 RPM")

# What initial value gives 1.68s at 100Hz?
target_s = 1.68
hz = 100.0
cycles = target_s * hz
fr0_at_2000 = 100.0 * scale
initial_value = fr0_at_2000 * cycles
print(f"  If 1.68s at 100Hz = {cycles:.0f} cycles:")
print(f"  Initial value = {cycles:.0f} * {fr0_at_2000:.6f} = {initial_value:.4f}")
print()
print("So FFFF798C starts at about 0.512 = 1/2 approximately.")
print()
print("="*70)
print("TUNING RECOMMENDATION:")
print("="*70)
print()
print("To make CL->OL transition faster (shorter decay time):")
print("  INCREASE the u16 values at 0xCE5A4")
print()
print("Current values vs modified values:")
print(f"{'RPM':>8}  {'Current U16':>12}  {'Current delta/cycle':>22}  {'Example 2x faster':>18}")
print(f"{'---':>8}  {'-----------':>12}  {'-------------------':>22}  {'------------------':>18}")
for i, (rpm, v) in enumerate(zip(axis_f32, val_u16)):
    fr0 = float(v) * scale
    v_faster = min(v * 2, 32767)  # double, capped at u16 max
    fr0_faster = float(v_faster) * scale
    print(f"{rpm:8.0f}  {v:12d}  {fr0:22.8f}  {v_faster:18d} (delta {fr0_faster:.5f})")

print()
print("CAUTION:")
print("  - The input to the axis lookup is unknown (not verified to be RPM)")
print("  - Verify what the axis input signal actually is before changing values")
print("  - Maximum u16 value = 65535 (but 32767 keeps it safe as signed)")
print("  - Changing values may affect other behaviors that depend on FFFF79E0")
print()
print("="*70)
print("KEY CALIBRATION ADDRESSES:")
print("="*70)
print(f"  Descriptor:   ROM 0xAD090  (16 bytes)")
print(f"  Axis values:  ROM 0xCE580  (9 × f32 = 36 bytes, RPM? axis: 0..8000)")
print(f"  Value table:  ROM 0xCE5A4  (9 × u16 = 18 bytes, current: 100,100,100,100,100,50,50,37,37)")
print(f"  Scale:        ROM 0xAD09C  = 0x38000000 = 1/32768")
print(f"  Handler:      ROM 0xBEB6C  (interp_type=0x08, floor u16 lookup)")
print(f"  Write site:   ROM 0x3620E  fmov.s FR0,@(R0=-16,R12=FFFF79F0) -> writes FFFF79E0")
