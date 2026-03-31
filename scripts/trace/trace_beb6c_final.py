#!/usr/bin/env python3
"""
Final trace of sub_BEB6C (interp_type=0x08 handler) to determine the exact
float value written to FFFF79E0 for each RPM breakpoint.

sub_BEB6C disassembly:
  BEB6C: F28D  fldi0 FR2          ; FR2 = 0.0
  BEB6E: 4000  shll R0            ; R0 <<= 1  (R0 = index * 2, not *4!)
  BEB70: F204  fcmp/lt FR0,FR2    ; T=1 if FR2 < FR0
  BEB72: 310C  add R0,R1          ; R1 = val_ptr + index*2  (u16 offset!)
  BEB74: 6015  ??                 ; see below
  BEB76: 600D  extu.w R0,R0       ; R0 = zero-extend word (low 16 bits of R0)
  BEB78: 405A  lds R0,FPUL        ; FPUL = R0 (integer)
  BEB7A: 8D06  bt/s 0xBEB8A      ; if T (FR2 < FR0, i.e. 0 < FR0?? -- always true for positive),
                                   ; branch to rts
  BEB7C: F22D  float FPUL,FR2    ; delay slot: FR2 = float(FPUL) = float(R0) = float(val[index])
  BEB7E: 6011  mov.w @R1,R0      ; R0 = u16 at val_ptr+index*2+2  (or val_ptr+index*2?)
                                   ; Wait: after add R0,R1: R1=val_ptr+index*2
                                   ; After BEB6E shll R0: R0=index*2
                                   ; After BEB72 add R0,R1: R1=val_ptr+index*2
                                   ; BEB74: 6015 = mov.b @R1,R0 (sign-ext)? OR
                                   ; 6015 = 0110 0000 0001 0101 -> n=0,m=1,sub=5 -> mov.w @R1,R0 (sign-ext word)
  BEB80: 600D  extu.w R0,R0       ; R0 zero-extended
  BEB82: 405A  lds R0,FPUL
  BEB84: F12D  float FPUL,FR1    ; FR1 = float(val[index+1]) (next entry)
  BEB86: F121  fmul FR2,FR1       ; FR1 = FR1 * FR2 = float(val[index+1]) * float(val[index])??
                                   ; WAIT: FR2 = float(val[index]) at this point??
                                   ; Let me re-check.
  BEB88: F21E  fmac FR0,FR1,FR2   ; FR2 = FR0*FR1 + FR2
  BEB8A: 000B  rts
  BEB8C: 0009  nop

Actually: at BEB78, lds R0,FPUL:
  R0 = was the byte offset = index*2 (from shll R0 = index<<1)
  So FPUL = index*2 (NOT val[index])

Let me re-trace more carefully.
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
print("FULL PRECISE DECODE OF sub_BEB6C")
print("="*70)
print()
print("SH-2 opcode 0x6015:")
op = 0x6015
n = (op>>8)&0xF  # 0
m = (op>>4)&0xF  # 1
sub = op&0xF     # 5
print(f"  0x6015: n={n}, m={m}, sub={sub}")
# SH-2 group 6:
# 6xx0 = mov.b @Rm,Rn  (sign-extend byte)
# 6xx1 = mov.w @Rm,Rn  (sign-extend word)
# 6xx2 = mov.l @Rm,Rn
# 6xx3 = mov Rm,Rn
# 6xx4 = mov.b @Rm+,Rn
# 6xx5 = mov.w @Rm+,Rn  (post-increment, sign-extend word)
# 6xx6 = mov.l @Rm+,Rn
# 6xx7 = not Rm,Rn
print(f"  sub=5 -> mov.w @R{m}+,R{n}  [sign-ext word, post-incr R{m}]")
print(f"  = mov.w @R1+,R0  (R0 = sign-ext word from @R1, R1 += 2)")
print()
print("So BEB74: mov.w @R1+,R0  reads val[index] as SIGNED word, R1 advances 2 bytes")
print()

# Re-trace BEB6C with correction:
# Entry: R0=index (from axis search), R1=val_ptr, FR0=fractional_pos (0..1), FR1=??
print("CORRECTED TRACE of sub_BEB6C:")
print("Entry state:")
print("  R0 = integer index from BECA8 (e.g. 1 for RPM between 1000 and 2000)")
print("  R1 = val_ptr = 0xCE5A4")
print("  FR0 = fractional position (0.0..1.0) from BECA8")
print("  FR1 = unknown (possibly still contains axis search result)")
print()
print("  BEB6C: fldi0 FR2       ; FR2 = 0.0")
print("  BEB6E: shll R0         ; R0 <<= 1  (index * 2, for u16 element size)")
print("  BEB70: fcmp/lt FR0,FR2 ; T = (FR2 < FR0) = (0 < frac_pos)")
print("                          ; T=1 if frac_pos > 0 (between axis entries)")
print("                          ; T=0 if frac_pos == 0 (exact axis hit)")
print("  BEB72: add R0,R1       ; R1 = val_ptr + index*2  (points to val[index])")
print("  BEB74: mov.w @R1+,R0   ; R0 = val[index] (u16 as signed), R1 -> val[index+1]")
print("  BEB76: extu.w R0,R0    ; R0 = zero-extend (unsigned u16)")
print("  BEB78: lds R0,FPUL     ; FPUL = val[index] as integer")
print("  BEB7A: bt/s BEB8A      ; if T=1 (frac_pos > 0), branch to rts")
print("                          ; (with delay: FR2 = float(val[index]))")
print("  BEB7C: float FPUL,FR2  ; delay slot: FR2 = (float)val[index]")
print("         WAIT: if T=1, branch is taken -> goes to rts at BEB8A")
print("         This means: if frac_pos > 0 (between entries), return FR2=float(val[index]) directly?")
print("         That would be a floor lookup (not interpolated)!")
print()
print("  If branch NOT taken (T=0, frac_pos == 0 exactly):")
print("  BEB7E: mov.w @R1,R0    ; R0 = val[index+1]  (R1 already points there after post-incr)")
print("  BEB80: extu.w R0,R0    ; zero-extend")
print("  BEB82: lds R0,FPUL     ; FPUL = val[index+1]")
print("  BEB84: float FPUL,FR1  ; FR1 = (float)val[index+1]")
print("  BEB86: fmul FR2,FR1    ; FR1 = val[index+1] * val[index]  ???")
print("         (FR2 was float(val[index]) from delay slot)")
print("  BEB88: fmac FR0,FR1,FR2 ; FR2 = FR0*FR1 + FR2")
print("                           ;     = frac*val[i]*val[i+1] + val[i]")
print("         That's not standard linear interpolation either!")
print()

# Wait - let me re-read bt/s:
# BEB7A: 8D06 bt/s 0xBEB8A (branch if T=1)
# delay slot BEB7C: float FPUL,FR2
#
# bt/s = branch if TRUE with delay slot
# The delay slot EXECUTES regardless of whether branch is taken.
# So FR2 = float(val[index]) ALWAYS (regardless of branch)
#
# Then: if T=1, jump to BEB8A (rts) -> return FR2 = float(val[index])
# if T=0, continue to BEB7E (interpolation code)

print("="*70)
print("CORRECTED: bt/s executes delay slot ALWAYS, then branches if T=1")
print("="*70)
print()
print("BEB78: lds R0,FPUL    ; FPUL = val[index]")
print("BEB7A: bt/s BEB8A     ; delay slot always executes:")
print("BEB7C: float FPUL,FR2 ; FR2 = float(val[index])  <-- ALWAYS")
print()
print("If T=1 (frac_pos > 0 -- between entries):")
print("  Jump to BEB8A: rts  ; return FR2 = float(val[index])")
print("  This is a FLOOR lookup (take left bracket value, no interpolation)")
print()
print("If T=0 (frac_pos == 0 exactly -- hit exact axis point):")
print("  Continue to BEB7E:")
print("  BEB7E: mov.w @R1,R0    ; R0 = val[index+1]")
print("  BEB80: extu.w R0,R0")
print("  BEB82: lds R0,FPUL")
print("  BEB84: float FPUL,FR1  ; FR1 = float(val[index+1])")
print("  BEB86: fmul FR2,FR1    ; FR1 = val[i+1] * val[i]  (product?)")
print("  BEB88: fmac FR0,FR1,FR2; FR2 = FR0*FR1 + FR2 = 0*(val[i+1]*val[i]) + val[i] = val[i]")
print("  BEB8A: rts")
print()
print("Wait: if frac_pos=0 exactly, the fmac with FR0=0 just gives val[i] again.")
print("So BOTH paths return val[index] as float when input exactly hits an axis point!")
print("And when between points (frac_pos > 0), it returns val[floor(index)].")
print("This is effectively a FLOOR (left-bracket, no interpolation) lookup!")
print()

# But wait: T = (FR2 < FR0) = (0 < frac_pos)
# If frac_pos > 0: T=1 -> branch taken -> return float(val[index])
# If frac_pos = 0: T=0 -> NO branch -> goes through fmul/fmac
# And fmac: FR2 = FR0*FR1 + FR2 = 0*FR1 + val[i] = val[i]
# So YES: both cases return val[index]. It's a floor lookup.

# BUT WAIT: Maybe FR0 is NOT the fractional position in BEB6C context.
# Let me re-trace what BECA8 puts in FR0.
#
# BECA8 is called at BE836 with delay FR0=FR4=RPM_input.
# BECA8 modifies FR0.
# After BECA8 returns, BE83C-BE844 execute (integer ops, don't change FP regs)
# Then jsr @R2 (BEB6C) with delay: R1 = val_ptr
# So FR0 at BEB6C entry = what BECA8 left in FR0.
#
# From BECA8 analysis:
# After BF/S to BECD0: return with shlr2 R0, delay fldi0 FR0
# That sets FR0 = 0.0 on return!
# But that's the "out of range high" path.
#
# The main path (BECB4-BECCA) presumably sets FR0 = fractional position.
# Let me trace the main loop more carefully.

print("="*70)
print("BECA8 MAIN LOOP trace (for input in range):")
print("="*70)
print()
# BECB4: bt/s BECCD6 -- delay: add #-4,R0
# BECB6: add #-4,R0 (delay slot)
# BECB8: F116 fmov.s @R1,FR1   -> FR1 = axis[0]? No, @R1 where R1 was not modified?
# Wait: R1 = axis_ptr at BECA8 entry
# After BECA8 entry:
# BECA8: add #-1,R0 -> R0=8
# BECAA: shll2 R0 -> R0=32
# BECAC: F116 fmov.s @R1,FR1 -> FR1 = @(CE580) = 0.0 (axis[0])
# BECAE: F105 -> this overwrites FR0 but let's assume it's @(R0,R1) = @(CE580+32) = axis[8]=8000.0
#   Wait: we determined F105 = fmov.s @(R0,R1),FR0 with Rn=R1(bits11:8=1), FRm=FR0(bits7:4=0)
#   addr = R0+R1 = 32 + CE580 = CE5A0
#   FR0 = f32@CE5A0 = 8000.0
# BECB0: bf/s BECD0; delay: tst R0,R0 -> T=(R0==0)=0 (R0=32), so T=0
# bf/s (branch if T=0): branch taken to BECD0!
# BECD0: shlr2 R0 -> R0=8 (= last index)
# BECD2: rts
# BECD4: fldi0 FR0 (delay: FR0=0.0)
# Return: R0=8, FR0=0.0
#
# Hmm! So for any count > 1, BECA8 takes the bf/s to BECD0 and returns R0=last_index=8, FR0=0.0?
# That means it's ALWAYS returning the last index!
# And FR0=0.0 means the handler (BEB6C) always hits the T=1 path (0<0 is FALSE, wait...
# fcmp/lt FR0,FR2: T=1 if FR2 < FR0. FR2=0.0, FR0=0.0 -> NOT (0<0) -> T=0!
# So branch NOT taken -> goes through to fmul/fmac path
# But frac=FR0=0.0, so fmac gives val[index] = val[8] = 37

print("If BECA8 always returns R0=8, FR0=0.0 (for count>1 tables):")
print("  BEB6C: fldi0 FR2 -> FR2=0.0")
print("  shll R0 -> R0=16 (index*2 = 8*2)")
print("  fcmp/lt FR0,FR2 -> T=(FR2<FR0)=(0<0)=0")
print("  add R0,R1 -> R1 = CE5A4 + 16 = CE5B4")
print("  mov.w @R1+,R0 -> R0 = u16 @ CE5B4 = ?")
print(f"  u16 @ 0xCE5B4 = 0x{ru16(0xCE5B4):04X} = {ru16(0xCE5B4)}")
print("  T=0 -> NOT branch -> goes through interpolation with frac=0")
print("  Result = float(val[8]) = float(37) = 37.0")
print()
print("That would mean the decay delta = 37.0 at all RPMs? That doesn't match")
print("the varying table values (100, 50, 37). Something's wrong with my BECA8 decode.")
print()
print("="*70)
print("NEW HYPOTHESIS: BECA8 works differently.")
print("Maybe the bf/s goes TO a DIFFERENT address (I might have miscalculated)")
print("="*70)
print()
beca8_bf_s_addr = 0xBECB0
disp = 0x0E
target = beca8_bf_s_addr + 4 + disp * 2
print(f"BECB0: bf/s target = 0x{beca8_bf_s_addr:05X} + 4 + 0x{disp:02X}*2 = 0x{target:05X}")
print()
# 0xBECB0 + 4 + 28 = 0xBECCC
# Let me recalculate
print(f"= 0x{0xBECB0:05X} + 4 + {0x0E*2} = 0x{0xBECB0+4+0x0E*2:05X}")
# So target is 0xBECD0 (as before).
print()

# Let me just dump the full BECA8 with 50 bytes to see ALL of it
print("="*70)
print("BECA8 full dump (all opcodes):")
print("="*70)
for i in range(0, 0x30, 2):
    a = 0xBECA8 + i
    op = ru16(a)
    n = (op>>8)&0xF
    m = (op>>4)&0xF
    sub = op&0xF
    hi = (op>>12)&0xF
    imm8 = op&0xFF

    # Precise decode
    if hi == 0xF:
        if sub == 5: s = f"fmov.s @(R0,R{n}),FR{m}"  # Rn=base in bits[11:8], FRm=dest in bits[7:4]
        elif sub == 6: s = f"fmov.s @R{n},FR{m}"
        elif sub == 4: s = f"fcmp/lt FR{m},FR{n}  [T=1 if FR{n}<FR{m}]"
        elif sub == 3: s = f"fcmp/eq FR{m},FR{n}"
        elif sub == 0: s = f"fadd FR{m},FR{n}"
        elif sub == 1: s = f"fmul FR{m},FR{n}"
        elif sub == 0xC: s = f"fmov FR{m},FR{n}"
        elif sub == 0xD and m == 0: s = f"fsts FPUL,FR{n}"
        elif sub == 0xD and m == 8: s = f"fldi0 FR{n}"
        elif sub == 0xD and m == 9: s = f"fldi1 FR{n}"
        elif sub == 0xD and m == 2: s = f"float FPUL,FR{n}"
        elif sub == 0xD and m == 3: s = f"ftrc FR{n},FPUL"
        elif sub == 8: s = f"fmov.s @R{n}+,FR{m}  [FR{m}=@R{n}, R{n}+=4]"
        elif sub == 9: s = f"fmov.s @-R{n},FR{m}?  [unknown]"
        elif sub == 0xE: s = f"fmac FR0,FR{m},FR{n}"
        else: s = f"fpu ?? 0x{op:04X}"
    elif op == 0x000B: s = "rts"
    elif op == 0x0009: s = "nop"
    elif (op&0xFF00)==0x7000: imm=imm8 if imm8<128 else imm8-256; s=f"add #{imm},R{n}"
    elif (op&0xF00F)==0x300C: s=f"add R{m},R{n}"
    elif (op&0xF0FF)==0x4008: s=f"shll2 R{n}"
    elif (op&0xF0FF)==0x4009: s=f"shlr2 R{n}"
    elif (op&0xF0FF)==0x4000: s=f"shll R{n}"
    elif (op&0xFF00)==0xE000: imm=imm8 if imm8<128 else imm8-256; s=f"mov #{imm},R{n}"
    elif (op&0xF00F)==0x600C: s=f"extu.b R{m},R{n}"
    elif (op&0xF00F)==0x600D: s=f"extu.w R{m},R{n}"
    elif (op&0xFF00)==0x8B00: d=imm8 if imm8<128 else imm8-256; s=f"bf 0x{a+4+d*2:05X}"
    elif (op&0xFF00)==0x8F00: d=imm8 if imm8<128 else imm8-256; s=f"bf/s 0x{a+4+d*2:05X}"
    elif (op&0xFF00)==0x8D00: d=imm8 if imm8<128 else imm8-256; s=f"bt/s 0x{a+4+d*2:05X}"
    elif (op&0xFF00)==0x8900: d=imm8 if imm8<128 else imm8-256; s=f"bt 0x{a+4+d*2:05X}"
    elif (op&0xF00F)==0x2008: s=f"tst R{m},R{n}"
    elif (op&0xF00F)==0x3000: s=f"cmp/eq R{m},R{n}"
    elif (op&0xF00F)==0x3003: s=f"cmp/ge R{m},R{n}"
    elif (op&0xF0FF)==0x405A: s=f"lds R{n},FPUL"
    elif (op&0xF0FF)==0x4022: s=f"sts.l PR,@-R{n}"
    elif (op&0xF0FF)==0x4026: s=f"lds.l @R{n}+,PR"
    else: s=f"?? 0x{op:04X}"
    print(f"  {a:05X}: {op:04X}  {s}")

print()
print("="*70)
print("KEY OBSERVATION:")
print("="*70)
print()
print("Looking at the bf/s at BECB0 more carefully:")
print("The DELAY SLOT at BECB2 is: 2008 = tst R0,R0")
print("R0 = 32 (byte offset = (count-1)*4)")
print("tst R0,R0: T = 1 if R0==0 (R0 AND R0 = 0), T = 0 if R0!=0")
print("R0=32 -> T=0 -> bf/s (branch if false): T=0 means FALSE -> BRANCH TAKEN")
print()
print("But wait: 'FALSE' for bf/s means T==0, so branch if T==0")
print("T=0 (R0!=0) -> branch taken -> BECD0")
print()
print("HMMMM - wait. Let me re-examine whether 0x2008 is actually 'tst' here.")
print("0x2008 = 0010 0000 0000 1000")
print("SH-2 group 2 (0x2000-0x2FFF), sub-code = 1000")
print("Actually in SH-2, group 2 encodings:")
print("  0x2nm0 = mov.b Rm,@Rn  (store byte)")
print("  0x2nm1 = mov.w Rm,@Rn  (store word)")
print("  0x2nm2 = mov.l Rm,@Rn  (store long)")
print("  0x2nm4 = mov.b @(R0,Rm),Rn??  No: actually used for different")
print("  0x2nm7 = div0s Rm,Rn")
print("  0x2nm8 = tst Rm,Rn")
print("  0x2nm9 = and Rm,Rn")
print()
print("0x2008: n=0, m=0, sub=8 -> tst R0,R0  YES, this sets T=(R0==0)")
print()

# Now the REAL question: what does BECA8 do for input in range?
# The answer is: if R0 = (count-1)*4 != 0 (i.e. count > 1, which is always true for 9-entry table),
# then bf/s at BECB0 is ALWAYS taken, and the function returns:
# shlr2 R0 = (count-1)*4 >> 2 = (count-1) = index of last entry
# FR0 = 0.0 (from delay slot fldi0 FR0)
#
# So BECA8 is NOT an axis search! It always returns R0=last_index for count>1.
# This means BEB6C always looks up val[last_index] = val[8] = 37.
#
# But that gives a constant decay rate of 37 at all RPMs, ignoring the table!
#
# WAIT: Unless BECA8 is called with DIFFERENT arguments by different callsites.
# The descriptor at 0xAD090 has count=9 (word at +0 = 0x0009).
# But maybe for the CL/OL decay specific call, the descriptor is different?

print("="*70)
print("Let me verify: what is the ACTUAL descriptor pointer at the jsr @R5 in sub_36070?")
print("="*70)
print()
# Look at the area around 0x36208 to find what R4 contains
# (R4 is passed to BE830 as the descriptor pointer)
print("Disassembling sub_36070 from prologue to identify R4 load before jsr @R5 at 36208:")
print()

for a in range(0x36070, 0x36280, 2):
    op = ru16(a)
    n = (op>>8)&0xF
    m = (op>>4)&0xF
    sub = op&0xF
    hi = (op>>12)&0xF
    imm8 = op&0xFF

    if (op & 0xF000) == 0xD000:
        disp = (op & 0xFF) * 4
        pc4 = (a + 4) & ~3
        tgt = pc4 + disp
        val = ru32(tgt)
        s = f"mov.l @(0x{disp:02X},PC),R{n}  ; @0x{tgt:05X}=0x{val:08X}"
    elif (op & 0xF000) == 0x9000:
        disp = (op & 0xFF) * 2
        tgt = a + 4 + disp
        val = ru16(tgt)
        sval = rs16(tgt)
        s = f"mov.w @(0x{disp:02X},PC),R{n}  ; @0x{tgt:05X}=0x{val:04X}={sval}"
    elif (op & 0xFF00) == 0xC700:
        disp = (op & 0xFF) * 4
        pc4 = (a + 4) & ~3
        tgt = pc4 + disp
        s = f"mova @(0x{disp:02X},PC),R0  ; =0x{tgt:05X}"
    elif hi == 0xF:
        if sub == 5: s = f"fmov.s @(R0,R{n}),FR{m}"
        elif sub == 6: s = f"fmov.s @R{n},FR{m}"
        elif sub == 7: s = f"fmov.s FR{m},@(R0,R{n})"
        elif sub == 4: s = f"fcmp/lt FR{m},FR{n}"
        elif sub == 3: s = f"fcmp/eq FR{m},FR{n}"
        elif sub == 0: s = f"fadd FR{m},FR{n}"
        elif sub == 1: s = f"fmul FR{m},FR{n}"
        elif sub == 0xC: s = f"fmov FR{m},FR{n}"
        elif sub == 0xD and m==8: s=f"fldi0 FR{n}"
        elif sub == 0xD and m==9: s=f"fldi1 FR{n}"
        elif sub == 0xD and m==2: s=f"float FPUL,FR{n}"
        elif sub == 0xD and m==3: s=f"ftrc FR{n},FPUL"
        elif sub == 0xD: s=f"fsts/etc FR{n}"
        elif sub == 8: s = f"fmov.s @R{n}+,FR{m}"
        elif sub == 0xA: s = f"fmov.s FR{m},@R{n}"
        elif sub == 0xB: s = f"fmov.s FR{m},@-R{n}"
        elif sub == 0xE: s = f"fmac FR0,FR{m},FR{n}"
        else: s = f"FPU?? 0x{op:04X}"
    elif op == 0x000B: s = "rts"
    elif op == 0x0009: s = "nop"
    elif (op&0xFF00)==0x7000: imm=imm8 if imm8<128 else imm8-256; s=f"add #{imm},R{n}"
    elif (op&0xF00F)==0x300C: s=f"add R{m},R{n}"
    elif (op&0xF00F)==0x3008: s=f"sub R{m},R{n}"
    elif (op&0xF0FF)==0x4008: s=f"shll2 R{n}"
    elif (op&0xF0FF)==0x4009: s=f"shlr2 R{n}"
    elif (op&0xF0FF)==0x4000: s=f"shll R{n}"
    elif (op&0xF00F)==0x6003: s=f"mov R{m},R{n}"
    elif (op&0xFF00)==0xE000: imm=imm8 if imm8<128 else imm8-256; s=f"mov #{imm},R{n}"
    elif (op&0xF00F)==0x600C: s=f"extu.b R{m},R{n}"
    elif (op&0xF00F)==0x600D: s=f"extu.w R{m},R{n}"
    elif (op&0xF00F)==0x600E: s=f"exts.b R{m},R{n}"
    elif (op&0xF00F)==0x600F: s=f"exts.w R{m},R{n}"
    elif (op&0xF00F)==0x6001: s=f"mov.w @R{m},R{n}"
    elif (op&0xF00F)==0x6002: s=f"mov.l @R{m},R{n}"
    elif (op&0xF00F)==0x6006: s=f"mov.b @R{m},R{n}"
    elif (op&0xF00F)==0x6005: s=f"mov.w @R{m}+,R{n}  [post-incr]"
    elif (op&0xFF00)==0x8B00: d=imm8 if imm8<128 else imm8-256; s=f"bf 0x{a+4+d*2:05X}"
    elif (op&0xFF00)==0x8F00: d=imm8 if imm8<128 else imm8-256; s=f"bf/s 0x{a+4+d*2:05X}"
    elif (op&0xFF00)==0x8D00: d=imm8 if imm8<128 else imm8-256; s=f"bt/s 0x{a+4+d*2:05X}"
    elif (op&0xFF00)==0x8900: d=imm8 if imm8<128 else imm8-256; s=f"bt 0x{a+4+d*2:05X}"
    elif (op&0xF0FF)==0x400B: s=f"jsr @R{n}"
    elif (op&0xF0FF)==0x402B: s=f"jmp @R{n}"
    elif (op&0xF0FF)==0x4026: s=f"lds.l @R{n}+,PR"
    elif (op&0xF0FF)==0x4022: s=f"sts.l PR,@-R{n}"
    elif (op&0xF0FF)==0x405A: s=f"lds R{n},FPUL"
    elif (op&0xF0FF)==0x406A: s=f"lds R{n},FPSCR"
    elif (op&0xF0FF)==0x002A: s=f"sts PR,R{n}"
    elif (op&0xF0FF)==0x0029: s=f"movt R{n}"
    elif (op&0xF0FF)==0x4015: s=f"cmp/pl R{n}"
    elif (op&0xF0FF)==0x4011: s=f"cmp/pz R{n}"
    elif (op&0xF00F)==0x2008: s=f"tst R{m},R{n}"
    elif (op&0xF00F)==0x2009: s=f"and R{m},R{n}"
    elif (op&0xF00F)==0x200A: s=f"xor R{m},R{n}"
    elif (op&0xF00F)==0x200B: s=f"or R{m},R{n}"
    elif (op&0xF00F)==0x3000: s=f"cmp/eq R{m},R{n}"
    elif (op&0xF00F)==0x3003: s=f"cmp/ge R{m},R{n}"
    elif (op&0xF00F)==0x3006: s=f"cmp/hi R{m},R{n}"
    elif (op&0xF00F)==0x3007: s=f"cmp/gt R{m},R{n}"
    elif (op&0xF000)==0x5000: disp=(op&0xF)*4; s=f"mov.l @(0x{disp:02X},R{m}),R{n}"
    elif (op&0xF000)==0x1000: disp=(op&0xF)*4; s=f"mov.l R{m},@(0x{disp:02X},R{n})"
    elif (op&0xFF00)==0x8400: disp=(op&0xF); rn=(op>>4)&0xF; s=f"mov.b @(0x{disp:02X},R{rn}),R0"
    elif (op&0xFF00)==0x8500: disp=(op&0xF)*2; rn=(op>>4)&0xF; s=f"mov.w @(0x{disp:02X},R{rn}),R0"
    elif (op&0xFF00)==0x8000: disp=(op&0xF); rn=(op>>4)&0xF; s=f"mov.b R0,@(0x{disp:02X},R{rn})"
    elif (op&0xFF00)==0x8100: disp=(op&0xF)*2; rn=(op>>4)&0xF; s=f"mov.w R0,@(0x{disp:02X},R{rn})"
    elif (op&0xF0FF)==0x4010: s=f"dt R{n}"
    elif (op&0xF00F)==0x400C: s=f"shad R{m},R{n}"
    elif (op&0xF00F)==0x400D: s=f"shld R{m},R{n}"
    else: s=f"?? 0x{op:04X}"

    marker = ""
    if a == 0x36208: marker = "  <-- jsr @R5 (calls BE830)"
    if a == 0x3620E: marker = "  <-- fmov.s FR0,@(R0,R12) writes FFFF79E0"
    print(f"  {a:05X}: {op:04X}  {s}{marker}")

    # stop at rts+delay or at a reasonable endpoint
    if op == 0x000B and a > 0x36200:
        break
