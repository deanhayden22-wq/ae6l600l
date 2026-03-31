#!/usr/bin/env python3
"""
Analyze the exact data flow through BE830 + BEACC to understand
how the u16 values at 0xCE5A4 become the float FR0 returned to sub_36070.

Key question: what is the actual engineering-unit value of the decay delta
when RPM is e.g. 2000 (table value = 100 = 0x0064)?
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
print("FULL DATA FLOW ANALYSIS: BE830 + BEACC")
print("="*70)
print()
print("sub_BE830 entry: R4=descriptor_ptr (0xAD090), FR4=input (RPM value)")
print()
print("BE830 disassembly (annotated):")
print("  BE830: 4F22  sts.l PR,@-R15         ; save return addr")
print("  BE832: ????  mov.b @(2,R4),R0        ; R0 = interp_type byte")
print("  BE834: 5141  mov.l @(4,R4),R1        ; R1 = axis_ptr (@0xCE580)")
print("  BE836: B237  bsr 0xBECA8             ; call axis_search(R0=count?, R1=axis_ptr, FR0=input)")
print("  BE838: F04C  fmov FR4,FR0            ; delay slot: FR0 = RPM input")
print("  BE83A: 6103  mov R0,R1               ; after return: R1 = index from BECA8")
print("  BE83C: 8442  mov.w @(4,R4),R0        ; R0 = word at desc+4 (count/flags?)")
print("  BE83E: 630C  extu.b R0,R3            ; R3 = lower byte = interp_type")
print("  BE840: C707  mova @(0x1C,PC),R0      ; R0 = jump table base 0xBE860")
print("  BE842: 023E  mov.l @(R0,R3),R2       ; R2 = jump_table[R3] = handler fn ptr")
print("  BE844: 6013  mov R1,R0               ; R0 = index from axis search")
print("  BE846: 420B  jsr @R2                 ; call interp handler (BEACC for type=0)")
print("  BE848: 5142  mov.l @(8,R4),R1        ; delay slot: R1 = val_ptr (@0xCE5A4)")
print("  BE84A: ????  (comparison)")
print("  BE84E: F12C  fmov FR2,FR1            ; after return: FR1 = interpolated result")
print("  BE858: lds.l @R15+,PR")
print("  BE85A: rts")
print("  BE85C: F01C  fmov FR1,FR0            ; delay slot: FR0 = result")
print()
print("KEY: When jsr @R2 is executed:")
print("  R0 = integer index (from axis search)")
print("  R1 = val_ptr (0xCE5A4)")
print("  FR1 = fractional position (0.0..1.0) -- from BECA8")
print()
print("="*70)
print("BEACC annotated (type=0x00, linear interpolation):")
print("="*70)
print()
print("  BEACC: F28D  fsts FPUL,FR2           ; FR2 = float(FPUL)")
print("                                        ; Wait -- what's in FPUL here?")
print("  BEACE: 4008  shll2 R0                ; R0 = index * 4 (byte offset for f32 table)")
print("  BEAD0: 310C  add R0,R1               ; R1 = val_ptr + index*4  (addr of val[index])")
print("  BEAD2: F204  fcmp/gt FR0,FR2         ; compare FR2 vs FR0 (fractional?)")
print("  BEAD4: 8D03  bt/s 0xBEADE            ; if FR2 > FR0, skip to return")
print("  BEAD6: F219  fmov.s @(R0,R1),FR2     ; delay slot: FR2 = val[index+1] (next entry)")
print("                                        ; @(R0,R1) = val_ptr + index*4 + index*4?")
print("                                        ; Actually R0=index*4, R1=val_ptr+index*4")
print("                                        ; so @(R0,R1) = val_ptr + 2*index*4 = val_ptr + index*8 ???")
print("                                        ; That seems wrong. Let me reconsider.")
print()
print("WAIT - re-check: at BEACC entry:")
print("  R0 = integer index (raw, not yet scaled)")
print("  R1 = val_ptr")
print("  FR1 = fractional position from BECA8")
print()
print("  BEACC: F28D  fsts FPUL,FR2           ; FR2 = float(FPUL)  [what's in FPUL?]")
print("  BEACE: 4008  shll2 R0                ; R0 <<= 2  (R0 = index * 4)")
print("  BEAD0: 310C  add R0,R1               ; R1 = val_ptr + index*4  (addr of val[index])")
print("  BEAD2: F204  fcmp/gt FR0,FR2         ; compare: FR0 vs FR2")
print("                                        ; At this point FR0 = ??? (was fractional or still RPM?)")
print()

# Check what BECA8 does more carefully - look at its return values
print("="*70)
print("Let's carefully re-read BECA8 to understand what it returns in FR1:")
print("="*70)
print()
# BECA8:
# 70FF  add #-1,R0         ; R0 = count - 1
# 4008  shll2 R0           ; R0 = (count-1)*4 = last index byte offset
# F116  fmov.s @R1,FR1     ; FR1 = axis[0]  (first axis entry)
# F105  fmov.s @(R0,R0),FR1 ; WAIT: @(R0,R0)?? That's @(R0 + R0)?? No.
#                            ; fmov.s @(R0,Rn),FRm has opcode 1111nnnnmmmm0101
#                            ; F105 = 1111 0001 0000 0101 -> n=1,m=0 -> fmov.s @(R0,R1),FR0??
#                            ; Wait let me re-read BECA8 more carefully
print("BECA8 raw opcodes:")
for i in range(0, 0x30, 2):
    a = 0xBECA8 + i
    op = ru16(a)
    # decode fmov.s @(R0,Rn),FRm  = F_n_m_5
    if (op & 0xF00F) == 0xF005:
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        print(f"  {a:05X}: {op:04X}  fmov.s @(R0,R{n}),FR{m}")
    elif (op & 0xF00F) == 0xF006:
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        print(f"  {a:05X}: {op:04X}  fmov.s @R{n},FR{m}")
    elif (op & 0xF00F) == 0xF004:
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        print(f"  {a:05X}: {op:04X}  fcmp/lt FR{m},FR{n}  (T=1 if FRn<FRm)")
    elif (op & 0xF00F) == 0xF003:
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        print(f"  {a:05X}: {op:04X}  fcmp/eq FR{m},FR{n}")
    elif (op & 0xF00F) == 0xF000:
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        print(f"  {a:05X}: {op:04X}  fadd FR{m},FR{n}")
    elif (op & 0xF00F) == 0xF001:
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        print(f"  {a:05X}: {op:04X}  fmul FR{m},FR{n}")
    elif (op & 0xF00F) == 0xF00C:
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        print(f"  {a:05X}: {op:04X}  fmov FR{m},FR{n}  (copy)")
    elif (op & 0xF0FF) == 0xF02D:
        n = (op >> 8) & 0xF
        print(f"  {a:05X}: {op:04X}  float FPUL,FR{n}")
    elif (op & 0xF0FF) == 0xF03D:
        n = (op >> 8) & 0xF
        print(f"  {a:05X}: {op:04X}  ftrc FR{n},FPUL  (convert float to int)")
    elif (op & 0xF00F) == 0xF008:
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        print(f"  {a:05X}: {op:04X}  fmov.s @R{n}+,FR{m}  (post-increment)")
    elif (op & 0xF00F) == 0xF002:
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        print(f"  {a:05X}: {op:04X}  fdiv FR{m},FR{n}")
    elif (op & 0xF0FF) == 0xF08D:
        n = (op >> 8) & 0xF
        print(f"  {a:05X}: {op:04X}  fldi0 FR{n}")
    elif (op & 0xF0FF) == 0xF09D:
        n = (op >> 8) & 0xF
        print(f"  {a:05X}: {op:04X}  fldi1 FR{n}")
    else:
        # non-FPU
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        hi = (op >> 12) & 0xF
        imm8 = op & 0xFF
        imm4 = op & 0xF
        if op == 0x000B: s = "rts"
        elif op == 0x0009: s = "nop"
        elif (op & 0xFF00) == 0x7000: s = f"add #{(imm8 if imm8<128 else imm8-256)},R{n}"
        elif (op & 0xF00F) == 0x300C: s = f"add R{m},R{n}"
        elif (op & 0xF0FF) == 0x4008: s = f"shll2 R{n}"
        elif (op & 0xF0FF) == 0x4009: s = f"shlr2 R{n}"
        elif (op & 0xF0FF) == 0x4018: s = f"shll8 R{n}"
        elif (op & 0xF0FF) == 0x4028: s = f"shll16 R{n}"
        elif (op & 0xF00F) == 0x6003: s = f"mov R{m},R{n}"
        elif (op & 0xFF00) == 0xE000: s = f"mov #{(imm8 if imm8<128 else imm8-256)},R{n}"
        elif (op & 0xF00F) == 0x6007: s = f"not R{m},R{n}"
        elif (op & 0xF00F) == 0x600C: s = f"extu.b R{m},R{n}"
        elif (op & 0xF00F) == 0x600D: s = f"extu.w R{m},R{n}"
        elif (op & 0xF0FF) == 0x4015: s = f"cmp/pl R{n}"
        elif (op & 0xF0FF) == 0x4011: s = f"cmp/pz R{n}"
        elif (op & 0xFF00) == 0x8900:
            d = op&0xFF; d = d if d<128 else d-256; s = f"bt 0x{0xBECA8+i+4+d*2:05X}"
        elif (op & 0xFF00) == 0x8B00:
            d = op&0xFF; d = d if d<128 else d-256; s = f"bf 0x{0xBECA8+i+4+d*2:05X}"
        elif (op & 0xFF00) == 0x8F00:
            d = op&0xFF; d = d if d<128 else d-256; s = f"bf/s 0x{0xBECA8+i+4+d*2:05X}"
        elif (op & 0xFF00) == 0x8D00:
            d = op&0xFF; d = d if d<128 else d-256; s = f"bt/s 0x{0xBECA8+i+4+d*2:05X}"
        elif (op & 0xF0FF) == 0x4026: s = f"lds.l @R{n}+,PR"
        elif (op & 0xF0FF) == 0x405A: s = f"lds R{n},FPUL"
        elif (op & 0xF0FF) == 0x406A: s = f"lds R{n},FPSCR"
        elif (op & 0xF0FF) == 0x4052: s = f"sts.l FPUL,@-R{n}"
        elif (op & 0xF0FF) == 0x400B: s = f"jsr @R{n}"
        elif (op & 0xF0FF) == 0x002A: s = f"sts PR,R{n}"
        elif (op & 0xF0FF) == 0x0029: s = f"movt R{n}"
        elif (op & 0xF00F) == 0x3000: s = f"cmp/eq R{m},R{n}"
        elif (op & 0xF00F) == 0x3003: s = f"cmp/ge R{m},R{n}"
        elif (op & 0xF00F) == 0x3006: s = f"cmp/hi R{m},R{n}"
        elif (op & 0xF00F) == 0x3007: s = f"cmp/gt R{m},R{n}"
        elif (op & 0xF0FF) == 0x4000: s = f"shll R{n}"
        elif (op & 0xF0FF) == 0x4001: s = f"shlr R{n}"
        elif (op & 0xF0FF) == 0x4020: s = f"shal R{n}"
        elif (op & 0xF0FF) == 0xF00D: s = "fsts FPUL,FRn"
        elif (op & 0xF00F) == 0x400D: s = f"shld R{m},R{n}"
        elif (op & 0xF0FF) == 0x4022: s = f"sts.l PR,@-R{n}"
        elif (op & 0xF0FF) == 0x402B: s = f"jmp @R{n}"
        else: s = f"?? 0x{op:04X}"
        print(f"  {a:05X}: {op:04X}  {s}")

print()
print("="*70)
print("BEACC raw opcodes (more careful decode):")
print("="*70)
for i in range(0, 0x20, 2):
    a = 0xBEACC + i
    op = ru16(a)
    n = (op >> 8) & 0xF
    m = (op >> 4) & 0xF
    hi = (op >> 12) & 0xF
    imm8 = op & 0xFF

    if (op & 0xF00F) == 0xF005:
        s = f"fmov.s @(R0,R{n}),FR{m}"
    elif (op & 0xF00F) == 0xF006:
        s = f"fmov.s @R{n},FR{m}"
    elif (op & 0xF00F) == 0xF004:
        s = f"fcmp/lt FR{m},FR{n}  (T=1 if FR{n}<FR{m})"
    elif (op & 0xF00F) == 0xF003:
        s = f"fcmp/eq FR{m},FR{n}"
    elif (op & 0xF00F) == 0xF000:
        s = f"fadd FR{m},FR{n}"
    elif (op & 0xF00F) == 0xF001:
        s = f"fmul FR{m},FR{n}"
    elif (op & 0xF00F) == 0xF00C:
        s = f"fmov FR{m},FR{n}  (copy)"
    elif (op & 0xF0FF) == 0xF02D:
        n2 = (op >> 8) & 0xF
        s = f"float FPUL,FR{n2}"
    elif (op & 0xF0FF) == 0xF03D:
        n2 = (op >> 8) & 0xF
        s = f"ftrc FR{n2},FPUL"
    elif (op & 0xF00F) == 0xF008:
        s = f"fmov.s @R{n}+,FR{m}  (post-incr)"
    elif (op & 0xF00F) == 0xF002:
        s = f"fdiv FR{m},FR{n}"
    elif (op & 0xF0FF) == 0xF08D:
        n2 = (op >> 8) & 0xF
        s = f"fldi0 FR{n2}"
    elif (op & 0xF0FF) == 0xF09D:
        n2 = (op >> 8) & 0xF
        s = f"fldi1 FR{n2}"
    elif (op & 0xF0FF) == 0xF00D:
        n2 = (op >> 8) & 0xF
        s = f"fsts FPUL,FR{n2}"
    elif (op & 0xF00F) == 0xF007:
        s = f"fmov.s FR{m},@(R0,R{n})"
    elif (op & 0xF00F) == 0xF00E:
        s = f"fmac FR0,FR{m},FR{n}"
    elif op == 0x000B: s = "rts"
    elif op == 0x0009: s = "nop"
    elif (op & 0xFF00) == 0x7000: s = f"add #{(imm8 if imm8<128 else imm8-256)},R{n}"
    elif (op & 0xF00F) == 0x300C: s = f"add R{m},R{n}"
    elif (op & 0xF0FF) == 0x4008: s = f"shll2 R{n}"
    elif (op & 0xF0FF) == 0x4009: s = f"shlr2 R{n}"
    elif (op & 0xF00F) == 0x3008: s = f"sub R{m},R{n}"
    elif (op & 0xFF00) == 0x8D00:
        d = op&0xFF; d = d if d<128 else d-256; s = f"bt/s 0x{a+4+d*2:05X}"
    elif (op & 0xFF00) == 0x8F00:
        d = op&0xFF; d = d if d<128 else d-256; s = f"bf/s 0x{a+4+d*2:05X}"
    elif (op & 0xFF00) == 0x8900:
        d = op&0xFF; d = d if d<128 else d-256; s = f"bt 0x{a+4+d*2:05X}"
    elif (op & 0xF0FF) == 0x405A: s = f"lds R{n},FPUL"
    else: s = f"?? 0x{op:04X}"
    print(f"  {a:05X}: {op:04X}  {s}")

print()
print("="*70)
print("KEY QUESTION: Does BEACC read the value table as f32 or u16?")
print()

# The value at val_ptr=0xCE5A4 - check what's there
val_ptr = 0xCE5A4
print(f"At 0xCE5A4, first few entries as f32:")
for i in range(9):
    a = val_ptr + i*4
    fv = rf32(a)
    iv = ru16(a)
    b0, b1, b2, b3 = rom[a], rom[a+1], rom[a+2], rom[a+3]
    print(f"  [{i}] @{a:05X}: bytes={b0:02X} {b1:02X} {b2:02X} {b3:02X}  as_f32={fv:.4f}  as_u16_hi={iv}  as_u16_lo={ru16(a+2)}")

print()
print(f"At 0xCE5A4, first few entries as u16 (2-byte read):")
for i in range(9):
    a = val_ptr + i*2
    v = ru16(a)
    print(f"  [{i}] @{a:05X}: 0x{v:04X} = {v}")

# The BEACC code:
# shll2 R0 -> R0 = index * 4
# add R0,R1 -> R1 = val_ptr + index*4
# fmov.s @(R0,R1),FR2 -> FR2 = *(val_ptr + index*4 + index*4) = *(val_ptr + index*8)???
# That's wrong. Let me think again.

print()
print("="*70)
print("ANALYSIS: Understanding @(R0,R1) in BEACC")
print("="*70)
print()
print("After shll2 R0:  R0 = index * 4")
print("After add R0,R1: R1 = val_ptr + index*4  (points to val[index])")
print()
print("fmov.s @(R0,R1),FR2:")
print("  Address = R0 + R1 = index*4 + val_ptr + index*4 = val_ptr + index*8")
print()
print("BUT WAIT: fmov.s @R1+,FR1 reads @R1 and post-increments R1 by 4:")
print("  FR1 = f32 at val_ptr+index*4  (= val[index])")
print("  R1 becomes val_ptr + index*4 + 4")
print()
print("So the flow is:")
print("  F28D: fsts FPUL,FR2     -- FR2 = float(FPUL)  -- see below")
print("  4008: shll2 R0          -- R0 = index*4")
print("  310C: add R0,R1         -- R1 = val_ptr + index*4")
print("  F204: fcmp/lt FR4,FR2?  -- wait, F204 = 1111 0010 0000 0100")
print("        n=2, m=0, sub=4 -> fcmp/lt FR0,FR2  (T=1 if FR2 < FR0)")
print("  8D03: bt/s +3           -- if T (FR2 < FR0): branch to BEADE (rts)")
print("  F219: fmov.s @(R0,R1),FR2  DELAY SLOT: FR2 = val[index + index] ???")
print()

# Let me check what F204 actually means precisely
# F204 = 1111 0010 0000 0100
# SH2 FPU: fcmp/lt FRm, FRn: opcode 1111nnnnmmmm0100
# n = (F204 >> 8) & 0xF = 2
# m = (F204 >> 4) & 0xF = 0
# sub = F204 & 0xF = 4
# So: fcmp/lt FR0, FR2  -> T=1 if FR2 < FR0
op = 0xF204
n_val = (op >> 8) & 0xF
m_val = (op >> 4) & 0xF
sub = op & 0xF
print(f"F204: n={n_val}, m={m_val}, sub={sub}")
print(f"  fcmp/lt FR{m_val},FR{n_val}  -> T=1 if FR{n_val} < FR{m_val}")
print(f"  i.e. if FR2 < FR0 then T=1, branch to rts (skip interpolation)")
print()

# What's in FPUL / FR0 at BEACC entry?
# At BE830 entry: FR4=input
# BE836: bsr 0xBECA8 with delay slot FR0=FR4
# BECA8 does axis search - let's understand what it puts in FPUL/FR0 on return
print("="*70)
print("What does BECA8 return?")
print("After BECA8 returns, before jsr @R2:")
print("  R0 = integer index")
print("  FR1 = fractional interpolation position (0.0..1.0)")
print()
print("Then BE83C: 8442: mov.w @(4,R4),R0 -- reloads R0 with count/flags word")
print("Then BE846: jsr @R2 with delay slot: R1 = val_ptr (0xCE5A4)")
print("So at BEACC entry:")
print("  R0 = integer index (from 6013: mov R1,R0)")
print("       Wait: R1 was set to index by BECA8, then 6103: mov R0,R1")
print("       then 8442 reloads R0, then 6013: mov R1,R0")
print("       So yes: R0 = original index from BECA8")
print("  R1 = val_ptr = 0xCE5A4 (from delay slot 5142)")
print("  FR1 = fractional position from BECA8")
print()

# BE838-BE848 trace:
# BE836: bsr BECA8  (delay: FR0 = FR4 = RPM input)
# BECA8 runs. What does it return?
print("BECA8 return analysis:")
print()
print("BECA8 trace (annotated):")
print("  BECA8: 70FF  add #-1,R0         -- R0 = count-1 = 8 (for 9-entry table)")
print("  BECAA: 4008  shll2 R0           -- R0 = 8*4 = 32 = 0x20 (last axis byte offset)")
print("  BECAC: F116  fmov.s @R1,FR1     -- FR1 = axis[0] = 0.0")
print("  BECAE: F105  fmov.s @(R0,R1),FR0?? -- wait, F105...")

op2 = 0xF105
n2 = (op2>>8)&0xF  # 1
m2 = (op2>>4)&0xF  # 0
sub2 = op2&0xF     # 5
print(f"  F105: n={n2}, m={m2}, sub={sub2} -> fmov.s @(R0,R{n2}),FR{m2}")
print(f"        = fmov.s @(R0,R1),FR0")
print(f"        = FR0 = axis[last] = axis[8] = 8000.0")
print()

# Continuing BECA8:
# F116 fmov.s @R1,FR1 -- FR1 = axis[0]=0.0
# F105 fmov.s @(R0,R1),FR0 -- FR0 = axis[last]=8000.0
# 8F0E bf/s +14 -- if T=0, branch; T=?
# 2008 ?? 0x2008 -- delay slot

# 2008 = mov.b R0,@R0? No: 2008 = 0010 0000 0000 1000 -> tst R0,R0? No.
# 2008 = 0010nnnnmmmm1000 -> n=0,m=0,sub=8 -> tst R0,R0
# Actually: op 2008: hi=2, 0010 0000 0000 1000
# -> group 2: n=0, m=0, sub=8 -> ?
# sub-opcodes for group 2:
# 0=mov.b, 1=mov.w, 2=mov.l, 4=mov.b @(R0,Rm),Rn?, 5=mov.w..., 6=mov.l..., 7=div0s
# 8=tst, 9=and, a=xor, b=or
# 2008 = 0010 0000 0000 1000 -> tst R0,R0  (n=0, m=0, sub=8 -> tst Rm,Rn = tst R0,R0)
# Actually: 0x2008 = 0010nnnnmmmm1000 with n=0,m=0 would be tst R0,R0 but
# standard form is: 2nm8 for tst
# Actually tst is: 0010nnnnmmmm1000 = TSTR: test Rm & Rn, set T
# So 2008 = tst R0,R0 -- wait no: n=0, m=0 -> tst R0,R0 -> always T=1 since R0&R0=R0, and if R0=0, T=1
# But here the context is different...

print("Decoding 0x2008 in BECA8 delay slot:")
op3 = 0x2008
n3 = (op3>>8)&0xF  # 0
m3 = (op3>>4)&0xF  # 0
sub3 = op3&0xF     # 8
print(f"  0x2008: n={n3}, m={m3}, sub={sub3} -> group 2, sub 8 = tst R{m3},R{n3}")
print(f"  -> tst R0,R0: T=1 if R0==0 (no bits set)")
print()

# OK let me just check what BECA8 is doing by looking at complete trace
print("="*70)
print("BECA8 full precise decode:")
print("="*70)
for i in range(0, 0x30, 2):
    a = 0xBECA8 + i
    op = ru16(a)
    n4 = (op>>8)&0xF
    m4 = (op>>4)&0xF
    sub4 = op&0xF
    hi4 = (op>>12)&0xF
    imm8_4 = op&0xFF

    if (op & 0xF00F) == 0xF005:
        s = f"fmov.s @(R0,R{n4}),FR{m4}"
    elif (op & 0xF00F) == 0xF006:
        s = f"fmov.s @R{n4},FR{m4}"
    elif (op & 0xF00F) == 0xF004:
        s = f"fcmp/lt FR{m4},FR{n4}  -> T=1 if FR{n4}<FR{m4}"
    elif (op & 0xF00F) == 0xF003:
        s = f"fcmp/eq FR{m4},FR{n4}"
    elif (op & 0xF00F) == 0xF000:
        s = f"fadd FR{m4},FR{n4}"
    elif (op & 0xF00F) == 0xF001:
        s = f"fmul FR{m4},FR{n4}"
    elif (op & 0xF00F) == 0xF00C:
        s = f"fmov FR{m4},FR{n4}"
    elif (op & 0xF0FF) == 0xF02D:
        s = f"float FPUL,FR{n4}"
    elif (op & 0xF0FF) == 0xF03D:
        s = f"ftrc FR{n4},FPUL  (float->int in FPUL)"
    elif (op & 0xF00F) == 0xF008:
        s = f"fmov.s @R{n4}+,FR{m4}  ; FR{m4}=*R{n4}, R{n4}+=4"
    elif (op & 0xF00F) == 0xF002:
        s = f"fdiv FR{m4},FR{n4}"
    elif (op & 0xF0FF) == 0xF08D:
        s = f"fldi0 FR{n4}"
    elif (op & 0xF0FF) == 0xF09D:
        s = f"fldi1 FR{n4}"
    elif (op & 0xF0FF) == 0xF00D:
        s = f"fsts FPUL,FR{n4}"
    elif (op & 0xF00F) == 0xF007:
        s = f"fmov.s FR{m4},@(R0,R{n4})"
    elif (op & 0xF00F) == 0xF00E:
        s = f"fmac FR0,FR{m4},FR{n4}"
    elif op == 0x000B: s = "rts"
    elif op == 0x0009: s = "nop"
    elif (op & 0xFF00) == 0x7000:
        s = f"add #{(imm8_4 if imm8_4<128 else imm8_4-256)},R{n4}"
    elif (op & 0xF00F) == 0x300C: s = f"add R{m4},R{n4}"
    elif (op & 0xF00F) == 0x3008: s = f"sub R{m4},R{n4}"
    elif (op & 0xF0FF) == 0x4008: s = f"shll2 R{n4}"
    elif (op & 0xF0FF) == 0x4009: s = f"shlr2 R{n4}"
    elif (op & 0xF0FF) == 0x4018: s = f"shll8 R{n4}"
    elif (op & 0xF0FF) == 0x4028: s = f"shll16 R{n4}"
    elif (op & 0xF00F) == 0x6003: s = f"mov R{m4},R{n4}"
    elif (op & 0xFF00) == 0xE000:
        s = f"mov #{(imm8_4 if imm8_4<128 else imm8_4-256)},R{n4}"
    elif (op & 0xF00F) == 0x600C: s = f"extu.b R{m4},R{n4}"
    elif (op & 0xF00F) == 0x600D: s = f"extu.w R{m4},R{n4}"
    elif (op & 0xF0FF) == 0x4015: s = f"cmp/pl R{n4}"
    elif (op & 0xF0FF) == 0x4011: s = f"cmp/pz R{n4}"
    elif (op & 0xFF00) == 0x8900:
        d = imm8_4; d = d if d<128 else d-256; s = f"bt 0x{a+4+d*2:05X}"
    elif (op & 0xFF00) == 0x8B00:
        d = imm8_4; d = d if d<128 else d-256; s = f"bf 0x{a+4+d*2:05X}"
    elif (op & 0xFF00) == 0x8F00:
        d = imm8_4; d = d if d<128 else d-256; s = f"bf/s 0x{a+4+d*2:05X}"
    elif (op & 0xFF00) == 0x8D00:
        d = imm8_4; d = d if d<128 else d-256; s = f"bt/s 0x{a+4+d*2:05X}"
    elif (op & 0xF000) == 0xA000:
        d = op&0xFFF; d = d if d<2048 else d-4096; s = f"bra 0x{a+4+d*2:05X}"
    elif (op & 0xF000) == 0xB000:
        d = op&0xFFF; d = d if d<2048 else d-4096; s = f"bsr 0x{a+4+d*2:05X}"
    elif (op & 0xF0FF) == 0x4026: s = f"lds.l @R{n4}+,PR"
    elif (op & 0xF0FF) == 0x405A: s = f"lds R{n4},FPUL"
    elif (op & 0xF0FF) == 0x406A: s = f"lds R{n4},FPSCR"
    elif (op & 0xF0FF) == 0x4052: s = f"sts.l FPUL,@-R{n4}"
    elif (op & 0xF0FF) == 0x400B: s = f"jsr @R{n4}"
    elif (op & 0xF0FF) == 0x002A: s = f"sts PR,R{n4}"
    elif (op & 0xF0FF) == 0x0029: s = f"movt R{n4}"
    elif (op & 0xF00F) == 0x3000: s = f"cmp/eq R{m4},R{n4}"
    elif (op & 0xF00F) == 0x3003: s = f"cmp/ge R{m4},R{n4}"
    elif (op & 0xF00F) == 0x3006: s = f"cmp/hi R{m4},R{n4}"
    elif (op & 0xF00F) == 0x3007: s = f"cmp/gt R{m4},R{n4}"
    elif (op & 0xF0FF) == 0x4000: s = f"shll R{n4}"
    elif (op & 0xF0FF) == 0x4001: s = f"shlr R{n4}"
    elif (op & 0xFF00) == 0xD000:
        disp4 = (op & 0xFF) * 4
        pc4 = (a + 4) & ~3
        tgt = pc4 + disp4
        val = ru32(tgt)
        s = f"mov.l @(0x{disp4:02X},PC),R{n4}  ; @0x{tgt:05X}=0x{val:08X}"
    elif (op & 0xF0FF) == 0x402B: s = f"jmp @R{n4}"
    elif (op & 0xF00F) == 0x400D: s = f"shld R{m4},R{n4}"
    elif (op & 0xF0FF) == 0x4022: s = f"sts.l PR,@-R{n4}"
    elif (op & 0xF00F) == 0x2009: s = f"and R{m4},R{n4}"
    elif (op & 0xF00F) == 0x2008: s = f"tst R{m4},R{n4}"
    else: s = f"?? 0x{op:04X}"
    print(f"  {a:05X}: {op:04X}  {s}")

print()
print("="*70)
print("BEACC full precise decode:")
print("="*70)
for i in range(0, 0x20, 2):
    a = 0xBEACC + i
    op = ru16(a)
    n4 = (op>>8)&0xF
    m4 = (op>>4)&0xF
    sub4 = op&0xF
    hi4 = (op>>12)&0xF
    imm8_4 = op&0xFF

    if (op & 0xF00F) == 0xF005:
        s = f"fmov.s @(R0,R{n4}),FR{m4}"
    elif (op & 0xF00F) == 0xF006:
        s = f"fmov.s @R{n4},FR{m4}"
    elif (op & 0xF00F) == 0xF004:
        s = f"fcmp/lt FR{m4},FR{n4}  -> T=1 if FR{n4}<FR{m4}"
    elif (op & 0xF00F) == 0xF003:
        s = f"fcmp/eq FR{m4},FR{n4}"
    elif (op & 0xF00F) == 0xF000:
        s = f"fadd FR{m4},FR{n4}"
    elif (op & 0xF00F) == 0xF001:
        s = f"fmul FR{m4},FR{n4}"
    elif (op & 0xF00F) == 0xF00C:
        s = f"fmov FR{m4},FR{n4}"
    elif (op & 0xF0FF) == 0xF02D:
        s = f"float FPUL,FR{n4}"
    elif (op & 0xF0FF) == 0xF03D:
        s = f"ftrc FR{n4},FPUL  (float->int)"
    elif (op & 0xF00F) == 0xF008:
        s = f"fmov.s @R{n4}+,FR{m4}  ; FR{m4}=f32@R{n4}, R{n4}+=4"
    elif (op & 0xF00F) == 0xF002:
        s = f"fdiv FR{m4},FR{n4}"
    elif (op & 0xF0FF) == 0xF08D:
        s = f"fldi0 FR{n4}"
    elif (op & 0xF0FF) == 0xF09D:
        s = f"fldi1 FR{n4}"
    elif (op & 0xF0FF) == 0xF00D:
        s = f"fsts FPUL,FR{n4}"
    elif (op & 0xF00F) == 0xF007:
        s = f"fmov.s FR{m4},@(R0,R{n4})"
    elif (op & 0xF00F) == 0xF00E:
        s = f"fmac FR0,FR{m4},FR{n4}"
    elif op == 0x000B: s = "rts"
    elif op == 0x0009: s = "nop"
    elif (op & 0xFF00) == 0x7000:
        s = f"add #{(imm8_4 if imm8_4<128 else imm8_4-256)},R{n4}"
    elif (op & 0xF00F) == 0x300C: s = f"add R{m4},R{n4}"
    elif (op & 0xF00F) == 0x3008: s = f"sub R{m4},R{n4}"
    elif (op & 0xF0FF) == 0x4008: s = f"shll2 R{n4}"
    elif (op & 0xF0FF) == 0x4009: s = f"shlr2 R{n4}"
    elif (op & 0xF00F) == 0x6003: s = f"mov R{m4},R{n4}"
    elif (op & 0xFF00) == 0xE000:
        s = f"mov #{(imm8_4 if imm8_4<128 else imm8_4-256)},R{n4}"
    elif (op & 0xFF00) == 0x8900:
        d = imm8_4; d = d if d<128 else d-256; s = f"bt 0x{a+4+d*2:05X}"
    elif (op & 0xFF00) == 0x8B00:
        d = imm8_4; d = d if d<128 else d-256; s = f"bf 0x{a+4+d*2:05X}"
    elif (op & 0xFF00) == 0x8F00:
        d = imm8_4; d = d if d<128 else d-256; s = f"bf/s 0x{a+4+d*2:05X}"
    elif (op & 0xFF00) == 0x8D00:
        d = imm8_4; d = d if d<128 else d-256; s = f"bt/s 0x{a+4+d*2:05X}"
    elif (op & 0xF0FF) == 0x405A: s = f"lds R{n4},FPUL"
    elif (op & 0xF0FF) == 0x400B: s = f"jsr @R{n4}"
    elif (op & 0xF0FF) == 0x002A: s = f"sts PR,R{n4}"
    elif (op & 0xF0FF) == 0x4022: s = f"sts.l PR,@-R{n4}"
    elif (op & 0xF00F) == 0x2008: s = f"tst R{m4},R{n4}"
    else: s = f"?? 0x{op:04X}"
    print(f"  {a:05X}: {op:04X}  {s}")

print()
print("="*70)
print("CRITICAL INSIGHT - What is the value table format?")
print("="*70)
print()
print("BEACC: fmov.s @R1+,FR1 reads a FLOAT (f32) from val_ptr+index*4")
print("This means the value table at 0xCE5A4 MUST be f32 values, not u16!")
print()
print("Let me re-read 0xCE5A4 as bytes and understand:")
raw = rom[0xCE5A4:0xCE5A4+36]
print(f"Hex at 0xCE5A4: {raw.hex()}")
print()
print("As f32 values:")
for i in range(9):
    fv = rf32(0xCE5A4 + i*4)
    b = rom[0xCE5A4+i*4:0xCE5A4+i*4+4]
    print(f"  [{i}] {b.hex()}: {fv}")
print()
print("BUT those f32 values look like: 0x00640064 = 0.0 with suffix...")
print("Specifically, 0x00640064 is NOT a valid normalized float.")
print("Let's check if BECA8/BEACC interpret value table as WORDS not floats.")
print()

# The key: fmov.s @R1+,FR1 ALWAYS reads 4 bytes as f32 on SH-2
# If val_ptr values are stored as u16 pairs packed into 32 bits, the fmov
# would read them as a weird float.
#
# But the u16 values 100,100 -> bytes 00 64 00 64
# As f32: 0x00640064 -- this is a denormalized float very close to 0
# That cannot be right.
#
# ALTERNATIVE: Maybe the value table IS f32 but scaled differently.
# Let me check the bytes at CE5A4 more carefully.
print("Raw bytes at 0xCE5A4 in groups of 4:")
for i in range(9):
    a = 0xCE5A4 + i*4
    b = rom[a:a+4]
    fv = struct.unpack('>f', b)[0]
    iv = struct.unpack('>I', b)[0]
    hv = struct.unpack('>H', b)[0]
    lv = struct.unpack('>H', b[2:])[0]
    print(f"  {a:05X}: {b.hex()}  -> f32={fv:e}  u32={iv}  u16hi={hv}  u16lo={lv}")

print()
print("CONCLUSION: The u16 values (100,100,100,100,100,50,50,37,37) are each")
print("2 bytes. They are read with fmov.s which reads 4 bytes at a time.")
print("So the 'effective float' is built from two consecutive u16 values.")
print()
print("0x0064 0x0064 -> bytes 00 64 00 64 -> f32 = ?")
fv = struct.unpack('>f', bytes([0x00, 0x64, 0x00, 0x64]))[0]
print(f"  f32(0x00640064) = {fv:e}")
print()
print("This would give an extremely small decay delta -- unlikely to be correct.")
print()
print("Let me check: maybe the axis at CE580 are also u16 not f32?")
print("If so, the struct format would be different.")
print()
print("CE580 as u16 pairs:")
for i in range(9):
    a = 0xCE580 + i*2
    v = ru16(a)
    print(f"  [{i}] @{a:05X}: 0x{v:04X} = {v}")

print()
print("CE580 already shown as f32 = 0.0, 1000.0, 2000.0 ... 8000.0")
print("So axis IS f32, but values at CE5A4 might be differently-spaced.")
print()
print("WAIT - maybe val_ptr in the descriptor for this specific call is")
print("NOT 0xCE5A4 but something else. Let me re-check BE830 flow:")
print()
print("BE848: 5142 mov.l @(8,R4),R1  ; R1 = val_ptr from descriptor @(8,R4)")
desc = 0xAD090
val_from_desc = ru32(desc + 8)
axis_from_desc = ru32(desc + 4)
print(f"  R4=0xAD090, @(8, 0xAD090) = @0xAD098 = 0x{val_from_desc:08X}")
print(f"  So R1 = 0x{val_from_desc:08X} = val_ptr = 0x{val_from_desc:05X}")
print()
print(f"  @(4, 0xAD090) = axis_ptr = 0x{axis_from_desc:05X}")

# Check if BE830 also does some scaling of the output
# After jsr @R2 (BEACC returns FR2 = interpolated result):
# BE84A checks flags etc.
# BE84E: F12C fmov FR2,FR1  -> FR1 = interpolated val
# BE858: lds.l @R15+,PR
# BE85A: rts
# BE85C: fmov FR1,FR0  -> FR0 = result returned to caller

print()
print("="*70)
print("Final output chain:")
print("  BEACC returns result in FR2")
print("  BE84E: fmov FR2,FR1")
print("  BE85C (rts delay slot): fmov FR1,FR0")
print("  So FR0 = interpolated f32 value from val table")
print()
print("The value table IS read as f32 by fmov.s")
print("But 0x00640064 as f32 = very small number (near-zero denorm)")
print()
print("ALTERNATIVE HYPOTHESIS: The value table is NOT at CE5A4 for the")
print("decay-delta lookup. Let me check what descriptor IS used.")

# Let me trace what R4 points to when jsr @R5 is called in sub_36070
# From the previous analysis:
# sub_36070 uses descriptor at 0xAD090 for one table
# But let me verify by checking the actual memory around that call site

# From find_writes analysis, the call chain was:
# 0x3603A: mov.l @(?,PC),R?  loading 0xBE830 (function ptr)
# 0x360D2: loading 0xFFFF79F0 into R12
# 0x36208: fmov.s FR0,@(R0,R12)  -- the write

# What does R4 contain at the jsr @R5 call?
# Let's look at sub_36070 more carefully around the descriptor load
print()
print("="*70)
print("Checking what R4 is loaded with before jsr @R5 at 0x36208")
print("This determines which calibration table is being looked up")
print("="*70)

# Read the area before 0x36208
for a in range(0x361E0, 0x36220, 2):
    op = ru16(a)
    n5 = (op>>8)&0xF
    m5 = (op>>4)&0xF
    hi5 = (op>>12)&0xF
    imm8_5 = op&0xFF

    if (op & 0xF000) == 0xD000:
        disp5 = (op & 0xFF) * 4
        pc4 = (a + 4) & ~3
        tgt = pc4 + disp5
        val = ru32(tgt)
        s = f"mov.l @(0x{disp5:02X},PC),R{n5}  ; @0x{tgt:05X}=0x{val:08X}"
    elif (op & 0xF000) == 0x9000:
        disp5 = (op & 0xFF) * 2
        tgt = a + 4 + disp5
        val = ru16(tgt)
        sval = struct.unpack('>h', rom[tgt:tgt+2])[0]
        s = f"mov.w @(0x{disp5:02X},PC),R{n5}  ; @0x{tgt:05X}=0x{val:04X}={sval}"
    elif (op & 0xF00F) == 0x6003: s = f"mov R{m5},R{n5}"
    elif (op & 0xF00F) == 0xF006: s = f"fmov.s @R{n5},FR{m5}"
    elif (op & 0xF00F) == 0xF005: s = f"fmov.s @(R0,R{n5}),FR{m5}"
    elif (op & 0xF00F) == 0xF007: s = f"fmov.s FR{m5},@(R0,R{n5})"
    elif (op & 0xF00F) == 0xF00C: s = f"fmov FR{m5},FR{n5}"
    elif (op & 0xF0FF) == 0x400B: s = f"jsr @R{n5}"
    elif op == 0x000B: s = "rts"
    elif op == 0x0009: s = "nop"
    elif (op & 0xFF00) == 0x7000:
        s = f"add #{(imm8_5 if imm8_5<128 else imm8_5-256)},R{n5}"
    elif (op & 0xF00F) == 0x300C: s = f"add R{m5},R{n5}"
    elif (op & 0xF0FF) == 0x4008: s = f"shll2 R{n5}"
    elif (op & 0xFF00) == 0xE000:
        s = f"mov #{(imm8_5 if imm8_5<128 else imm8_5-256)},R{n5}"
    elif (op & 0xF0FF) == 0x002A: s = f"sts PR,R{n5}"
    elif (op & 0xF00F) == 0x5000:
        disp5 = (op&0xF)*4; s = f"mov.l @(0x{disp5:02X},R{m5}),R{n5}"
    elif (op & 0xF00F) == 0xF000: s = f"fadd FR{m5},FR{n5}"
    elif (op & 0xF00F) == 0xF001: s = f"fmul FR{m5},FR{n5}"
    elif (op & 0xF0FF) == 0xF02D: s = f"float FPUL,FR{n5}"
    elif (op & 0xF0FF) == 0xF00D: s = f"fsts FPUL,FR{n5}"
    elif (op & 0xF0FF) == 0x405A: s = f"lds R{n5},FPUL"
    elif (op & 0xF0FF) == 0x4026: s = f"lds.l @R{n5}+,PR"
    elif (op & 0xFF00) == 0xD000:
        disp5 = (op & 0xFF) * 4; pc4 = (a + 4) & ~3; tgt = pc4 + disp5
        s = f"mov.l @(0x{disp5:02X},PC),R{n5}  ; =0x{ru32(tgt):08X}"
    elif (op & 0xF00F) == 0xF008: s = f"fmov.s @R{n5}+,FR{m5}"
    elif (op & 0xF00F) == 0xF00A: s = f"fmov.s FR{m5},@R{n5}"
    elif (op & 0xF00F) == 0xF004: s = f"fcmp/lt FR{m5},FR{n5}"
    elif (op & 0xFF00) == 0x8D00:
        d = imm8_5; d = d if d<128 else d-256; s = f"bt/s 0x{a+4+d*2:05X}"
    elif (op & 0xFF00) == 0x8B00:
        d = imm8_5; d = d if d<128 else d-256; s = f"bf 0x{a+4+d*2:05X}"
    elif (op & 0xFF00) == 0x8900:
        d = imm8_5; d = d if d<128 else d-256; s = f"bt 0x{a+4+d*2:05X}"
    elif (op & 0xF0FF) == 0x4022: s = f"sts.l PR,@-R{n5}"
    else: s = f"?? 0x{op:04X}"
    marker = " <-- write to FFFF79E0" if a == 0x3620E else ""
    marker = " <-- jsr @R5" if a == 0x36208 else marker
    print(f"  {a:05X}: {op:04X}  {s}{marker}")
