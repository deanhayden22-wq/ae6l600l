#!/usr/bin/env python3
"""
Detailed trace of the function writing to FFFF79E0 at ROM 0x3620E.
Focus on: what is FR12 and how is it computed?
"""
import struct

ROM_PATH = 'C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin'
TARGET = 0xFFFF79E0
WRITE_ADDR = 0x3620E

with open(ROM_PATH, 'rb') as f:
    rom = f.read()

def ru16(a): return struct.unpack('>H', rom[a:a+2])[0]
def ru32(a): return struct.unpack('>I', rom[a:a+4])[0]
def rf32(a): return struct.unpack('>f', rom[a:a+4])[0]
def rs8(v): return v if v < 128 else v - 256
def sign12(v): return v if v < 2048 else v - 4096
GBR = 0xFFFF7450

def dis(addr):
    if addr < 0 or addr + 1 >= len(rom):
        return f"  {addr:06X}: ??"
    op = ru16(addr)
    top = (op >> 12) & 0xF
    n = (op >> 8) & 0xF
    m = (op >> 4) & 0xF
    d4 = op & 0xF
    d8 = op & 0xFF

    if op == 0x000B: return f"  {addr:06X}: {op:04X}  rts"
    if op == 0x0009: return f"  {addr:06X}: {op:04X}  nop"
    if op == 0x4F22: return f"  {addr:06X}: {op:04X}  sts.l  PR,@-R15  <<PROLOGUE>>"
    if op == 0x4F26: return f"  {addr:06X}: {op:04X}  lds.l  @R15+,PR"

    if top == 0x0:
        sub = op & 0xF
        if sub == 0x3: return f"  {addr:06X}: {op:04X}  bsrf R{n}"
        if sub == 0x6: return f"  {addr:06X}: {op:04X}  mov.l R{m},@(R0,R{n})"
        if sub == 0x7: return f"  {addr:06X}: {op:04X}  mul.l R{m},R{n}"
        if sub == 0x2:
            if m == 0: return f"  {addr:06X}: {op:04X}  stc SR,R{n}"
            if m == 1: return f"  {addr:06X}: {op:04X}  stc GBR,R{n}"
        if sub == 0xA:
            if m == 2: return f"  {addr:06X}: {op:04X}  sts PR,R{n}"
        if sub == 0xC: return f"  {addr:06X}: {op:04X}  mov.b @(R0,R{m}),R{n}"
        if sub == 0xD: return f"  {addr:06X}: {op:04X}  mov.w @(R0,R{m}),R{n}"
        if sub == 0xE: return f"  {addr:06X}: {op:04X}  mov.l @(R0,R{m}),R{n}"
    if top == 0x1:
        return f"  {addr:06X}: {op:04X}  mov.l R{m},@({d4*4},R{n})"
    if top == 0x2:
        sub = op & 0xF
        if sub == 0: return f"  {addr:06X}: {op:04X}  mov.b R{m},@R{n}"
        if sub == 1: return f"  {addr:06X}: {op:04X}  mov.w R{m},@R{n}"
        if sub == 2: return f"  {addr:06X}: {op:04X}  mov.l R{m},@R{n}"
        if sub == 4: return f"  {addr:06X}: {op:04X}  mov.b R{m},@-R{n}"
        if sub == 5: return f"  {addr:06X}: {op:04X}  mov.w R{m},@-R{n}"
        if sub == 6: return f"  {addr:06X}: {op:04X}  mov.l R{m},@-R{n}"
        if sub == 7: return f"  {addr:06X}: {op:04X}  div0s R{m},R{n}"
        if sub == 8: return f"  {addr:06X}: {op:04X}  tst R{m},R{n}"
        if sub == 9: return f"  {addr:06X}: {op:04X}  and R{m},R{n}"
        if sub == 0xA: return f"  {addr:06X}: {op:04X}  xor R{m},R{n}"
        if sub == 0xB: return f"  {addr:06X}: {op:04X}  or R{m},R{n}"
        if sub == 0xC: return f"  {addr:06X}: {op:04X}  cmp/str R{m},R{n}"
        if sub == 0xE: return f"  {addr:06X}: {op:04X}  mulu.w R{m},R{n}"
        if sub == 0xF: return f"  {addr:06X}: {op:04X}  muls.w R{m},R{n}"
    if top == 0x3:
        sub = op & 0xF
        ops3 = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",4:"div1",5:"dmulu.l",6:"cmp/hi",7:"cmp/gt",
                8:"sub",0xA:"subc",0xB:"subv",0xC:"add",0xD:"dmuls.l",0xE:"addc",0xF:"addv"}
        if sub in ops3: return f"  {addr:06X}: {op:04X}  {ops3[sub]} R{m},R{n}"
    if top == 0x4:
        low8 = op & 0xFF
        if low8 == 0x22: return f"  {addr:06X}: {op:04X}  sts.l PR,@-R{n}"
        if low8 == 0x26: return f"  {addr:06X}: {op:04X}  lds.l @R{n}+,PR"
        if low8 == 0x0B: return f"  {addr:06X}: {op:04X}  jsr @R{n}"
        if low8 == 0x2B: return f"  {addr:06X}: {op:04X}  jmp @R{n}"
        if low8 == 0x15: return f"  {addr:06X}: {op:04X}  cmp/pl R{n}"
        if low8 == 0x11: return f"  {addr:06X}: {op:04X}  cmp/pz R{n}"
        if low8 == 0x10: return f"  {addr:06X}: {op:04X}  dt R{n}"
        if low8 == 0x00: return f"  {addr:06X}: {op:04X}  shll R{n}"
        if low8 == 0x01: return f"  {addr:06X}: {op:04X}  shlr R{n}"
        if low8 == 0x08: return f"  {addr:06X}: {op:04X}  shll2 R{n}"
        if low8 == 0x09: return f"  {addr:06X}: {op:04X}  shlr2 R{n}"
        if low8 == 0x18: return f"  {addr:06X}: {op:04X}  shll8 R{n}"
        if low8 == 0x28: return f"  {addr:06X}: {op:04X}  shll16 R{n}"
        if low8 == 0x2A: return f"  {addr:06X}: {op:04X}  lds R{n},PR"
        if low8 == 0x0A: return f"  {addr:06X}: {op:04X}  lds R{n},MACH"
        if low8 == 0x1A: return f"  {addr:06X}: {op:04X}  lds R{n},MACL"
        if low8 == 0x1E: return f"  {addr:06X}: {op:04X}  ldc R{n},GBR"
        if low8 == 0x24: return f"  {addr:06X}: {op:04X}  rotcl R{n}"
        lo1 = op & 0xF
        if lo1 == 0xC: return f"  {addr:06X}: {op:04X}  shad R{m},R{n}"
        if lo1 == 0xD: return f"  {addr:06X}: {op:04X}  shld R{m},R{n}"
    if top == 0x5:
        return f"  {addr:06X}: {op:04X}  mov.l @({d4*4},R{m}),R{n}"
    if top == 0x6:
        sub = op & 0xF
        if sub == 0: return f"  {addr:06X}: {op:04X}  mov.b @R{m},R{n}"
        if sub == 1: return f"  {addr:06X}: {op:04X}  mov.w @R{m},R{n}"
        if sub == 2: return f"  {addr:06X}: {op:04X}  mov.l @R{m},R{n}"
        if sub == 3: return f"  {addr:06X}: {op:04X}  mov R{m},R{n}"
        if sub in (4, 5, 6):
            sz = {4: "mov.b", 5: "mov.w", 6: "mov.l"}[sub]
            return f"  {addr:06X}: {op:04X}  {sz} @R{m}+,R{n}"
        if sub == 7: return f"  {addr:06X}: {op:04X}  not R{m},R{n}"
        if sub == 0xB: return f"  {addr:06X}: {op:04X}  neg R{m},R{n}"
        if sub in (0xC, 0xD, 0xE, 0xF):
            ops = {0xC: "extu.b", 0xD: "extu.w", 0xE: "exts.b", 0xF: "exts.w"}
            return f"  {addr:06X}: {op:04X}  {ops[sub]} R{m},R{n}"
    if top == 0x7:
        return f"  {addr:06X}: {op:04X}  add #{rs8(d8)},R{n}"
    if top == 0x8:
        sub = (op >> 8) & 0xF
        if sub == 0x8: return f"  {addr:06X}: {op:04X}  cmp/eq #{rs8(d8)},R0"
        if sub == 0x9:
            t = addr + 4 + rs8(d8) * 2
            return f"  {addr:06X}: {op:04X}  bt 0x{t:05X}"
        if sub == 0xB:
            t = addr + 4 + rs8(d8) * 2
            return f"  {addr:06X}: {op:04X}  bf 0x{t:05X}"
        if sub == 0xD:
            t = addr + 4 + rs8(d8) * 2
            return f"  {addr:06X}: {op:04X}  bt/s 0x{t:05X}"
        if sub == 0xF:
            t = addr + 4 + rs8(d8) * 2
            return f"  {addr:06X}: {op:04X}  bf/s 0x{t:05X}"
        if sub == 0x0: return f"  {addr:06X}: {op:04X}  mov.b R0,@({d4},R{m})"
        if sub == 0x1: return f"  {addr:06X}: {op:04X}  mov.w R0,@({d4 * 2},R{m})"
        if sub == 0x4: return f"  {addr:06X}: {op:04X}  mov.b @({d4},R{m}),R0"
        if sub == 0x5: return f"  {addr:06X}: {op:04X}  mov.w @({d4 * 2},R{m}),R0"
    if top == 0x9:
        pool = addr + 4 + d8 * 2
        if pool + 1 < len(rom):
            val = ru16(pool)
            sval = struct.unpack('>h', rom[pool:pool + 2])[0]
            return f"  {addr:06X}: {op:04X}  mov.w @(0x{pool:05X},PC),R{n}  ; R{n}=0x{val:04X} ({sval})"
    if top == 0xA:
        t = addr + 4 + sign12(op & 0xFFF) * 2
        return f"  {addr:06X}: {op:04X}  bra 0x{t:05X}"
    if top == 0xB:
        t = addr + 4 + sign12(op & 0xFFF) * 2
        return f"  {addr:06X}: {op:04X}  bsr 0x{t:05X}  <<CALL>>"
    if top == 0xC:
        sub = (op >> 8) & 0xF
        if sub == 0x7:
            pa = ((addr + 4) & ~3) + d8 * 4
            if pa + 3 < len(rom):
                val = ru32(pa)
                return f"  {addr:06X}: {op:04X}  mova @(0x{pa:05X},PC),R0  ; R0=0x{pa:05X}"
        if sub == 0x6:
            disp = d8 * 4
            return f"  {addr:06X}: {op:04X}  mov.l @({disp:#x},GBR),R0  ; [{GBR+disp:08X}]"
        if sub == 0x2:
            disp = d8 * 4
            return f"  {addr:06X}: {op:04X}  mov.l R0,@({disp:#x},GBR)  ; [{GBR+disp:08X}]"
        if sub == 0x0:
            return f"  {addr:06X}: {op:04X}  mov.b R0,@({d8:#x},GBR)  ; [{GBR+d8:08X}]"
        if sub == 0x1:
            disp = d8 * 2
            return f"  {addr:06X}: {op:04X}  mov.w R0,@({disp:#x},GBR)  ; [{GBR+disp:08X}]"
        if sub == 0x4:
            return f"  {addr:06X}: {op:04X}  mov.b @({d8:#x},GBR),R0  ; [{GBR+d8:08X}]"
        if sub == 0x5:
            disp = d8 * 2
            return f"  {addr:06X}: {op:04X}  mov.w @({disp:#x},GBR),R0  ; [{GBR+disp:08X}]"
        if sub == 0x8: return f"  {addr:06X}: {op:04X}  tst #0x{d8:02X},R0"
        if sub == 0x9: return f"  {addr:06X}: {op:04X}  and #0x{d8:02X},R0"
        if sub == 0xB: return f"  {addr:06X}: {op:04X}  or #0x{d8:02X},R0"
    if top == 0xD:
        pool = ((addr + 4) & ~3) + d8 * 4
        if pool + 3 < len(rom):
            val = ru32(pool)
            extra = ""
            if 0xFFFF0000 <= val <= 0xFFFFFFFF:
                diff_s = val - 0xFFFF79E0
                if diff_s >= 0x80000000: diff_s -= 0x100000000
                if val == 0xFFFF79E0:
                    extra = "  <<TARGET FFFF79E0>>"
                elif abs(diff_s) <= 512:
                    extra = f"  (RAM {diff_s:+d} from FFFF79E0 = 0x{val:08X})"
                else:
                    extra = f"  (RAM 0x{val:08X})"
            elif val < len(rom):
                extra = f"  (ROM ptr 0x{val:05X})"
                try:
                    fv = rf32(val)
                    if 1e-8 < abs(fv) < 1e8:
                        extra = f"  (->ROM 0x{val:05X} = float {fv:.8f})"
                except:
                    pass
            else:
                try:
                    fv = struct.unpack('>f', struct.pack('>I', val))[0]
                    if 1e-8 < abs(fv) < 1e8:
                        extra = f"  (float {fv:.8f})"
                except:
                    pass
            return f"  {addr:06X}: {op:04X}  mov.l @(0x{pool:05X},PC),R{n}  ; R{n}=0x{val:08X}{extra}"
    if top == 0xE:
        return f"  {addr:06X}: {op:04X}  mov #{rs8(d8)},R{n}"
    if top == 0xF:
        sub = op & 0xF
        fn = n
        fm = m
        if sub == 0x0: return f"  {addr:06X}: {op:04X}  fadd FR{fm},FR{fn}"
        if sub == 0x1: return f"  {addr:06X}: {op:04X}  fsub FR{fm},FR{fn}"
        if sub == 0x2: return f"  {addr:06X}: {op:04X}  fmul FR{fm},FR{fn}"
        if sub == 0x3: return f"  {addr:06X}: {op:04X}  fdiv FR{fm},FR{fn}"
        if sub == 0x4: return f"  {addr:06X}: {op:04X}  fcmp/eq FR{fm},FR{fn}"
        if sub == 0x5: return f"  {addr:06X}: {op:04X}  fcmp/gt FR{fm},FR{fn}"
        if sub == 0x6: return f"  {addr:06X}: {op:04X}  fmov.s @(R0,R{m}),FR{fn}  [READ  R0+R{m}]"
        if sub == 0x7:
            return f"  {addr:06X}: {op:04X}  fmov.s FR{fn},@(R0,R{m})  [WRITE R0+R{m}]"
        if sub == 0x8: return f"  {addr:06X}: {op:04X}  fmov.s @R{m},FR{fn}"
        if sub == 0x9: return f"  {addr:06X}: {op:04X}  fmov.s @R{m}+,FR{fn}"
        if sub == 0xA: return f"  {addr:06X}: {op:04X}  fmov.s FR{fn},@R{m}"
        if sub == 0xB: return f"  {addr:06X}: {op:04X}  fmov.s FR{fn},@-R{m}"
        if sub == 0xC: return f"  {addr:06X}: {op:04X}  fmov FR{fm},FR{fn}"
        if sub == 0xD:
            if fm == 0: return f"  {addr:06X}: {op:04X}  fsts FPUL,FR{fn}"
            if fm == 1: return f"  {addr:06X}: {op:04X}  flds FR{fn},FPUL"
            if fm == 2: return f"  {addr:06X}: {op:04X}  float FPUL,FR{fn}"
            if fm == 3: return f"  {addr:06X}: {op:04X}  ftrc FR{fn},FPUL"
            if fm == 4: return f"  {addr:06X}: {op:04X}  fneg FR{fn}"
            if fm == 5: return f"  {addr:06X}: {op:04X}  fabs FR{fn}"
            if fm == 8: return f"  {addr:06X}: {op:04X}  fldi0 FR{fn}"
            if fm == 9: return f"  {addr:06X}: {op:04X}  fldi1 FR{fn}"
            if fm == 0xA: return f"  {addr:06X}: {op:04X}  lds R{n},FPUL"
        if sub == 0xE: return f"  {addr:06X}: {op:04X}  fmac FR0,FR{fm},FR{fn}"
    return f"  {addr:06X}: {op:04X}  .word 0x{op:04X}"

# Find function prologue by scanning backwards from write addr
func_start = None
for a in range(WRITE_ADDR, 0x34000, -2):
    op = ru16(a)
    if op == 0x4F22:
        func_start = a
        break

print(f"Function prologue at: 0x{func_start:05X}")
print(f"Write at: 0x{WRITE_ADDR:05X}")
print()

# ============================================================
# Dump from function start to find the complete function
# Focus on what computes FR12
# ============================================================
print("=" * 80)
print(f"FUNCTION DISASSEMBLY (from 0x{func_start:05X})")
print("=" * 80)
print()

mark = {WRITE_ADDR: "  <<<< WRITE TO FFFF79E0 (FR12 -> [R0+R12] = FFFF79F0 + (-16))"}

rts_count = 0
for a in range(func_start, func_start + 0x500, 2):
    line = dis(a)
    if a in mark:
        line = line + mark[a]
    print(line)
    op = ru16(a)
    if op == 0x000B:
        rts_count += 1
        if rts_count >= 3 and a > func_start + 0x100:
            print("  ... (truncated at 3rd rts)")
            break

# ============================================================
# Now look at the called function at 0x36208 - what does it return?
# jsr @R5 with R5 = @(12, R15) = function pointer on stack
# The function pointer was pushed when setting up the call
# Need to find what R5 was set to
# Looking at the code:
#   0x36204: D43A  mov.l @(0x362F0,PC),R4  ; R4=0x000AD090 (ROM addr)
#   0x36206: 55F3  mov.l @(12,R15),R5
#   0x36208: 450B  jsr @R5
#   0x3620A: F4F8  fmov.s @R15,FR4
#   0x3620C: E0F0  mov #-16,R0
#   0x3620E: FC07  fmov.s FR12,@(R0,R0) <-- NOTE: THIS IS @(R0+R12) = FFFF79F0-16=FFFF79E0
# Wait, the opcode is FC07:
# F = 0xF, C = dest_reg(n)=12(0xC), 0 = src_reg(m)=0, 7 = indexed write
# fmov.s FRn,@(R0,Rm) = 1111 nnnn mmmm 0111
# So n=12 (FR12), m=0 (R0 is the address base register? NO)
# Wait: 1111 nnnn mmmm 0111
# opcode FC07 = 1111 1100 0000 0111
# n = (0xC) = 12, m = 0
# fmov.s FR12, @(R0, R0)  -- stores FR12 to addr R0+R0
# But R0 = -16 at that point!  R0 + R0 = -32 = FFFF79E0 - 16?? No...
# Wait: R0 = -16 = 0xFFFFFFF0 as 32-bit
# R0 + R0 = 0xFFFFFFE0  -- that's not FFFF79E0!

# CORRECTION: The step 3/4 said R12=0xFFFF79F0, R0=-16 -> FFFF79F0 + (-16) = FFFF79E0
# But the opcode FC07 is: fmov.s FR12,@(R0,R0) = FR12 -> @(R0+R0)
# That would be 0xFFFFFFF0 + 0xFFFFFFF0 = 0xFFFFFFE0 (modulo 32-bit), not FFFF79E0

# Something is off in the encoding. Let me re-check.
# F [n][m] 7 = fmov.s FRm, @(R0,Rn)
# Wait - I need to check which is the address register (n or m)?
# SH2 manual: fmov.s FRm,@(R0,Rn): format F[n][m]7
# The destination address = R0 + Rn, source = FRm
# So for FC07: n=C=12, m=0, opcode = F[12][0]7
# Address = R0 + R12 = (-16) + 0xFFFF79F0 = 0xFFFF79E0
# Source = FR0 (not FR12!)

print()
print("=" * 80)
print("CORRECTION: Opcode FC07 analysis")
print("=" * 80)
op = 0xFC07
n = (op >> 8) & 0xF  # 0xC = 12
m = (op >> 4) & 0xF  # 0x0 = 0
print(f"Opcode: 0x{op:04X}")
print(f"  Pattern: F[n][m]7 = fmov.s FRm,@(R0,Rn)")
print(f"  n = {n} (address register Rn = R12)")
print(f"  m = {m} (source float register FRm = FR0)")
print(f"  Instruction: fmov.s FR0, @(R0, R12)")
print(f"  At 0x3620C: R0 = -16 = 0xFFFFFFF0")
print(f"  R12 = 0xFFFF79F0 (loaded at 0x360D2)")
print(f"  Address = R0 + R12 = 0xFFFFFFF0 + 0xFFFF79F0 = 0x{(0xFFFFFFF0 + 0xFFFF79F0) & 0xFFFFFFFF:08X}")
print(f"  This equals: 0x{((-16) + 0xFFFF79F0) & 0xFFFFFFFF:08X}")
print()
print("So the WRITE IS: fmov.s FR0 -> [FFFF79E0]")
print("Source register is FR0, NOT FR12!")
print()

# So what does FR0 contain at that point?
# From the context:
#   0x36204: D43A  mov.l @(0x362F0,PC),R4 ; R4 = ROM ptr 0xAD090
#   0x36206: 55F3  mov.l @(12,R15),R5     ; R5 = function ptr from stack
#   0x36208: 450B  jsr @R5                 ; call function via R5
#   0x3620A: F4F8  fmov.s @R15,FR4        ; delay slot: FR4 = @R15
#   (return from jsr) -> return value is in FR0 (float functions return in FR0)
#   0x3620C: E0F0  mov #-16,R0
#   0x3620E: FC07  fmov.s FR0,@(R0,R12)   ; WRITE FR0 to FFFF79E0

print("=" * 80)
print("What is the function called at 0x36208?")
print("R5 = @(12, R15) -- a function pointer on the stack frame")
print("R4 = ROM 0xAD090 (first argument - calibration pointer?)")
print()

# What is at ROM 0xAD090?  This looks like a calibration table pointer
addr_r4 = 0xAD090
print(f"Value at ROM 0x{addr_r4:05X}: 0x{ru32(addr_r4):08X}")
try:
    fv = rf32(addr_r4)
    print(f"As float: {fv}")
except:
    pass
# Check if it's a pointer
ptr = ru32(addr_r4)
if 0 < ptr < len(rom):
    print(f"Pointer to ROM 0x{ptr:05X}")
    # Dump a few floats at that location
    print("Floats at that location:")
    for i in range(8):
        a2 = ptr + i*4
        if a2+3 < len(rom):
            print(f"  0x{a2:05X}: {rf32(a2):.6f}")

print()
print("=" * 80)
print("Stack frame analysis - what is at @(12, R15)?")
print("Looking at the function prologue to understand the stack layout")
print("=" * 80)

# Find function prologue
print(f"Function starts at 0x{func_start:05X}")
print()
print("Prologue and early setup (first 80 instructions):")
for a in range(func_start, func_start + 160, 2):
    print(dis(a))
    op2 = ru16(a)
    if op2 == 0x000B and a > func_start + 20:
        break

print()
print("=" * 80)
print("Focus area: 0x36190 - 0x36215 (context just before write)")
print("=" * 80)
for a in range(0x36190, 0x36216, 2):
    line = dis(a)
    if a == WRITE_ADDR:
        line = ">>>" + line[3:] + "  <<<< WRITE FR0 -> [R0+R12] = FFFF79E0"
    print(line)

print()
print("=" * 80)
print("What function does jsr @R5 call? Tracing R5 = @(12,R15)")
print("Need to find where R5's value is pushed to stack")
print("Looking at function entry/args")
print("=" * 80)
# The function at 0x3603A loaded R6=FFFF79F0
# At 0x360D2 loaded R12=FFFF79F0
# jsr @R5 at 0x36208 with R5=@(12,R15)
# The value at @(12,R15) is a function pointer - it came from the caller's args
# or was saved on stack. Let's look at what's pushed near 0x36200
print()
print("Area 0x361E0-0x36215 in detail (tracing FR0 source):")
for a in range(0x361E0, 0x36215+2, 2):
    line = dis(a)
    if a == WRITE_ADDR:
        line = ">>>" + line[3:] + "  <<<< WRITE FR0 -> [R0+R12] = FFFF79E0"
    print(line)

# The jsr at 0x36208 with R5=@(12,R15)
# 55F3 = mov.l @(12,R15),R5  at 0x36206
# What called function returns FR0 with the delta value?
# R4 = 0xAD090 = calibration table addr
# Let's look at what's at 0xAD090
print()
print("=" * 80)
print("ROM pointer 0xAD090 analysis (R4 argument to called function)")
print("=" * 80)
for i in range(16):
    a2 = 0xAD090 + i*4
    if a2+3 < len(rom):
        val = ru32(a2)
        try:
            fv = rf32(a2)
            print(f"  0x{a2:05X}: 0x{val:08X}  (float {fv:.8f})")
        except:
            print(f"  0x{a2:05X}: 0x{val:08X}")

print()
print("=" * 80)
print("Also: Before the jsr at 0x36208, what is @(12,R15)?")
print("  - 0x36206: mov.l @(12,R15),R5")
print("  - @(12,R15) is 3rd word of stack frame = arg or saved reg")
print("  Searching for where @(12,R15) was stored...")
print("=" * 80)
# At 0x3620A in delay slot: fmov.s @R15,FR4
# This means @R15 is a float value too
# The delay slot executes BEFORE jsr returns to next instruction
# So @R15 = FR4 argument to the called function

# Let's look at the broader function starting area to find stack saves
print()
print("Function from 0x360C0 onwards:")
for a in range(0x360C0, 0x36215, 2):
    line = dis(a)
    if a == WRITE_ADDR:
        line = ">>>" + line[3:]
    print(line)
