#!/usr/bin/env python3
"""
Analyze the function at 0xBE830 (the function pointer called at 0x36208)
and the calibration tables it accesses (R4 = 0xAD090 at the critical call).
Also look at the four cal table pointers used throughout the function.
"""
import struct

ROM_PATH = 'C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin'
with open(ROM_PATH, 'rb') as f:
    rom = f.read()

def ru16(a): return struct.unpack('>H', rom[a:a+2])[0]
def ru32(a): return struct.unpack('>I', rom[a:a+4])[0]
def rf32(a): return struct.unpack('>f', rom[a:a+4])[0]
def rs8(v): return v if v < 128 else v - 256
def sign12(v): return v if v < 2048 else v - 4096
GBR = 0xFFFF798C  # GBR set at 0x3607E

def dis(addr, gbr_base=0xFFFF798C):
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
    if op == 0x4F22: return f"  {addr:06X}: {op:04X}  sts.l PR,@-R15 <<PROLOGUE>>"
    if op == 0x4F26: return f"  {addr:06X}: {op:04X}  lds.l @R15+,PR"
    if top == 0x0:
        sub = op & 0xF
        if sub == 0x3: return f"  {addr:06X}: {op:04X}  bsrf R{n}"
        if sub == 0x6: return f"  {addr:06X}: {op:04X}  mov.l R{m},@(R0,R{n})"
        if sub == 0x7: return f"  {addr:06X}: {op:04X}  mul.l R{m},R{n}"
        if sub == 0x2:
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
        return f"  {addr:06X}: {op:04X}  bsr 0x{t:05X} <<CALL>>"
    if top == 0xC:
        sub = (op >> 8) & 0xF
        if sub == 0x7:
            pa = ((addr + 4) & ~3) + d8 * 4
            return f"  {addr:06X}: {op:04X}  mova @(0x{pa:05X},PC),R0"
        if sub == 0x6:
            disp = d8 * 4
            return f"  {addr:06X}: {op:04X}  mov.l @({disp:#x},GBR),R0  ; [{gbr_base+disp:08X}]"
        if sub == 0x2:
            disp = d8 * 4
            return f"  {addr:06X}: {op:04X}  mov.l R0,@({disp:#x},GBR)  ; [{gbr_base+disp:08X}]"
        if sub == 0x0:
            return f"  {addr:06X}: {op:04X}  mov.b R0,@({d8:#x},GBR)  ; [{gbr_base+d8:08X}]"
        if sub == 0x1:
            disp = d8 * 2
            return f"  {addr:06X}: {op:04X}  mov.w R0,@({disp:#x},GBR)  ; [{gbr_base+disp:08X}]"
        if sub == 0x4:
            return f"  {addr:06X}: {op:04X}  mov.b @({d8:#x},GBR),R0  ; [{gbr_base+d8:08X}]"
        if sub == 0x5:
            disp = d8 * 2
            return f"  {addr:06X}: {op:04X}  mov.w @({disp:#x},GBR),R0  ; [{gbr_base+disp:08X}]"
        if sub == 0x8: return f"  {addr:06X}: {op:04X}  tst #0x{d8:02X},R0"
        if sub == 0x9: return f"  {addr:06X}: {op:04X}  and #0x{d8:02X},R0"
        if sub == 0xB: return f"  {addr:06X}: {op:04X}  or #0x{d8:02X},R0"
    if top == 0xD:
        pool = ((addr + 4) & ~3) + d8 * 4
        if pool + 3 < len(rom):
            val = ru32(pool)
            extra = ""
            if 0xFFFF0000 <= val <= 0xFFFFFFFF:
                extra = f"  (RAM 0x{val:08X})"
            elif val < len(rom):
                extra = f"  (ROM 0x{val:05X})"
                try:
                    fv = rf32(val)
                    if 1e-6 < abs(fv) < 1e6:
                        extra = f"  (->ROM 0x{val:05X} = float {fv:.8f})"
                except: pass
            else:
                try:
                    fv = struct.unpack('>f', struct.pack('>I', val))[0]
                    if 1e-6 < abs(fv) < 1e8:
                        extra = f"  (float {fv:.8f})"
                except: pass
            return f"  {addr:06X}: {op:04X}  mov.l @(0x{pool:05X},PC),R{n}  ; R{n}=0x{val:08X}{extra}"
    if top == 0xE:
        return f"  {addr:06X}: {op:04X}  mov #{rs8(d8)},R{n}"
    if top == 0xF:
        sub = op & 0xF
        fn = n; fm = m
        if sub == 0x0: return f"  {addr:06X}: {op:04X}  fadd FR{fm},FR{fn}"
        if sub == 0x1: return f"  {addr:06X}: {op:04X}  fsub FR{fm},FR{fn}"
        if sub == 0x2: return f"  {addr:06X}: {op:04X}  fmul FR{fm},FR{fn}"
        if sub == 0x3: return f"  {addr:06X}: {op:04X}  fdiv FR{fm},FR{fn}"
        if sub == 0x4: return f"  {addr:06X}: {op:04X}  fcmp/eq FR{fm},FR{fn}"
        if sub == 0x5: return f"  {addr:06X}: {op:04X}  fcmp/gt FR{fm},FR{fn}"
        if sub == 0x6: return f"  {addr:06X}: {op:04X}  fmov.s @(R0,R{m}),FR{fn}  [READ]"
        if sub == 0x7: return f"  {addr:06X}: {op:04X}  fmov.s FR{fn},@(R0,R{m})  [WRITE]"
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


# ============================================================
# 1. Analyze function at 0xBE830 (the function ptr stored at @(12,R15))
# ============================================================
print("=" * 80)
print("FUNCTION AT 0xBE830 (called multiple times, returns float in FR0)")
print("This is the function pointer stored at @(12,R15)")
print("=" * 80)
print()
# This function is a 2D lookup / interpolation function
# Called with R4 = calibration table pointer, FR4 = input value
# Returns interpolated float in FR0
for a in range(0xBE830, 0xBE830 + 200, 2):
    print(dis(a))
    op = ru16(a)
    if op == 0x000B:
        # Check if next is nop or prologue
        next_op = ru16(a + 2) if a + 2 < len(rom) else 0
        if next_op == 0x0009 or next_op == 0x4F22:
            break

print()

# ============================================================
# 2. Analyze the calibration table pointed to by R4=0xAD090
#    at the critical jsr that produces FR0 = decay delta
# ============================================================
print("=" * 80)
print("CALIBRATION TABLE at 0xAD090 (R4 argument to critical call at 0x36208)")
print("This determines the delta written to FFFF79E0")
print("=" * 80)
print()

# 0xAD090 contains 4 ROM pointers and other data
# Let's interpret it as the descriptor struct for the lookup function
# Common Subaru cal table descriptor format:
# [0]: ptr to X axis values
# [4]: ptr to Y/Z axis values
# [8]: ptr to table data
# [12]: 32-bit value
# [16]: more params

print("Descriptor at 0xAD090:")
for i in range(12):
    a2 = 0xAD090 + i * 4
    val = ru32(a2)
    fv_str = ""
    try:
        fv = rf32(a2)
        if 1e-8 < abs(fv) < 1e10:
            fv_str = f"  (float: {fv:.8f})"
    except: pass
    ptr_str = ""
    if 0 < val < len(rom):
        ptr_str = f"  -> ROM 0x{val:05X}"
        # If it points to data, show a few floats
        try:
            fv2 = rf32(val)
            ptr_str += f" = float {fv2:.6f}"
        except: pass
    print(f"  0x{a2:05X}: 0x{val:08X}{fv_str}{ptr_str}")

print()
print("Values at 0x90800 (first pointer from descriptor):")
for i in range(16):
    a2 = 0x90800 + i * 4
    if a2 + 3 < len(rom):
        val = ru32(a2)
        fv_str = ""
        try:
            fv = rf32(a2)
            if 1e-38 < abs(fv) < 1e10:
                fv_str = f"  (float: {fv:.8f})"
        except: pass
        print(f"  0x{a2:05X}: 0x{val:08X}{fv_str}")

print()

# ============================================================
# 3. Other cal tables used in the function at 0x36070
#    at 0x360BE: R4=0xAC5D0, 0x360CA: R4=0xAC5E4
#    at various jsr @R2 calls with R2=0xBE8E4
# ============================================================
print("=" * 80)
print("Function at 0xBE8E4 (another lookup, called many times with different R4 cal ptrs)")
print("=" * 80)
for a in range(0xBE8E4, 0xBE8E4 + 200, 2):
    print(dis(a))
    op = ru16(a)
    if op == 0x000B:
        next_op = ru16(a + 2) if a + 2 < len(rom) else 0
        if next_op == 0x0009 or next_op == 0x4F22:
            break

print()

# Cal tables used with 0xBE8E4:
print("=" * 80)
print("Calibration tables used with 0xBE8E4 lookup function:")
print("=" * 80)
cal_tables = [
    (0xAD674, "R4 at 0x360F6 (used with FR5=@R15, FR4=@(4,R15))"),
    (0xAD6AC, "R4 at 0x36106"),
    (0xAD690, "R4 at 0x3613A"),
    (0xAD6C8, "R4 at 0x3616A and 0x3618E"),
    (0xAD6E4, "R4 at 0x36178"),
    (0xAD700, "R4 at 0x3617E"),
]
for (addr, desc) in cal_tables:
    print(f"\n  Table at 0x{addr:05X}: {desc}")
    for i in range(8):
        a2 = addr + i * 4
        val = ru32(a2)
        fv_str = ""
        try:
            fv = rf32(a2)
            if 1e-8 < abs(fv) < 1e8:
                fv_str = f"  (float: {fv:.6f})"
        except: pass
        ptr_str = ""
        if 0 < val < len(rom):
            ptr_str = f"  -> ROM 0x{val:05X}"
        print(f"    0x{a2:05X}: 0x{val:08X}{fv_str}{ptr_str}")

print()
print("=" * 80)
print("Cal table at 0xAC5D0 and 0xAC5E4 (used early in function 0x36070)")
print("These compute FR14 and FR0 before the decay delta write")
print("=" * 80)
for tbl_addr in [0xAC5D0, 0xAC5E4, 0xAC5A8]:
    print(f"\nTable at 0x{tbl_addr:05X}:")
    for i in range(8):
        a2 = tbl_addr + i * 4
        val = ru32(a2)
        fv_str = ""
        try:
            fv = rf32(a2)
            if 1e-8 < abs(fv) < 1e8:
                fv_str = f"  (float: {fv:.6f})"
        except: pass
        ptr_str = ""
        if 0 < val < len(rom):
            ptr_str = f"  -> ROM 0x{val:05X}"
        print(f"    0x{a2:05X}: 0x{val:08X}{fv_str}{ptr_str}")

print()
print("=" * 80)
print("SUMMARY: What writes to FFFF79E0?")
print("=" * 80)
print()
print("Write location: ROM 0x3620E")
print("Instruction: fmov.s FR0, @(R0, R12)")
print("  R0 = -16 (set at 0x3620C: mov #-16,R0)")
print("  R12 = 0xFFFF79F0 (set at 0x360D2: loaded from pool at 0x36284)")
print("  Effective address: 0xFFFF79F0 + (-16) = 0xFFFF79E0")
print()
print("Source: FR0 = return value of jsr @R5 at 0x36208")
print("  R5 = @(12, R15) = function pointer = 0xBE830 (lookup/interpolation function)")
print("  R4 = 0xAD090 (calibration table descriptor for the delta value)")
print("  FR4 = @R15 (from delay slot fmov.s @R15,FR4 - stack top = input signal)")
print()
print("Function context: sub_36070")
print("  GBR = 0xFFFF798C (set at 0x3607E)")
print("  This function is the AFL decay/transition manager")
print()
print("The decay delta (FFFF79E0) is computed by interpolating calibration table 0xAD090")
print("with input FR4 = the current AFL or throttle position value at @R15.")
print()
print("To tune the decay rate, look at calibration table 0xAD090 and its descriptor.")
