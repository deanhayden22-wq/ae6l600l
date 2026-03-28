#!/usr/bin/env python3
"""
Disassemble sub_0xBEACC - the linear interpolation routine called for interp_type=0x00.
This function receives:
  R4 = descriptor pointer (e.g. 0xAD090)
  FR0 = input value (axis lookup key)
  R0  = integer index from axis search (sub_BECA8)
  FR1 = fractional position from axis search

We need to determine how it reads the value table and returns FR0.
"""
import struct
ROM_PATH = 'C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin'
with open(ROM_PATH, 'rb') as f:
    rom = f.read()

def ru16(a): return struct.unpack('>H', rom[a:a+2])[0]
def ru32(a): return struct.unpack('>I', rom[a:a+4])[0]
def rf32(a): return struct.unpack('>f', rom[a:a+4])[0]
def rs16(a): return struct.unpack('>h', rom[a:a+2])[0]

def disasm_one(addr):
    op = ru16(addr)
    hi4 = (op >> 12) & 0xF
    n   = (op >> 8) & 0xF
    m   = (op >> 4) & 0xF
    imm8 = op & 0xFF
    imm4 = op & 0xF

    if op == 0x000B: return "rts"
    if op == 0x0009: return "nop"
    if op == 0x001B: return "sleep"
    if op == 0x0008: return "clrt"
    if op == 0x0028: return "clrmac"
    if (op & 0xF0FF) == 0x0023: return f"braf R{n}"
    if (op & 0xF0FF) == 0x0003: return f"bsrf R{n}"
    if (op & 0xFF00) == 0xC300: return f"trapa #{imm8}"
    if (op & 0xF00F) == 0x6003: return f"mov R{m},R{n}"
    if (op & 0xF00F) == 0x6006: return f"mov.b @R{m},R{n}"
    if (op & 0xF00F) == 0x6005: return f"mov.w @R{m},R{n}"
    if (op & 0xF00F) == 0x6002: return f"mov.l @R{m},R{n}"
    if (op & 0xF00F) == 0x6007: return f"not R{m},R{n}"
    if (op & 0xF00F) == 0x600C: return f"extu.b R{m},R{n}"
    if (op & 0xF00F) == 0x600D: return f"extu.w R{m},R{n}"
    if (op & 0xF00F) == 0x600E: return f"exts.b R{m},R{n}"
    if (op & 0xF00F) == 0x600F: return f"exts.w R{m},R{n}"
    if (op & 0xF00F) == 0x6001: return f"mov.w @R{m},R{n}  [sign-extend]"
    if (op & 0xF00F) == 0x6000: return f"mov.b @R{m},R{n}  [sign-extend]"
    if (op & 0xF00F) == 0x2000: return f"mov.b R{m},@R{n}"
    if (op & 0xF00F) == 0x2001: return f"mov.w R{m},@R{n}"
    if (op & 0xF00F) == 0x2002: return f"mov.l R{m},@R{n}"
    if (op & 0xFF00) == 0xE000: return f"mov #{(imm8 if imm8<128 else imm8-256)},R{n}"
    if (op & 0xFF00) == 0x7000: return f"add #{(imm8 if imm8<128 else imm8-256)},R{n}"
    if (op & 0xF00F) == 0x300C: return f"add R{m},R{n}"
    if (op & 0xF00F) == 0x3008: return f"sub R{m},R{n}"
    if (op & 0xF00F) == 0x200A: return f"xor R{m},R{n}"
    if (op & 0xF00F) == 0x2009: return f"and R{m},R{n}"
    if (op & 0xF00F) == 0x200B: return f"or R{m},R{n}"
    if (op & 0xF00F) == 0x3000: return f"cmp/eq R{m},R{n}"
    if (op & 0xF00F) == 0x3002: return f"cmp/hs R{m},R{n}"
    if (op & 0xF00F) == 0x3003: return f"cmp/ge R{m},R{n}"
    if (op & 0xF00F) == 0x3006: return f"cmp/hi R{m},R{n}"
    if (op & 0xF00F) == 0x3007: return f"cmp/gt R{m},R{n}"
    if (op & 0xF0FF) == 0x4015: return f"cmp/pl R{n}"
    if (op & 0xF0FF) == 0x4011: return f"cmp/pz R{n}"
    if (op & 0xFF00) == 0x8800: return f"cmp/eq #{(imm8 if imm8<128 else imm8-256)},R0"
    if (op & 0xF00F) == 0x4000: return f"shll R{n}"
    if (op & 0xF00F) == 0x4001: return f"shlr R{n}"
    if (op & 0xF00F) == 0x4020: return f"shal R{n}"
    if (op & 0xF00F) == 0x4021: return f"shar R{n}"
    if (op & 0xF0FF) == 0x4008: return f"shll2 R{n}"
    if (op & 0xF0FF) == 0x4018: return f"shll8 R{n}"
    if (op & 0xF0FF) == 0x4028: return f"shll16 R{n}"
    if (op & 0xF0FF) == 0x4009: return f"shlr2 R{n}"
    if (op & 0xF0FF) == 0x4019: return f"shlr8 R{n}"
    if (op & 0xF0FF) == 0x4029: return f"shlr16 R{n}"
    if (op & 0xF00F) == 0x400C: return f"shad R{m},R{n}"
    if (op & 0xF00F) == 0x400D: return f"shld R{m},R{n}"
    if (op & 0xF0FF) == 0x402B: return f"jmp @R{n}"
    if (op & 0xF0FF) == 0x400B: return f"jsr @R{n}"
    if (op & 0xF0FF) == 0x4010: return f"dt R{n}"
    if (op & 0xF0FF) == 0x002A: return f"sts PR,R{n}"
    if (op & 0xF0FF) == 0x000A: return f"sts MACH,R{n}"
    if (op & 0xF0FF) == 0x001A: return f"sts MACL,R{n}"
    if (op & 0xF0FF) == 0x0029: return f"movt R{n}"
    if (op & 0xF0FF) == 0x4022: return f"sts.l PR,@-R{n}"
    if (op & 0xF0FF) == 0x4026: return f"lds.l @R{n}+,PR"
    if (op & 0xF0FF) == 0x406A: return f"lds R{n},FPSCR"
    if (op & 0xF0FF) == 0x4062: return f"sts.l FPSCR,@-R{n}"
    if (op & 0xF0FF) == 0x405A: return f"lds R{n},FPUL"
    if (op & 0xF0FF) == 0x4052: return f"sts.l FPUL,@-R{n}"
    if (op & 0xF0FF) == 0x405E: return f"lds.l @R{n}+,FPUL"
    if (op & 0xF0FF) == 0x406E: return f"lds.l @R{n}+,FPSCR"
    if (op & 0xF0FF) == 0x0029: return f"movt R{n}"
    if (op & 0xF00F) == 0x4006: return f"lds R{m},FPSCR"

    # mov.l @(disp,PC),Rn
    if (op & 0xF000) == 0xD000:
        disp = (op & 0xFF) * 4
        pc4  = (addr + 4) & ~3
        tgt  = pc4 + disp
        val  = ru32(tgt)
        return f"mov.l @(0x{disp:02X},PC),R{n}  ; @0x{tgt:05X}=0x{val:08X}"

    # mov.w @(disp,PC),Rn
    if (op & 0xF000) == 0x9000:
        disp = (op & 0xFF) * 2
        tgt  = addr + 4 + disp
        val  = ru16(tgt)
        sval = rs16(tgt)
        return f"mov.w @(0x{disp:02X},PC),R{n}  ; @0x{tgt:05X}=0x{val:04X}={sval}"

    # mova @(disp,PC),R0
    if (op & 0xFF00) == 0xC700:
        disp = (op & 0xFF) * 4
        pc4  = (addr + 4) & ~3
        tgt  = pc4 + disp
        return f"mova @(0x{disp:02X},PC),R0  ; =0x{tgt:05X}"

    # bf/bt/bra/bsr with signed displacement
    if (op & 0xFF00) == 0x8900:
        d = op & 0xFF; d = d if d < 128 else d - 256
        tgt = addr + 4 + d*2
        return f"bt 0x{tgt:05X}"
    if (op & 0xFF00) == 0x8B00:
        d = op & 0xFF; d = d if d < 128 else d - 256
        tgt = addr + 4 + d*2
        return f"bf 0x{tgt:05X}"
    if (op & 0xFF00) == 0x8F00:
        d = op & 0xFF; d = d if d < 128 else d - 256
        tgt = addr + 4 + d*2
        return f"bf/s 0x{tgt:05X}"
    if (op & 0xFF00) == 0x8D00:
        d = op & 0xFF; d = d if d < 128 else d - 256
        tgt = addr + 4 + d*2
        return f"bt/s 0x{tgt:05X}"
    if (op & 0xF000) == 0xA000:
        d = op & 0xFFF; d = d if d < 2048 else d - 4096
        tgt = addr + 4 + d*2
        return f"bra 0x{tgt:05X}"
    if (op & 0xF000) == 0xB000:
        d = op & 0xFFF; d = d if d < 2048 else d - 4096
        tgt = addr + 4 + d*2
        return f"bsr 0x{tgt:05X}"

    # mov.l @(disp,Rn)
    if (op & 0xF000) == 0x5000:
        disp = (op & 0xF) * 4
        return f"mov.l @(0x{disp:02X},R{m}),R{n}"
    # mov.w @(disp,Rn)  -- 8400
    if (op & 0xFF00) == 0x8400:
        disp = (op & 0xF) * 2
        rn = (op >> 4) & 0xF
        return f"mov.w @(0x{disp:02X},R{rn}),R0"
    # mov.b @(disp,Rn) -- 8000
    if (op & 0xFF00) == 0x8000:
        disp = (op & 0xF)
        rn = (op >> 4) & 0xF
        return f"mov.b R0,@(0x{disp:02X},R{rn})"
    # mov.w R0,@(disp,Rn) -- 8100
    if (op & 0xFF00) == 0x8100:
        disp = (op & 0xF) * 2
        rn = (op >> 4) & 0xF
        return f"mov.w R0,@(0x{disp:02X},R{rn})"
    # mov.l @(disp,Rn) store -- 1xxx
    if (op & 0xF000) == 0x1000:
        disp = (op & 0xF) * 4
        return f"mov.l R{m},@(0x{disp:02X},R{n})"

    # FPU instructions
    if (op & 0xF00F) == 0xF00D: return f"fsts FPUL,FR{n}"
    if (op & 0xF00F) == 0xF00C: return f"fmov FR{m},FR{n}"  # actually fmov
    if (op & 0xF00F) == 0xF001: return f"fmul FR{m},FR{n}"
    if (op & 0xF00F) == 0xF000: return f"fadd FR{m},FR{n}"
    if (op & 0xF00F) == 0xF001: return f"fmul FR{m},FR{n}"
    if (op & 0xF00F) == 0xF002: return f"fdiv FR{m},FR{n}"
    if (op & 0xF00F) == 0xF003: return f"fcmp/eq FR{m},FR{n}"
    if (op & 0xF00F) == 0xF004: return f"fcmp/gt FR{m},FR{n}"  # actually fcmp/lt
    if (op & 0xF00F) == 0xF005: return f"fmov.s @(R0,R{m}),FR{n}"
    if (op & 0xF00F) == 0xF006: return f"fmov.s @R{m},FR{n}"
    if (op & 0xF00F) == 0xF007: return f"fmov.s FR{m},@(R0,R{n})"
    if (op & 0xF00F) == 0xF008: return f"fmov.s @R{m}+,FR{n}"
    if (op & 0xF00F) == 0xF00A: return f"fmov.s FR{m},@R{n}"
    if (op & 0xF00F) == 0xF00B: return f"fmov.s FR{m},@-R{n}"
    if (op & 0xF0FF) == 0xF08D: return f"fldi0 FR{n}"
    if (op & 0xF0FF) == 0xF09D: return f"fldi1 FR{n}"
    if (op & 0xF0FF) == 0xF02D: return f"float FPUL,FR{n}"
    if (op & 0xF0FF) == 0xF03D: return f"ftrc FR{n},FPUL"
    if (op & 0xF0FF) == 0xF04D: return f"fneg FR{n}"
    if (op & 0xF0FF) == 0xF05D: return f"fabs FR{n}"
    if (op & 0xF0FF) == 0xF06D: return f"fsqrt FR{n}"
    if (op & 0xF0FF) == 0xF07D: return f"fsub FR{n},?"  # placeholder
    if (op & 0xF00F) == 0xF009: return f"fmov.s @(R0,R{m}),FR{n}"  # dup check
    if (op & 0xF00F) == 0xF00E: return f"fmac FR0,FR{m},FR{n}"

    # fmov aliases and sub
    if hi4 == 0xF:
        sub4 = op & 0xF
        if sub4 == 0x8: return f"fmov.s @R{m}+,FR{n}"
        if sub4 == 0xC: return f"fmov FR{m},FR{n}"
        if sub4 == 0xE: return f"fmac FR0,FR{m},FR{n}"

    # fsub
    if (op & 0xF00F) == 0xF001: return f"fmul FR{m},FR{n}"

    return f"?? 0x{op:04X}"

def disasm_range(start, end, label=""):
    if label:
        print(f"\n{'='*60}")
        print(f"sub_{start:05X}  {label}")
        print(f"{'='*60}")
    addr = start
    while addr < end:
        op = ru16(addr)
        ins = disasm_one(addr)
        print(f"  {addr:05X}: {op:04X}  {ins}")
        if ins in ("rts",) or ins.startswith("jmp"):
            # print delay slot too
            ds = disasm_one(addr+2)
            print(f"  {addr+2:05X}: {ru16(addr+2):04X}  {ds}  [delay slot]")
            break
        addr += 2

# ============================================================
# First: disassemble sub_BEACC - the type=0x00 interpolation handler
# This is dispatched from BE830's jump table when interp_type=0x00
# ============================================================
print("Disassembling sub_BEACC (linear interpolation, type=0x00)")
print("Called from BE830 after sub_BECA8 has done axis search.")
print("On entry:")
print("  R4  = descriptor pointer (e.g. 0xAD090)")
print("  R0  = integer index (from axis search) -- but may have been moved to another reg")
print("  FR0 = fractional interpolation position (0.0..1.0)")
print("  FR1 = may still have fractional from BECA8")
print()
disasm_range(0xBEACC, 0xBEACC + 0x60, "interp_type=0x00 linear interpolation")

# ============================================================
# Also disassemble BECA8 - the axis search function
# ============================================================
print()
print("Disassembling sub_BECA8 (axis search)")
print("On entry: R0=count, R1=axis_ptr, FR0=input_value")
print("Returns: R0=index, FR1=fractional position")
print()
disasm_range(0xBECA8, 0xBECA8 + 0x60, "axis search sub_BECA8")

# ============================================================
# Check BE830 main dispatch more carefully
# ============================================================
print()
print("Disassembling BE830 main body more carefully")
disasm_range(0xBE830, 0xBE830 + 0x60)

# ============================================================
# Read raw bytes at BEACC for manual analysis
# ============================================================
print()
print("="*60)
print("Raw hex dump at 0xBEACC:")
for i in range(0, 0x60, 2):
    a = 0xBEACC + i
    op = ru16(a)
    print(f"  {a:05X}: {op:04X}")
