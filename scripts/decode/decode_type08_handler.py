#!/usr/bin/env python3
"""
The descriptor at 0xAD090 has interp_type=0x08 (from desc+2).
The jump table entry at 0xBE860 + 0x08 gives the actual handler.
Disassemble that handler to understand how it reads the u16 table values.
"""
import struct
ROM_PATH = 'C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin'
with open(ROM_PATH, 'rb') as f:
    rom = f.read()

def ru16(a): return struct.unpack('>H', rom[a:a+2])[0]
def ru32(a): return struct.unpack('>I', rom[a:a+4])[0]
def rf32(a): return struct.unpack('>f', rom[a:a+4])[0]
def rs16(a): return struct.unpack('>h', rom[a:a+2])[0]

# BE840: mova @(0x1C,PC),R0 -> R0 = (BE844 & ~3) + 0x1C = 0xBE860
# Note: mova is (BE840+4)&~3 + disp = (BE844)&~3 + 0x1C = 0xBE844 + 0x1C = 0xBE860
jt_base = (0xBE840 + 4) & ~3  # = 0xBE844 since it's already aligned
jt_base_actual = ((0xBE840 + 4) & ~3) + 0x1C
print(f"Jump table base from mova: 0x{jt_base_actual:05X}")
print()

# Check the jump table entries:
print("Jump table entries at 0xBE860:")
for i in range(0, 0x20, 4):
    a = jt_base_actual + i
    v = ru32(a)
    print(f"  [{i:2d}/4={i//4}] @0x{a:05X}: 0x{v:08X}  (handler for interp_type={i})")
print()

# interp_type = 0x08 -> entry at offset 8
interp_type = 0x08
handler_ptr = ru32(jt_base_actual + interp_type)
print(f"Handler for interp_type=0x08: 0x{handler_ptr:08X}")
handler_addr = handler_ptr & 0x0FFFFFFF  # mask ROM address
print(f"  -> sub_{handler_addr:05X}")
print()

# Disassemble the handler
def disasm_range(start, length=0x40):
    addr = start
    end = start + length
    while addr < end:
        op = ru16(addr)
        n = (op>>8)&0xF
        m = (op>>4)&0xF
        sub = op&0xF
        hi = (op>>12)&0xF
        imm8 = op&0xFF

        # FPU
        if (op & 0xF00F) == 0xF005:
            s = f"fmov.s @(R0,R{n}),FR{m}"  # n=base, m=float dest
        elif (op & 0xF00F) == 0xF006:
            s = f"fmov.s @R{n},FR{m}"
        elif (op & 0xF00F) == 0xF004:
            s = f"fcmp/lt FR{m},FR{n}  [T=1 if FR{n}<FR{m}]"
        elif (op & 0xF00F) == 0xF003:
            s = f"fcmp/eq FR{m},FR{n}"
        elif (op & 0xF00F) == 0xF000:
            s = f"fadd FR{m},FR{n}"
        elif (op & 0xF00F) == 0xF001:
            s = f"fmul FR{m},FR{n}"
        elif (op & 0xF00F) == 0xF00C:
            s = f"fmov FR{m},FR{n}"
        elif (op & 0xF0FF) == 0xF02D:
            s = f"float FPUL,FR{n}"
        elif (op & 0xF0FF) == 0xF03D:
            s = f"ftrc FR{n},FPUL  [float->int]"
        elif (op & 0xF00F) == 0xF008:
            s = f"fmov.s @R{n}+,FR{m}  [FR{m}=f32@R{n}, R{n}+=4]"
        elif (op & 0xF00F) == 0xF002:
            s = f"fdiv FR{m},FR{n}"
        elif (op & 0xF0FF) == 0xF08D:
            s = f"fldi0 FR{n}"
        elif (op & 0xF0FF) == 0xF09D:
            s = f"fldi1 FR{n}"
        elif (op & 0xF0FF) == 0xF00D:
            s = f"fsts FPUL,FR{n}"
        elif (op & 0xF00F) == 0xF007:
            s = f"fmov.s FR{m},@(R0,R{n})"
        elif (op & 0xF00F) == 0xF00E:
            s = f"fmac FR0,FR{m},FR{n}"
        elif (op & 0xF00F) == 0xF00A:
            s = f"fmov.s FR{m},@R{n}"
        elif (op & 0xF00F) == 0xF00B:
            s = f"fmov.s FR{m},@-R{n}"
        # int
        elif op == 0x000B: s = "rts"
        elif op == 0x0009: s = "nop"
        elif (op & 0xFF00) == 0x7000:
            s = f"add #{(imm8 if imm8<128 else imm8-256)},R{n}"
        elif (op & 0xF00F) == 0x300C: s = f"add R{m},R{n}"
        elif (op & 0xF00F) == 0x3008: s = f"sub R{m},R{n}"
        elif (op & 0xF0FF) == 0x4008: s = f"shll2 R{n}"
        elif (op & 0xF0FF) == 0x4009: s = f"shlr2 R{n}"
        elif (op & 0xF0FF) == 0x4018: s = f"shll8 R{n}"
        elif (op & 0xF0FF) == 0x4028: s = f"shll16 R{n}"
        elif (op & 0xF0FF) == 0x4001: s = f"shlr R{n}"
        elif (op & 0xF0FF) == 0x4000: s = f"shll R{n}"
        elif (op & 0xF00F) == 0x6003: s = f"mov R{m},R{n}"
        elif (op & 0xFF00) == 0xE000:
            s = f"mov #{(imm8 if imm8<128 else imm8-256)},R{n}"
        elif (op & 0xF00F) == 0x600C: s = f"extu.b R{m},R{n}"
        elif (op & 0xF00F) == 0x600D: s = f"extu.w R{m},R{n}"
        elif (op & 0xF00F) == 0x600E: s = f"exts.b R{m},R{n}"
        elif (op & 0xF00F) == 0x600F: s = f"exts.w R{m},R{n}"
        elif (op & 0xF00F) == 0x6001: s = f"mov.w @R{m},R{n}  [sign-ext]"
        elif (op & 0xF00F) == 0x6000: s = f"mov.b @R{m},R{n}  [sign-ext]"
        elif (op & 0xF00F) == 0x6002: s = f"mov.l @R{m},R{n}"
        elif (op & 0xF0FF) == 0x4015: s = f"cmp/pl R{n}"
        elif (op & 0xF0FF) == 0x4011: s = f"cmp/pz R{n}"
        elif (op & 0xFF00) == 0x8900:
            d = imm8; d = d if d<128 else d-256; s = f"bt 0x{addr+4+d*2:05X}"
        elif (op & 0xFF00) == 0x8B00:
            d = imm8; d = d if d<128 else d-256; s = f"bf 0x{addr+4+d*2:05X}"
        elif (op & 0xFF00) == 0x8F00:
            d = imm8; d = d if d<128 else d-256; s = f"bf/s 0x{addr+4+d*2:05X}"
        elif (op & 0xFF00) == 0x8D00:
            d = imm8; d = d if d<128 else d-256; s = f"bt/s 0x{addr+4+d*2:05X}"
        elif (op & 0xF000) == 0xA000:
            d = op&0xFFF; d = d if d<2048 else d-4096; s = f"bra 0x{addr+4+d*2:05X}"
        elif (op & 0xF000) == 0xB000:
            d = op&0xFFF; d = d if d<2048 else d-4096; s = f"bsr 0x{addr+4+d*2:05X}"
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
        elif (op & 0xF0FF) == 0x4022: s = f"sts.l PR,@-R{n}"
        elif (op & 0xF0FF) == 0x402B: s = f"jmp @R{n}"
        elif (op & 0xF00F) == 0x400D: s = f"shld R{m},R{n}"
        elif (op & 0xF00F) == 0x2008: s = f"tst R{m},R{n}"
        elif (op & 0xF00F) == 0x2009: s = f"and R{m},R{n}"
        elif (op & 0xF000) == 0x5000:
            disp = (op&0xF)*4; s = f"mov.l @(0x{disp:02X},R{m}),R{n}"
        elif (op & 0xF000) == 0x1000:
            disp = (op&0xF)*4; s = f"mov.l R{m},@(0x{disp:02X},R{n})"
        elif (op & 0xFF00) == 0x8400:
            disp = (op&0xF); rn = (op>>4)&0xF; s = f"mov.b @(0x{disp:02X},R{rn}),R0"
        elif (op & 0xFF00) == 0x8500:
            disp = (op&0xF)*2; rn = (op>>4)&0xF; s = f"mov.w @(0x{disp:02X},R{rn}),R0"
        elif (op & 0xF000) == 0xD000:
            disp = (op & 0xFF) * 4
            pc4 = (addr + 4) & ~3
            tgt = pc4 + disp
            val = ru32(tgt)
            s = f"mov.l @(0x{disp:02X},PC),R{n}  ; @0x{tgt:05X}=0x{val:08X}"
        elif (op & 0xF000) == 0x9000:
            disp = (op & 0xFF) * 2
            tgt = addr + 4 + disp
            val = ru16(tgt)
            sval = rs16(tgt)
            s = f"mov.w @(0x{disp:02X},PC),R{n}  ; @0x{tgt:05X}=0x{val:04X}={sval}"
        elif (op & 0xFF00) == 0xC700:
            disp = (op & 0xFF) * 4
            pc4 = (addr + 4) & ~3
            tgt = pc4 + disp
            s = f"mova @(0x{disp:02X},PC),R0  ; =0x{tgt:05X}"
        else: s = f"?? 0x{op:04X}"

        print(f"  {addr:05X}: {op:04X}  {s}")
        if op == 0x000B:  # rts
            addr += 2
            op2 = ru16(addr)
            s2 = "??"
            print(f"  {addr:05X}: {op2:04X}  [delay slot]")
            break
        addr += 2

print(f"Disassembling handler at 0x{handler_addr:05X}:")
disasm_range(handler_addr, 0x50)

print()
# Also check scale usage in BE830:
# After BEACC/handler returns FR2 = interpolated value:
# BE84A: 2338 ??
# BE84C: 8D04 bt/s
# BE84E: F12C fmov FR2,FR1
# BE850: 740C ?? -- or is this add #12,R4?
# etc.
print("="*60)
print("BE830 post-handler section (after jsr @R2):")
print("="*60)
for a in range(0xBE84A, 0xBE860, 2):
    op = ru16(a)
    n = (op>>8)&0xF
    m = (op>>4)&0xF
    hi = (op>>12)&0xF
    imm8 = op&0xFF

    if (op & 0xF00F) == 0xF00C:
        s = f"fmov FR{m},FR{n}"
    elif (op & 0xF00F) == 0xF000:
        s = f"fadd FR{m},FR{n}"
    elif (op & 0xF00F) == 0xF001:
        s = f"fmul FR{m},FR{n}"
    elif (op & 0xF00F) == 0xF005:
        s = f"fmov.s @(R0,R{n}),FR{m}"
    elif (op & 0xF00F) == 0xF008:
        s = f"fmov.s @R{n}+,FR{m}"
    elif (op & 0xF00F) == 0xF00E:
        s = f"fmac FR0,FR{m},FR{n}"
    elif (op & 0xF0FF) == 0xF02D:
        s = f"float FPUL,FR{n}"
    elif (op & 0xF0FF) == 0xF00D:
        s = f"fsts FPUL,FR{n}"
    elif op == 0x000B: s = "rts"
    elif op == 0x0009: s = "nop"
    elif (op & 0xFF00) == 0x7000:
        s = f"add #{(imm8 if imm8<128 else imm8-256)},R{n}"
    elif (op & 0xF00F) == 0x6003: s = f"mov R{m},R{n}"
    elif (op & 0xFF00) == 0xE000:
        s = f"mov #{(imm8 if imm8<128 else imm8-256)},R{n}"
    elif (op & 0xF0FF) == 0x4026: s = f"lds.l @R{n}+,PR"
    elif (op & 0xF0FF) == 0x405A: s = f"lds R{n},FPUL"
    elif (op & 0xFF00) == 0x8D00:
        d = imm8; d = d if d<128 else d-256; s = f"bt/s 0x{a+4+d*2:05X}"
    elif (op & 0xFF00) == 0x8B00:
        d = imm8; d = d if d<128 else d-256; s = f"bf 0x{a+4+d*2:05X}"
    elif (op & 0xFF00) == 0x8900:
        d = imm8; d = d if d<128 else d-256; s = f"bt 0x{a+4+d*2:05X}"
    elif (op & 0xF000) == 0x5000:
        disp = (op&0xF)*4; s = f"mov.l @(0x{disp:02X},R{m}),R{n}"
    elif (op & 0xF00F) == 0xF004:
        s = f"fcmp/lt FR{m},FR{n}"
    elif (op & 0xF0FF) == 0x4008: s = f"shll2 R{n}"
    elif (op & 0xFF00) == 0x8400:
        disp = (op&0xF); rn = (op>>4)&0xF; s = f"mov.b @(0x{disp:02X},R{rn}),R0"
    elif (op & 0xFF00) == 0x8500:
        disp = (op&0xF)*2; rn = (op>>4)&0xF; s = f"mov.w @(0x{disp:02X},R{rn}),R0"
    else: s = f"?? 0x{op:04X}"
    print(f"  {a:05X}: {op:04X}  {s}")

print()
print("="*60)
print("SCALE from descriptor:")
scale = rf32(0xAD090 + 12)
print(f"  @0xAD09C = 0x{ru32(0xAD09C):08X} -> f32 = {scale:.8f}")
print(f"  = 1/{1.0/scale:.0f}")
print()
print("Interpretation: The handler (type=0x08) likely:")
print("  1. Reads u16 values from val_ptr (0xCE5A4)")
print("  2. Loads them into FPUL via 'lds Rn,FPUL'")
print("  3. Converts to float via 'float FPUL,FRn'")
print("  4. Multiplies by scale (1/32768) to get the normalized value")
print()
print("U16 values (100, 50, 37) * scale (1/32768) =")
for v in [100, 50, 37, 0]:
    result = v * scale
    print(f"  {v} * (1/32768) = {result:.8f}")
print()
print("These are tiny fractions, not useful as decay deltas in engineering units.")
print()
print("ALTERNATIVE: scale is applied differently (e.g. val/scale, not val*scale)")
scale_alt = 1.0 / scale  # = 32768
for v in [100, 50, 37, 0]:
    print(f"  {v} / (1/32768) = {v * scale_alt:.2f}")

print()
print("="*60)
print("What do the u16 values mean without scaling?")
print("100, 100, 100, 100, 100, 50, 50, 37, 37")
print()
print("If they represent percent: 100%=full decay, 50%=half, 37%=37%")
print("If they represent time constant in ms: 100ms=0.1s decay")
print("If they're raw integers used as float: 100.0, 50.0, 37.0 (cast not convert)")
print()
print("The scale 0x38000000 = 3.05176e-05 = 1/32768 = 2^-15")
print("100 * 2^-15 = 0.00305176")
print("This could be a normalized fraction (0..1 range for 0..32768)")
