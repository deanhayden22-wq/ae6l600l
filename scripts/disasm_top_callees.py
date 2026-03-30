#!/usr/bin/env python3
"""
Disassemble the top unlabeled call targets to classify them.
Outputs SH-2A disassembly for each function's first N instructions.
"""
import os
import struct
import sys

ROM_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rom")

def load_rom():
    p = os.path.join(ROM_DIR, "ae5l600l.bin")
    if os.path.isfile(p):
        with open(p, "rb") as f:
            return f.read()
    for fn in sorted(os.listdir(ROM_DIR)):
        if fn.lower().endswith(".bin"):
            with open(os.path.join(ROM_DIR, fn), "rb") as f:
                return f.read()
    sys.exit("No ROM found")

def sign_extend_8(v):
    return v - 0x100 if v & 0x80 else v

def sign_extend_12(v):
    return v - 0x1000 if v & 0x800 else v

def disasm_one(w, pc, rom):
    """Disassemble a single SH-2 16-bit instruction. Returns mnemonic string."""
    hi = (w >> 12) & 0xF
    rn = (w >> 8) & 0xF
    rm = (w >> 4) & 0xF
    lo = w & 0xF

    # Common patterns
    if w == 0x0009: return "nop"
    if w == 0x000B: return "rts"
    if w == 0x4F22: return "sts.l  pr, @-r15"
    if w == 0x4F26: return "lds.l  @r15+, pr"
    if w == 0x0023: return "braf   r0"
    if w == 0x402B: return "jmp    @r0"

    if hi == 0xA:
        disp = sign_extend_12(w & 0xFFF)
        target = (pc + 4) + (disp << 1)
        return f"bra    0x{target:05X}"
    if hi == 0xB:
        disp = sign_extend_12(w & 0xFFF)
        target = (pc + 4) + (disp << 1)
        return f"bsr    0x{target:05X}"

    if hi == 0x8:
        if rm == 0x9:  # BT
            disp = sign_extend_8(w & 0xFF)
            target = (pc + 4) + (disp << 1)
            return f"bt     0x{target:05X}"
        if rm == 0xB:  # BF
            disp = sign_extend_8(w & 0xFF)
            target = (pc + 4) + (disp << 1)
            return f"bf     0x{target:05X}"
        if rm == 0xD:  # BT/S
            disp = sign_extend_8(w & 0xFF)
            target = (pc + 4) + (disp << 1)
            return f"bt/s   0x{target:05X}"
        if rm == 0xF:  # BF/S
            disp = sign_extend_8(w & 0xFF)
            target = (pc + 4) + (disp << 1)
            return f"bf/s   0x{target:05X}"

    if hi == 0xD:
        disp = w & 0xFF
        lit_addr = (pc & ~3) + 4 + disp * 4
        if lit_addr + 4 <= len(rom):
            val = struct.unpack_from(">I", rom, lit_addr)[0]
            return f"mov.l  @(0x{lit_addr:05X}), r{rn}  ; =0x{val:08X}"
        return f"mov.l  @({disp},pc), r{rn}"

    if hi == 0xC:
        if rn == 0x7:  # MOVA
            disp = w & 0xFF
            lit_addr = (pc & ~3) + 4 + disp * 4
            return f"mova   @(0x{lit_addr:05X}), r0  ; disp={disp}"
        if rn == 0x1:  # MOV.W @(disp,GBR),R0
            disp = w & 0xFF
            return f"mov.w  @(0x{disp*2:X},gbr), r0"
        if rn == 0x2:  # MOV.L @(disp,GBR),R0
            disp = w & 0xFF
            return f"mov.l  @(0x{disp*4:X},gbr), r0"
        if rn == 0x5:  # MOV.W R0,@(disp,GBR)
            disp = w & 0xFF
            return f"mov.w  r0, @(0x{disp*2:X},gbr)"
        if rn == 0x6:  # MOV.L R0,@(disp,GBR)
            disp = w & 0xFF
            return f"mov.l  r0, @(0x{disp*4:X},gbr)"
        if rn == 0x0:  # MOV.B R0,@(disp,GBR)
            disp = w & 0xFF
            return f"mov.b  r0, @(0x{disp:X},gbr)"

    if hi == 0x9:
        disp = w & 0xFF
        lit_addr = pc + 4 + disp * 2
        if lit_addr + 2 <= len(rom):
            val = struct.unpack_from(">H", rom, lit_addr)[0]
            return f"mov.w  @(0x{lit_addr:05X}), r{rn}  ; =0x{val:04X}"
        return f"mov.w  @({disp},pc), r{rn}"

    if hi == 0xE:
        imm = sign_extend_8(w & 0xFF)
        return f"mov    #{imm}, r{rn}"

    if hi == 0x7:
        imm = sign_extend_8(w & 0xFF)
        return f"add    #{imm}, r{rn}"

    # mov.l Rm, @(disp,Rn): 0001nnnnmmmmddd
    if hi == 0x1:
        disp = lo
        return f"mov.l  r{rm}, @(0x{disp*4:X},r{rn})"

    # mov.l @(disp,Rm), Rn: 0101nnnnmmmmdddd
    if hi == 0x5:
        disp = lo
        return f"mov.l  @(0x{disp*4:X},r{rm}), r{rn}"

    # 0100 patterns
    if hi == 0x4:
        if (w & 0xF0FF) == 0x400B:
            return f"jsr    @r{rn}"
        if (w & 0xF0FF) == 0x404B:
            return f"jsr/n  @r{rn}"
        if (w & 0xF0FF) == 0x401E:
            return f"ldc    r{rn}, gbr"
        if (w & 0xF0FF) == 0x4022:
            return f"sts.l  pr, @-r{rn}"
        if (w & 0xF0FF) == 0x4026:
            return f"lds.l  @r{rn}+, pr"
        if (w & 0xF0FF) == 0x4052:
            return f"sts.l  fpul, @-r{rn}"
        if (w & 0xF0FF) == 0x4056:
            return f"lds.l  @r{rn}+, fpul"
        if (w & 0xFF) == 0x15:
            return f"cmp/pl r{rn}"
        if (w & 0xFF) == 0x11:
            return f"cmp/pz r{rn}"

    # 0110 patterns
    if hi == 0x6:
        if lo == 0x3:
            return f"mov    r{rm}, r{rn}"
        if lo == 0x2:
            return f"mov.l  @r{rm}, r{rn}"
        if lo == 0x6:
            return f"mov.l  @r{rm}+, r{rn}"
        if lo == 0x1:
            return f"mov.w  @r{rm}, r{rn}"
        if lo == 0x0:
            return f"mov.b  @r{rm}, r{rn}"
        if lo == 0xA:
            return f"negc   r{rm}, r{rn}"
        if lo == 0xB:
            return f"neg    r{rm}, r{rn}"
        if lo == 0x9:
            return f"swap.w r{rm}, r{rn}"
        if lo == 0x8:
            return f"swap.b r{rm}, r{rn}"

    # 0010 patterns (stores)
    if hi == 0x2:
        if lo == 0x2:
            return f"mov.l  r{rm}, @r{rn}"
        if lo == 0x6:
            return f"mov.l  r{rm}, @-r{rn}"
        if lo == 0x1:
            return f"mov.w  r{rm}, @r{rn}"
        if lo == 0x0:
            return f"mov.b  r{rm}, @r{rn}"

    # 0011 patterns (cmp, add, sub)
    if hi == 0x3:
        if lo == 0x0:
            return f"cmp/eq r{rm}, r{rn}"
        if lo == 0x2:
            return f"cmp/hs r{rm}, r{rn}"
        if lo == 0x3:
            return f"cmp/ge r{rm}, r{rn}"
        if lo == 0x6:
            return f"cmp/hi r{rm}, r{rn}"
        if lo == 0x7:
            return f"cmp/gt r{rm}, r{rn}"
        if lo == 0xC:
            return f"add    r{rm}, r{rn}"
        if lo == 0x8:
            return f"sub    r{rm}, r{rn}"

    # 0000 misc
    if hi == 0x0:
        if lo == 0x7 and rm == 0:
            return f"mul.l  r0, r{rn}"
        if (w & 0xF0FF) == 0x0002:
            return f"stc    sr, r{rn}"
        if (w & 0xF0FF) == 0x0012:
            return f"stc    gbr, r{rn}"
        if (w & 0xF0FF) == 0x001A:
            return f"sts    macl, r{rn}"
        if (w & 0xF0FF) == 0x000A:
            return f"sts    mach, r{rn}"
        if (w & 0xF0FF) == 0x002A:
            return f"sts    pr, r{rn}"
        if lo == 0xC:
            return f"mov.b  @(r0,r{rm}), r{rn}"
        if lo == 0xD:
            return f"mov.w  @(r0,r{rm}), r{rn}"
        if lo == 0xE:
            return f"mov.l  @(r0,r{rm}), r{rn}"

    # FPU: 1111xxxx
    if hi == 0xF:
        if lo == 0x0:
            return f"fadd   fr{rm}, fr{rn}"
        if lo == 0x1:
            return f"fsub   fr{rm}, fr{rn}"
        if lo == 0x2:
            return f"fmul   fr{rm}, fr{rn}"
        if lo == 0x3:
            return f"fdiv   fr{rm}, fr{rn}"
        if lo == 0x4:
            return f"fcmp/eq fr{rm}, fr{rn}"
        if lo == 0x5:
            return f"fcmp/gt fr{rm}, fr{rn}"
        if lo == 0x6:
            return f"fmov.s @(r0,r{rm}), fr{rn}"
        if lo == 0x7:
            return f"fmov.s fr{rm}, @(r0,r{rn})"
        if lo == 0x8:
            return f"fmov.s @r{rm}, fr{rn}"
        if lo == 0x9:
            return f"fmov.s @r{rm}+, fr{rn}"
        if lo == 0xA:
            return f"fmov.s fr{rm}, @r{rn}"
        if lo == 0xB:
            return f"fmov.s fr{rm}, @-r{rn}"
        if lo == 0xC:
            return f"fmov   fr{rm}, fr{rn}"
        if lo == 0xE:
            return f"fmac   fr0, fr{rm}, fr{rn}"
        if (w & 0xF0FF) == 0xF01D:
            return f"flds   fr{rn}, fpul"
        if (w & 0xF0FF) == 0xF00D:
            return f"fsts   fpul, fr{rn}"
        if (w & 0xF0FF) == 0xF02D:
            return f"float  fpul, fr{rn}"
        if (w & 0xF0FF) == 0xF03D:
            return f"ftrc   fr{rn}, fpul"
        if (w & 0xF0FF) == 0xF04D:
            return f"fneg   fr{rn}"
        if (w & 0xF0FF) == 0xF05D:
            return f"fabs   fr{rn}"

    return f".word  0x{w:04X}"

def disasm_func(rom, start, max_instrs=30):
    """Disassemble up to max_instrs instructions from start."""
    lines = []
    pc = start
    for _ in range(max_instrs):
        if pc + 2 > len(rom):
            break
        w = struct.unpack_from(">H", rom, pc)[0]
        mnem = disasm_one(w, pc, rom)
        lines.append(f"  0x{pc:05X}:  {w:04X}  {mnem}")
        pc += 2
        # Stop at RTS + delay slot
        if w == 0x000B and pc + 2 <= len(rom):
            w2 = struct.unpack_from(">H", rom, pc)[0]
            mnem2 = disasm_one(w2, pc, rom)
            lines.append(f"  0x{pc:05X}:  {w2:04X}  {mnem2}  ; (delay slot)")
            break
    return lines

# Top unlabeled targets to analyze
TARGETS = [
    (0x0BE554, 685, "?"),
    (0x0BE53C, 461, "?"),
    (0x0BDBCC, 309, "?"),
    (0x000317C, 298, "?"),
    (0x0BE82C, 236, "?"),
    (0x0BE81C, 235, "?"),
    (0x0BE56C, 218, "?"),
    (0x09EDEC, 186, "?"),
    (0x0003190, 181, "?"),
    (0x0BE5D8, 147, "?"),
    (0x0BE598, 145, "?"),
    (0x09ED90, 140, "?"),
    (0x0BDCB6, 120, "?"),
    (0x0002B8C, 118, "?"),
    (0x0BE5A8, 113, "?"),
    (0x0022F92, 111, "?"),
    (0x0582D2, 108, "?"),
    (0x0022CF4, 100, "?"),
    (0x0582AC, 100, "?"),
    (0x000E6E4, 73, "?"),
    (0x002F8EA, 65, "?"),
    (0x0584C8, 59, "?"),
    (0x0058318, 57, "?"),
    (0x0006B5A, 53, "?"),
    (0x0058404, 49, "?"),
    (0x09CFEE, 48, "?"),
    (0x000B9E0, 44, "?"),
    (0x0582E0, 43, "?"),
    (0x0584BE, 43, "?"),
    (0x004E0B8, 40, "?"),
    (0x000DCE4, 37, "?"),
    (0x0006BC4, 35, "?"),
    (0x003AB20, 35, "?"),
    (0x0006BF0, 31, "?"),
    (0x0BE588, 31, "?"),
    (0x00067A6, 26, "?"),
    (0x00717B2, 25, "?"),
    (0x000B99C, 22, "?"),
    (0x00067DC, 21, "?"),
    (0x005CC9A, 20, "?"),
]

def main():
    rom = load_rom()
    for addr, count, _ in TARGETS:
        print(f"\n{'='*80}")
        print(f"0x{addr:08X}  ({count} calls)")
        print(f"{'='*80}")
        lines = disasm_func(rom, addr, 30)
        for line in lines:
            print(line)

if __name__ == "__main__":
    main()
