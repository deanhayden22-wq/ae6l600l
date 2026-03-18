#!/usr/bin/env python3
"""
Minimal SH-2A disassembler for tracing knock/FLKC functions.
Decodes 16-bit SH instructions (big-endian) with GBR-relative addressing annotation.
"""
import struct
import sys

def sign_extend_8(val):
    if val & 0x80: return val - 0x100
    return val

def sign_extend_12(val):
    if val & 0x800: return val - 0x1000
    return val

def decode_insn(code, pc, rom):
    """Decode a single 16-bit SH-2 instruction. Returns (mnemonic, length)."""
    n = (code >> 8) & 0xF
    m = (code >> 4) & 0xF
    d = code & 0xF
    i = code & 0xFF

    top4 = (code >> 12) & 0xF

    # Format: 0000nnnnmmmm0011 - MOV.L @(R0,Rm),Rn  (some are special)

    if code == 0x0009: return "nop", 2
    if code == 0x000B: return "rts", 2
    if code == 0x002B: return "rte", 2
    if code == 0x0019: return "div0u", 2
    if code == 0x0048: return "clrs", 2
    if code == 0x0058: return "sets", 2
    if code == 0x0008: return "clrt", 2
    if code == 0x0018: return "sett", 2
    if code == 0x0038: return "ldtlb", 2
    if code == 0x004B: return "rte (sleep?)", 2
    if code == 0x001B: return "sleep", 2

    if top4 == 0x0:
        mid = code & 0x00FF
        if (code & 0xF00F) == 0x0002: return f"stc    SR,r{n}", 2
        if (code & 0xF00F) == 0x0003: return f"bsrf   r{n}", 2
        if (code & 0xF0FF) == 0x0012: return f"stc    GBR,r{n}", 2
        if (code & 0xF0FF) == 0x0022: return f"stc    VBR,r{n}", 2
        if (code & 0xF00F) == 0x0004: return f"mov.b  r{m},@(r0,r{n})", 2
        if (code & 0xF00F) == 0x0005: return f"mov.w  r{m},@(r0,r{n})", 2
        if (code & 0xF00F) == 0x0006: return f"mov.l  r{m},@(r0,r{n})", 2
        if (code & 0xF00F) == 0x0007: return f"mul.l  r{m},r{n}", 2
        if (code & 0xF00F) == 0x000C: return f"mov.b  @(r0,r{m}),r{n}", 2
        if (code & 0xF00F) == 0x000D: return f"mov.w  @(r0,r{m}),r{n}", 2
        if (code & 0xF00F) == 0x000E: return f"mov.l  @(r0,r{m}),r{n}", 2
        if (code & 0xF0FF) == 0x000A: return f"sts    MACH,r{n}", 2
        if (code & 0xF0FF) == 0x001A: return f"sts    MACL,r{n}", 2
        if (code & 0xF0FF) == 0x002A: return f"sts    PR,r{n}", 2
        if (code & 0xF0FF) == 0x005A: return f"sts    FPUL,r{n}", 2
        if (code & 0xF0FF) == 0x006A: return f"sts    FPSCR,r{n}", 2
        if (code & 0xF00F) == 0x000F: return f"mac.l  @r{m}+,@r{n}+", 2
        if (code & 0xF0FF) == 0x0023: return f"braf   r{n}", 2
        if (code & 0xF0FF) == 0x0029: return f"movt   r{n}", 2
        if (code & 0xF0FF) == 0x0083: return f"pref   @r{n}", 2
        return f".word  0x{code:04X}  ; unknown 0x0nnn", 2

    if top4 == 0x1:  # mov.l Rm,@(disp,Rn)
        return f"mov.l  r{m},@({d*4},r{n})", 2

    if top4 == 0x2:
        op = code & 0xF
        if op == 0x0: return f"mov.b  r{m},@r{n}", 2
        if op == 0x1: return f"mov.w  r{m},@r{n}", 2
        if op == 0x2: return f"mov.l  r{m},@r{n}", 2
        if op == 0x4: return f"mov.b  r{m},@-r{n}", 2
        if op == 0x5: return f"mov.w  r{m},@-r{n}", 2
        if op == 0x6: return f"mov.l  r{m},@-r{n}", 2
        if op == 0x7: return f"div0s  r{m},r{n}", 2
        if op == 0x8: return f"tst    r{m},r{n}", 2
        if op == 0x9: return f"and    r{m},r{n}", 2
        if op == 0xA: return f"xor    r{m},r{n}", 2
        if op == 0xB: return f"or     r{m},r{n}", 2
        if op == 0xC: return f"cmp/str r{m},r{n}", 2
        if op == 0xD: return f"xtrct  r{m},r{n}", 2
        if op == 0xE: return f"mulu.w r{m},r{n}", 2
        if op == 0xF: return f"muls.w r{m},r{n}", 2
        return f".word  0x{code:04X}  ; unknown 0x2nmd", 2

    if top4 == 0x3:
        op = code & 0xF
        if op == 0x0: return f"cmp/eq r{m},r{n}", 2
        if op == 0x2: return f"cmp/hs r{m},r{n}", 2
        if op == 0x3: return f"cmp/ge r{m},r{n}", 2
        if op == 0x4: return f"div1   r{m},r{n}", 2
        if op == 0x5: return f"dmulu.l r{m},r{n}", 2
        if op == 0x6: return f"cmp/hi r{m},r{n}", 2
        if op == 0x7: return f"cmp/gt r{m},r{n}", 2
        if op == 0x8: return f"sub    r{m},r{n}", 2
        if op == 0xA: return f"subc   r{m},r{n}", 2
        if op == 0xB: return f"subv   r{m},r{n}", 2
        if op == 0xC: return f"add    r{m},r{n}", 2
        if op == 0xD: return f"dmuls.l r{m},r{n}", 2
        if op == 0xE: return f"addc   r{m},r{n}", 2
        if op == 0xF: return f"addv   r{m},r{n}", 2
        return f".word  0x{code:04X}  ; unknown 0x3nm_", 2

    if top4 == 0x4:
        lo = code & 0xFF
        lo4 = code & 0xF
        mid8 = code & 0xFF
        if mid8 == 0x00: return f"shll   r{n}", 2
        if mid8 == 0x01: return f"shlr   r{n}", 2
        if mid8 == 0x02: return f"sts.l  MACH,@-r{n}", 2
        if mid8 == 0x04: return f"rotl   r{n}", 2
        if mid8 == 0x05: return f"rotr   r{n}", 2
        if mid8 == 0x06: return f"lds.l  @r{n}+,MACH", 2
        if mid8 == 0x08: return f"shll2  r{n}", 2
        if mid8 == 0x09: return f"shlr2  r{n}", 2
        if mid8 == 0x0A: return f"lds    r{n},MACH", 2
        if mid8 == 0x0B: return f"jsr    @r{n}", 2
        if mid8 == 0x10: return f"dt     r{n}", 2
        if mid8 == 0x11: return f"cmp/pz r{n}", 2
        if mid8 == 0x12: return f"sts.l  MACL,@-r{n}", 2
        if mid8 == 0x15: return f"cmp/pl r{n}", 2
        if mid8 == 0x16: return f"lds.l  @r{n}+,MACL", 2
        if mid8 == 0x18: return f"shll8  r{n}", 2
        if mid8 == 0x19: return f"shlr8  r{n}", 2
        if mid8 == 0x1A: return f"lds    r{n},MACL", 2
        if mid8 == 0x1B: return f"tas.b  @r{n}", 2
        if mid8 == 0x20: return f"shal   r{n}", 2
        if mid8 == 0x21: return f"shar   r{n}", 2
        if mid8 == 0x22: return f"sts.l  PR,@-r{n}", 2
        if mid8 == 0x24: return f"rotcl  r{n}", 2
        if mid8 == 0x25: return f"rotcr  r{n}", 2
        if mid8 == 0x26: return f"lds.l  @r{n}+,PR", 2
        if mid8 == 0x28: return f"shll16 r{n}", 2
        if mid8 == 0x29: return f"shlr16 r{n}", 2
        if mid8 == 0x2A: return f"lds    r{n},PR", 2
        if mid8 == 0x2B: return f"jmp    @r{n}", 2
        if mid8 == 0x52: return f"sts.l  FPUL,@-r{n}", 2
        if mid8 == 0x56: return f"lds.l  @r{n}+,FPUL", 2
        if mid8 == 0x5A: return f"lds    r{n},FPUL", 2
        if mid8 == 0x62: return f"sts.l  FPSCR,@-r{n}", 2
        if mid8 == 0x66: return f"lds.l  @r{n}+,FPSCR", 2
        if mid8 == 0x6A: return f"lds    r{n},FPSCR", 2
        if lo4 == 0xF: return f"mac.w  @r{m}+,@r{n}+", 2
        if lo4 == 0xC: return f"shad   r{m},r{n}", 2
        if lo4 == 0xD: return f"shld   r{m},r{n}", 2
        # LDC variants
        if mid8 == 0x0E: return f"ldc    r{n},SR", 2
        if mid8 == 0x1E: return f"ldc    r{n},GBR", 2
        if mid8 == 0x2E: return f"ldc    r{n},VBR", 2
        if mid8 == 0x07: return f"ldc.l  @r{n}+,SR", 2
        if mid8 == 0x17: return f"ldc.l  @r{n}+,GBR", 2
        if mid8 == 0x27: return f"ldc.l  @r{n}+,VBR", 2
        # STC variants
        if mid8 == 0x03: return f"stc.l  SR,@-r{n}", 2
        if mid8 == 0x13: return f"stc.l  GBR,@-r{n}", 2
        if mid8 == 0x23: return f"stc.l  VBR,@-r{n}", 2
        return f".word  0x{code:04X}  ; 0x4n__ unknown", 2

    if top4 == 0x5:  # mov.l @(disp,Rm),Rn
        return f"mov.l  @({d*4},r{m}),r{n}", 2

    if top4 == 0x6:
        op = code & 0xF
        if op == 0x0: return f"mov.b  @r{m},r{n}", 2
        if op == 0x1: return f"mov.w  @r{m},r{n}", 2
        if op == 0x2: return f"mov.l  @r{m},r{n}", 2
        if op == 0x3: return f"mov    r{m},r{n}", 2
        if op == 0x4: return f"mov.b  @r{m}+,r{n}", 2
        if op == 0x5: return f"mov.w  @r{m}+,r{n}", 2
        if op == 0x6: return f"mov.l  @r{m}+,r{n}", 2
        if op == 0x7: return f"not    r{m},r{n}", 2
        if op == 0x8: return f"swap.b r{m},r{n}", 2
        if op == 0x9: return f"swap.w r{m},r{n}", 2
        if op == 0xA: return f"negc   r{m},r{n}", 2
        if op == 0xB: return f"neg    r{m},r{n}", 2
        if op == 0xC: return f"extu.b r{m},r{n}", 2
        if op == 0xD: return f"extu.w r{m},r{n}", 2
        if op == 0xE: return f"exts.b r{m},r{n}", 2
        if op == 0xF: return f"exts.w r{m},r{n}", 2

    if top4 == 0x7:  # add #imm,Rn
        imm = sign_extend_8(i)
        return f"add    #{imm},r{n}", 2

    if top4 == 0x8:
        sub = (code >> 8) & 0xF
        if sub == 0x0:  # mov.b R0,@(disp,Rn)
            return f"mov.b  r0,@({d},r{m})", 2
        if sub == 0x1:  # mov.w R0,@(disp,Rn)
            return f"mov.w  r0,@({d*2},r{m})", 2
        if sub == 0x4:  # mov.b @(disp,Rm),R0
            return f"mov.b  @({d},r{m}),r0", 2
        if sub == 0x5:  # mov.w @(disp,Rm),R0
            return f"mov.w  @({d*2},r{m}),r0", 2
        if sub == 0x8:  # cmp/eq #imm,R0
            imm = sign_extend_8(code & 0xFF)
            return f"cmp/eq #{imm},r0", 2
        if sub == 0x9:  # bt
            disp = sign_extend_8(code & 0xFF)
            target = pc + 4 + disp * 2
            return f"bt     0x{target:05X}", 2
        if sub == 0xB:  # bf
            disp = sign_extend_8(code & 0xFF)
            target = pc + 4 + disp * 2
            return f"bf     0x{target:05X}", 2
        if sub == 0xD:  # bt/s
            disp = sign_extend_8(code & 0xFF)
            target = pc + 4 + disp * 2
            return f"bt/s   0x{target:05X}", 2
        if sub == 0xF:  # bf/s
            disp = sign_extend_8(code & 0xFF)
            target = pc + 4 + disp * 2
            return f"bf/s   0x{target:05X}", 2
        return f".word  0x{code:04X}  ; 0x8s__ unknown", 2

    if top4 == 0x9:  # mov.w @(disp,PC),Rn
        disp = code & 0xFF
        target = pc + 4 + disp * 2
        # Try to read the literal value
        if target < len(rom):
            val = struct.unpack_from('>H', rom, target)[0]
            return f"mov.w  @(0x{target:05X}),r{n}  ; =0x{val:04X} ({val})", 2
        return f"mov.w  @(0x{target:05X}),r{n}", 2

    if top4 == 0xA:  # bra
        disp = sign_extend_12(code & 0xFFF)
        target = pc + 4 + disp * 2
        return f"bra    0x{target:05X}", 2

    if top4 == 0xB:  # bsr
        disp = sign_extend_12(code & 0xFFF)
        target = pc + 4 + disp * 2
        return f"bsr    0x{target:05X}", 2

    if top4 == 0xC:
        sub = (code >> 8) & 0xF
        imm = code & 0xFF
        if sub == 0x0: return f"mov.b  r0,@({imm},GBR)", 2
        if sub == 0x1: return f"mov.w  r0,@({imm*2},GBR)  ; GBR+0x{imm*2:X}", 2
        if sub == 0x2: return f"mov.l  r0,@({imm*4},GBR)  ; GBR+0x{imm*4:X}", 2
        if sub == 0x3: return f"trapa  #{imm}", 2
        if sub == 0x4: return f"mov.b  @({imm},GBR),r0", 2
        if sub == 0x5: return f"mov.w  @({imm*2},GBR),r0  ; GBR+0x{imm*2:X}", 2
        if sub == 0x6: return f"mov.l  @({imm*4},GBR),r0  ; GBR+0x{imm*4:X}", 2
        if sub == 0x7:
            target = pc + 4 + imm * 4
            return f"mova   @(0x{target:05X}),r0", 2
        if sub == 0x8: return f"tst    #{imm},r0", 2
        if sub == 0x9: return f"and    #{imm},r0", 2
        if sub == 0xA: return f"xor    #{imm},r0", 2
        if sub == 0xB: return f"or     #{imm},r0", 2
        if sub == 0xC: return f"tst.b  #{imm},@(r0,GBR)", 2
        if sub == 0xD: return f"and.b  #{imm},@(r0,GBR)", 2
        if sub == 0xE: return f"xor.b  #{imm},@(r0,GBR)", 2
        if sub == 0xF: return f"or.b   #{imm},@(r0,GBR)", 2

    if top4 == 0xD:  # mov.l @(disp,PC),Rn
        disp = code & 0xFF
        target = (pc & ~3) + 4 + disp * 4
        if target + 3 < len(rom):
            val = struct.unpack_from('>I', rom, target)[0]
            # Try to decode as float
            fval = struct.unpack_from('>f', rom, target)[0]
            comment = f"=0x{val:08X}"
            if 0x3F000000 <= val <= 0x4F000000 or 0xBF000000 <= val <= 0xCF000000:
                comment += f" ({fval:.6g})"
            elif val >= 0xFFFF0000:
                comment += f" (RAM 0x{val:08X})"
            return f"mov.l  @(0x{target:05X}),r{n}  ; {comment}", 2
        return f"mov.l  @(0x{target:05X}),r{n}", 2

    if top4 == 0xE:  # mov #imm,Rn
        imm = sign_extend_8(i)
        return f"mov    #{imm},r{n}", 2

    if top4 == 0xF:
        # FPU instructions
        lo4 = code & 0xF
        if lo4 == 0x0: return f"fadd   fr{m},fr{n}", 2
        if lo4 == 0x1: return f"fsub   fr{m},fr{n}", 2
        if lo4 == 0x2: return f"fmul   fr{m},fr{n}", 2
        if lo4 == 0x3: return f"fdiv   fr{m},fr{n}", 2
        if lo4 == 0x4: return f"fcmp/eq fr{m},fr{n}", 2
        if lo4 == 0x5: return f"fcmp/gt fr{m},fr{n}", 2
        if lo4 == 0x6: return f"fmov.s @(r0,r{m}),fr{n}", 2
        if lo4 == 0x7: return f"fmov.s fr{m},@(r0,r{n})", 2
        if lo4 == 0x8: return f"fmov.s @r{m},fr{n}", 2
        if lo4 == 0x9: return f"fmov.s @r{m}+,fr{n}", 2
        if lo4 == 0xA: return f"fmov.s fr{m},@r{n}", 2
        if lo4 == 0xB: return f"fmov.s fr{m},@-r{n}", 2
        if lo4 == 0xC: return f"fmov   fr{m},fr{n}", 2
        if lo4 == 0xD:
            mid = (code >> 4) & 0xF
            if mid == 0x0: return f"fsts   FPUL,fr{n}", 2
            if mid == 0x1: return f"flds   fr{n},FPUL", 2
            if mid == 0x2: return f"float  FPUL,fr{n}", 2
            if mid == 0x3: return f"ftrc   fr{n},FPUL", 2
            if mid == 0x4: return f"fneg   fr{n}", 2
            if mid == 0x5: return f"fabs   fr{n}", 2
            if mid == 0x6: return f"fsqrt  fr{n}", 2
            if mid == 0x8: return f"fldi0  fr{n}", 2
            if mid == 0x9: return f"fldi1  fr{n}", 2
            return f".word  0x{code:04X}  ; FPU special", 2
        if lo4 == 0xE: return f"fmac   fr0,fr{m},fr{n}", 2
        return f".word  0x{code:04X}  ; FPU unknown", 2

    return f".word  0x{code:04X}", 2


def disassemble_region(rom, start, end, label=""):
    """Disassemble a region of ROM."""
    pc = start
    lines = []
    if label:
        lines.append(f"\n; {'='*70}")
        lines.append(f"; {label}")
        lines.append(f"; {'='*70}")

    while pc < end:
        if pc + 1 >= len(rom):
            break
        code = struct.unpack_from('>H', rom, pc)[0]
        mnemonic, length = decode_insn(code, pc, rom)
        lines.append(f"  {pc:08X}:  {code:04X}        {mnemonic}")
        pc += length

    return '\n'.join(lines)


# Known RAM addresses for annotation
KNOWN_RAM = {
    0xFFFF80FC: "knock_det_GBR_base",
    0xFFFF81BA: "KNOCK_FLAG",
    0xFFFF81BB: "KNOCK_BANK_FLAG",
    0xFFFF81D9: "fn_043d68_output",
    0xFFFF323C: "FLKC_BASE_STEP",
    0xFFFF8290: "flkc_fg_GBR_base",
    0xFFFF8294: "flkc_fg_counter",
    0xFFFF8298: "flkc_fg_cyl_index",
    0xFFFF829C: "flkc_fg_active",
    0xFFFF829D: "flkc_fg_retard_done",
    0xFFFF829E: "flkc_fg_enable",
    0xFFFF82A0: "flkc_fg_exit_flag",
    0xFFFF82A1: "flkc_fg_bank_route",
    0xFFFF82AA: "flkc_fg_prev_cyl",
    0xFFFF8258: "flkc_fg_limit_FR15",
    0xFFFF3234: "flkc_fg_ref_FR14",
    0xFFFF3244: "flkc_fg_R0_init",
    0xFFFF3248: "flkc_fg_var_3248",
    0xFFFF8233: "flkc_fg_flag_8233",
    0xFFFF7D18: "sched_status_R1",
    0xFFFF3360: "flkc_output_table",
    0xFFFF8EDC: "sched_disable_flag",
}


def main():
    rom_path = "/home/user/ae6l600l/AE5L600L 20g rev 20.3 tiny wrex.bin"
    with open(rom_path, 'rb') as f:
        rom = f.read()

    print(f"; ROM: {rom_path}")
    print(f"; Size: {len(rom)} bytes (0x{len(rom):X})")
    print(f"; SH-2A Big-Endian Disassembly")
    print()

    # Disassemble knock_wrapper + knock_detector
    print(disassemble_region(rom, 0x43750, 0x43B62,
        "KNOCK_WRAPPER (0x43750) + KNOCK_DETECTOR (0x43782)"))
    print()

    # Disassemble flkc_path_J
    print(disassemble_region(rom, 0x45BFE, 0x45DE0,
        "FLKC_PATH_J (0x45BFE) - Task [18] Fast Response"))
    print()

    # Disassemble flkc_paths_FG
    print(disassemble_region(rom, 0x463BA, 0x466A0,
        "FLKC_PATHS_FG (0x463BA) - Task [25] Sustained Knock"))
    print()

    # Post-process: annotate known RAM addresses in output
    # (already done inline via mov.l literal pool decoding)


if __name__ == '__main__':
    main()
