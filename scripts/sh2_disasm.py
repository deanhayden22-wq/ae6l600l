#!/usr/bin/env python3
"""
SH-2/SH-2A disassembler for Subaru ECU ROM analysis.
Decodes 16-bit SH instructions (big-endian) with GBR-relative addressing
annotation and literal pool resolution (including float decoding).

Usage:
    python sh2_disasm.py                  # Run all analysis targets
    python sh2_disasm.py knock            # Knock/FLKC targets only
    python sh2_disasm.py fuel             # CL fueling / A/F Learning targets only
    python sh2_disasm.py 0x45BFE 0x45DE0  # Disassemble arbitrary range
"""
import os
import struct
import sys


# ─── Known RAM addresses for annotation ─────────────────────────────────────

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
    0xFFFF7814: "afc_p_term",
    0xFFFF7818: "afc_i_accumulator",
    0xFFFF7828: "afc_active_flag",
    0xFFFF7865: "afc_prev_state",
    0xFFFF7810: "afc_blend_output",
    0xFFFF77C8: "afc_gbr_base",
}

ROM_PATH = os.path.join(os.path.dirname(__file__), "..", "rom",
                        "AE5L600L 20g rev 20.3 tiny wrex.bin")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def sign_extend_8(val):
    if val & 0x80: return val - 0x100
    return val

def sign_extend_12(val):
    if val & 0x800: return val - 0x1000
    return val


# ─── Instruction Decoder ────────────────────────────────────────────────────

def decode_insn(code, pc, rom):
    """Decode a single 16-bit SH-2/SH-2A instruction. Returns (mnemonic, length)."""
    n = (code >> 8) & 0xF
    m = (code >> 4) & 0xF
    d = code & 0xF
    i = code & 0xFF

    top4 = (code >> 12) & 0xF

    if code == 0x0009: return "nop", 2
    if code == 0x000B: return "rts", 2
    if code == 0x002B: return "rte", 2
    if code == 0x0019: return "div0u", 2
    if code == 0x0048: return "clrs", 2
    if code == 0x0058: return "sets", 2
    if code == 0x0008: return "clrt", 2
    if code == 0x0018: return "sett", 2
    if code == 0x0038: return "ldtlb", 2
    if code == 0x001B: return "sleep", 2
    if code == 0x0028: return "clrmac", 2

    if top4 == 0x0:
        if (code & 0xF00F) == 0x0002: return f"stc    SR,r{n}", 2
        if (code & 0xF00F) == 0x0003: return f"bsrf   r{n}", 2
        if (code & 0xF0FF) == 0x0012: return f"stc    GBR,r{n}", 2
        if (code & 0xF0FF) == 0x0022: return f"stc    VBR,r{n}", 2
        if (code & 0xF0FF) == 0x0023: return f"braf   r{n}", 2
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
        if (code & 0xF0FF) == 0x0029: return f"movt   r{n}", 2
        if (code & 0xF0FF) == 0x0083: return f"pref   @r{n}", 2
        return f".word  0x{code:04X}", 2

    if top4 == 0x1:
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
        return f".word  0x{code:04X}", 2

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
        return f".word  0x{code:04X}", 2

    if top4 == 0x4:
        mid8 = code & 0xFF
        lo4 = code & 0xF
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
        if mid8 == 0x0E: return f"ldc    r{n},SR", 2
        if mid8 == 0x10: return f"dt     r{n}", 2
        if mid8 == 0x11: return f"cmp/pz r{n}", 2
        if mid8 == 0x12: return f"sts.l  MACL,@-r{n}", 2
        if mid8 == 0x15: return f"cmp/pl r{n}", 2
        if mid8 == 0x16: return f"lds.l  @r{n}+,MACL", 2
        if mid8 == 0x18: return f"shll8  r{n}", 2
        if mid8 == 0x19: return f"shlr8  r{n}", 2
        if mid8 == 0x1A: return f"lds    r{n},MACL", 2
        if mid8 == 0x1B: return f"tas.b  @r{n}", 2
        if mid8 == 0x1E: return f"ldc    r{n},GBR", 2
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
        if mid8 == 0x2E: return f"ldc    r{n},VBR", 2
        if mid8 == 0x52: return f"sts.l  FPUL,@-r{n}", 2
        if mid8 == 0x56: return f"lds.l  @r{n}+,FPUL", 2
        if mid8 == 0x5A: return f"lds    r{n},FPUL", 2
        if mid8 == 0x62: return f"sts.l  FPSCR,@-r{n}", 2
        if mid8 == 0x66: return f"lds.l  @r{n}+,FPSCR", 2
        if mid8 == 0x6A: return f"lds    r{n},FPSCR", 2
        if lo4 == 0xF: return f"mac.w  @r{m}+,@r{n}+", 2
        if lo4 == 0xC: return f"shad   r{m},r{n}", 2
        if lo4 == 0xD: return f"shld   r{m},r{n}", 2
        if mid8 == 0x07: return f"ldc.l  @r{n}+,SR", 2
        if mid8 == 0x17: return f"ldc.l  @r{n}+,GBR", 2
        if mid8 == 0x27: return f"ldc.l  @r{n}+,VBR", 2
        if mid8 == 0x03: return f"stc.l  SR,@-r{n}", 2
        if mid8 == 0x13: return f"stc.l  GBR,@-r{n}", 2
        if mid8 == 0x23: return f"stc.l  VBR,@-r{n}", 2
        return f".word  0x{code:04X}", 2

    if top4 == 0x5:
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

    if top4 == 0x7:
        imm = sign_extend_8(i)
        return f"add    #{imm},r{n}", 2

    if top4 == 0x8:
        sub = (code >> 8) & 0xF
        if sub == 0x0: return f"mov.b  r0,@({d},r{m})", 2
        if sub == 0x1: return f"mov.w  r0,@({d*2},r{m})", 2
        if sub == 0x4: return f"mov.b  @({d},r{m}),r0", 2
        if sub == 0x5: return f"mov.w  @({d*2},r{m}),r0", 2
        if sub == 0x8:
            imm = sign_extend_8(code & 0xFF)
            return f"cmp/eq #{imm},r0", 2
        if sub == 0x9:
            disp = sign_extend_8(code & 0xFF)
            target = pc + 4 + disp * 2
            return f"bt     0x{target:05X}", 2
        if sub == 0xB:
            disp = sign_extend_8(code & 0xFF)
            target = pc + 4 + disp * 2
            return f"bf     0x{target:05X}", 2
        if sub == 0xD:
            disp = sign_extend_8(code & 0xFF)
            target = pc + 4 + disp * 2
            return f"bt/s   0x{target:05X}", 2
        if sub == 0xF:
            disp = sign_extend_8(code & 0xFF)
            target = pc + 4 + disp * 2
            return f"bf/s   0x{target:05X}", 2
        return f".word  0x{code:04X}", 2

    if top4 == 0x9:
        disp = code & 0xFF
        target = pc + 4 + disp * 2
        if target < len(rom):
            val = struct.unpack_from('>H', rom, target)[0]
            return f"mov.w  @(0x{target:05X}),r{n}  ; =0x{val:04X} ({val})", 2
        return f"mov.w  @(0x{target:05X}),r{n}", 2

    if top4 == 0xA:
        disp = sign_extend_12(code & 0xFFF)
        target = pc + 4 + disp * 2
        return f"bra    0x{target:05X}", 2

    if top4 == 0xB:
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

    if top4 == 0xD:
        disp = code & 0xFF
        target = (pc & ~3) + 4 + disp * 4
        if target + 3 < len(rom):
            val = struct.unpack_from('>I', rom, target)[0]
            fval = struct.unpack_from('>f', rom, target)[0]
            comment = f"=0x{val:08X}"
            # Annotate as float if in plausible float range
            if 0x3F000000 <= val <= 0x4F000000 or 0xBF000000 <= val <= 0xCF000000:
                comment += f" ({fval:.6g})"
            # Annotate known RAM addresses
            elif val >= 0xFFFF0000:
                ram_name = KNOWN_RAM.get(val, "")
                comment += f" (RAM 0x{val:08X})"
                if ram_name:
                    comment += f" [{ram_name}]"
            return f"mov.l  @(0x{target:05X}),r{n}  ; {comment}", 2
        return f"mov.l  @(0x{target:05X}),r{n}", 2

    if top4 == 0xE:
        imm = sign_extend_8(i)
        return f"mov    #{imm},r{n}", 2

    if top4 == 0xF:
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


# ─── Disassembly Functions ──────────────────────────────────────────────────

def disassemble_region(rom, start, end, label=""):
    """Disassemble a region of ROM from start to end address."""
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


def find_function_end(rom, start_addr, max_len=1024):
    """Find approximate function end by looking for rts after lds.l @R15+,PR."""
    i = 0
    found_epilogue = False
    while i < max_len and start_addr + i < len(rom) - 3:
        opcode = struct.unpack_from('>H', rom, start_addr + i)[0]
        if opcode == 0x4F26:  # lds.l @R15+,PR
            found_epilogue = True
        if found_epilogue and opcode == 0x000B:  # rts
            return start_addr + i + 4  # include delay slot
        if found_epilogue and i > 10:
            found_epilogue = False
        i += 2
    return start_addr + min(max_len, len(rom) - start_addr)


# ─── Call Graph Utilities ───────────────────────────────────────────────────

def resolve_register_load(rom, jsr_addr, reg):
    """Look backwards from a jsr to find the mov.l @(disp,PC),Rn that loaded the register."""
    for back in range(2, 42, 2):
        check_addr = jsr_addr - back
        if check_addr < 0 or check_addr + 2 > len(rom):
            break
        prev_opcode = struct.unpack_from('>H', rom, check_addr)[0]
        # mov.l @(disp,PC),Rn = 0xDnXX
        if (prev_opcode >> 12) == 0xD and ((prev_opcode >> 8) & 0xF) == reg:
            disp8 = prev_opcode & 0xFF
            pool_addr = (check_addr & 0xFFFFFFFC) + 4 + disp8 * 4
            if pool_addr + 4 <= len(rom):
                return struct.unpack_from('>I', rom, pool_addr)[0]
            break
        # mov Rm,Rn = 0x6nm3 - register copy, trace further
        if (prev_opcode >> 12) == 0x6 and (prev_opcode & 0xF) == 0x3:
            dst = (prev_opcode >> 8) & 0xF
            src = (prev_opcode >> 4) & 0xF
            if dst == reg:
                return resolve_register_load(rom, check_addr, src)
    return None


def extract_jsr_targets(rom, start, end):
    """Extract all jsr/bsr call targets from a region."""
    targets = []
    pc = start
    while pc < end and pc + 1 < len(rom):
        opcode = struct.unpack_from('>H', rom, pc)[0]

        # jsr @Rn = 0x4n0B
        if (opcode & 0xF0FF) == 0x400B:
            rn = (opcode >> 8) & 0xF
            target_addr = resolve_register_load(rom, pc, rn)
            targets.append((pc, rn, target_addr))

        # bsr disp = 0xBxxx
        if (opcode >> 12) == 0xB:
            sdisp = opcode & 0xFFF
            if sdisp >= 2048: sdisp -= 4096
            target = pc + 4 + sdisp * 2
            targets.append((pc, -1, target))

        pc += 2
    return targets


def search_for_callers(rom, func_addr):
    """Search ROM for literal pool references to a function address."""
    pattern = struct.pack('>I', func_addr)
    hits = []
    i = 0
    while i < len(rom) - 4:
        if rom[i:i+4] == pattern:
            # Found literal pool entry; find the mov.l that references it
            for scan_back in range(4, 1028, 4):
                check_pc = i - scan_back
                if check_pc < 0 or check_pc + 2 > len(rom):
                    continue
                candidate = struct.unpack_from('>H', rom, check_pc)[0]
                if (candidate >> 12) == 0xD:
                    disp = candidate & 0xFF
                    rn = (candidate >> 8) & 0xF
                    computed_pool = (check_pc & 0xFFFFFFFC) + 4 + disp * 4
                    if computed_pool == i:
                        # Find the jsr that uses this register
                        jsr_addr = None
                        for fwd in range(2, 40, 2):
                            if check_pc + fwd + 2 > len(rom):
                                break
                            fwd_op = struct.unpack_from('>H', rom, check_pc + fwd)[0]
                            if (fwd_op & 0xF0FF) == 0x400B and ((fwd_op >> 8) & 0xF) == rn:
                                jsr_addr = check_pc + fwd
                                break
                        hits.append((i, check_pc, rn, jsr_addr))
                        break
        i += 1
    return hits


# ─── Analysis Target Definitions ────────────────────────────────────────────

KNOCK_TARGETS = [
    (0x43750, 0x43B62, "KNOCK_WRAPPER (0x43750) + KNOCK_DETECTOR (0x43782)"),
    (0x45BFE, 0x45DE0, "FLKC_PATH_J (0x45BFE) - Task [18] Fast Response"),
    (0x463BA, 0x466A0, "FLKC_PATHS_FG (0x463BA) - Task [25] Sustained Knock"),
]

FUEL_TARGETS = [
    (0x033CC4, None, "CL Fueling Target Calculation"),
    (0x034488, None, "A/F Learning #1 Limits"),
]

CALLER_SEARCH_ADDRS = [
    (0x033CC4, "CL fueling target calc"),
    (0x034488, "A/F Learning #1"),
    (0x036070, "CL/OL transition"),
]


# ─── Main ───────────────────────────────────────────────────────────────────

def run_knock_analysis(rom):
    """Disassemble knock/FLKC targets."""
    for start, end, label in KNOCK_TARGETS:
        print(disassemble_region(rom, start, end, label))
        print()


def run_fuel_analysis(rom):
    """Disassemble CL fueling targets with call graph and caller search."""
    for addr, end_addr, label in FUEL_TARGETS:
        if end_addr is None:
            end_addr = find_function_end(rom, addr, max_len=600)
        end_addr = max(end_addr, addr + 300)

        print("=" * 70)
        print(f"FUNCTION @ 0x{addr:06X} - {label}")
        print(f"  (disassembling to 0x{end_addr:06X})")
        print("=" * 70)
        print(disassemble_region(rom, addr, end_addr))
        print()

        targets = extract_jsr_targets(rom, addr, end_addr)
        if targets:
            print(f"--- JSR/BSR call targets in 0x{addr:06X} ---")
            for pc, rn, target in targets:
                tgt_str = f"0x{target:06X}" if target is not None else "UNKNOWN"
                if rn >= 0:
                    print(f"  0x{pc:06X}: jsr @r{rn}  -> {tgt_str}")
                else:
                    print(f"  0x{pc:06X}: bsr        -> {tgt_str}")
            print()

    for func_addr, desc in CALLER_SEARCH_ADDRS:
        print("=" * 70)
        print(f"SEARCH: Who calls 0x{func_addr:06X}? ({desc})")
        print("=" * 70)
        hits = search_for_callers(rom, func_addr)
        if not hits:
            print("  (no literal pool references found)")
        for pool_addr, mov_addr, rn, jsr_addr in hits:
            print(f"  Pool entry at 0x{pool_addr:06X}")
            print(f"    mov.l at 0x{mov_addr:06X} -> r{rn}")
            if jsr_addr is not None:
                print(f"    jsr @r{rn} at 0x{jsr_addr:06X}")
        print()


def main():
    with open(ROM_PATH, 'rb') as f:
        rom = f.read()

    print(f"; ROM: {ROM_PATH}")
    print(f"; Size: {len(rom)} bytes (0x{len(rom):X})")
    print(f"; SH-2/SH-2A Big-Endian Disassembly")
    print()

    args = sys.argv[1:]

    if not args or args[0] == "all":
        run_knock_analysis(rom)
        run_fuel_analysis(rom)
    elif args[0] == "knock":
        run_knock_analysis(rom)
    elif args[0] == "fuel":
        run_fuel_analysis(rom)
    elif args[0].startswith("0x") and len(args) >= 2:
        # Arbitrary range: sh2_disasm.py 0xSTART 0xEND [label]
        start = int(args[0], 16)
        end = int(args[1], 16)
        label = args[2] if len(args) > 2 else f"Region 0x{start:06X}-0x{end:06X}"
        print(disassemble_region(rom, start, end, label))
    else:
        print(f"Usage: {sys.argv[0]} [all|knock|fuel|0xSTART 0xEND [label]]")
        sys.exit(1)


if __name__ == '__main__':
    main()
