#!/usr/bin/env python3
"""
AE5L600L ECU ROM Analysis Toolkit
===================================
Consolidated toolset for Subaru AE5L600L (SH7058 / SH-2) ROM analysis.

Modules:
  disasm  — SH-2 disassembler with knock/fuel analysis targets
  clol    — CL/OL mode flag function trace (FFFF7448 writer at 0x034600)
  tasks   — 59-entry periodic task table dump with instruction peek
  tipin   — Tip-in enrichment vs Tau (alpha transient fueling) analysis

Usage:
    python ae5l600l_tools.py                       # Run all modules
    python ae5l600l_tools.py disasm                # All disasm targets
    python ae5l600l_tools.py disasm knock          # Knock/FLKC targets only
    python ae5l600l_tools.py disasm fuel           # CL fueling / A/F Learning only
    python ae5l600l_tools.py disasm 0x45BFE 0x45DE0  # Arbitrary range
    python ae5l600l_tools.py clol                  # CL/OL mode flag trace
    python ae5l600l_tools.py tasks                 # Task table dump
    python ae5l600l_tools.py tipin                 # Tip-in vs Tau analysis
"""
import os
import struct
import sys


# ═════════════════════════════════════════════════════════════════════════════
# SHARED CORE
# ═════════════════════════════════════════════════════════════════════════════

ROM_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rom")
ROM_PATH_PRIMARY = os.path.join(ROM_DIR, "AE5L600L 20g rev 20.3 tiny wrex.bin")
ROM_PATH_STOCK = os.path.join(ROM_DIR, "ae5l600l.bin")


def load_rom(path=None):
    """Load ROM binary. Tries primary path, then stock, then any .bin in rom/."""
    candidates = [path] if path else [ROM_PATH_PRIMARY, ROM_PATH_STOCK]
    for p in candidates:
        if p and os.path.isfile(p):
            with open(p, "rb") as f:
                return f.read(), p
    # Fallback: first .bin in rom/
    if os.path.isdir(ROM_DIR):
        for fn in os.listdir(ROM_DIR):
            if fn.lower().endswith(".bin"):
                p = os.path.join(ROM_DIR, fn)
                with open(p, "rb") as f:
                    return f.read(), p
    print(f"ERROR: No ROM binary found. Checked: {candidates}", file=sys.stderr)
    sys.exit(1)


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
    0xFFFF6350: "RPM",
    0xFFFF6624: "MAF",
    0xFFFF63CC: "ECT",
    0xFFFF5E94: "GEAR",
    0xFFFF3234: "IAM",
}

# Known function labels (shared across modules)
KNOWN_FUNCS = {
    0x04438C: "task11_knock_flag_read",
    0x043D68: "task12_knock_post",
    0x045BFE: "flkc_path_J",
    0x0463BA: "flkc_paths_FG",
    0x043750: "knock_wrapper",
    0x043782: "knock_detector",
    0x033278: "fuel_precalc",
    0x033CC4: "cl_fuel_target",
    0x036070: "cl_ol_transition_A",
    0x03697A: "cl_ol_transition_B",
    0x021A40: "front_o2_process",
    0x01FE54: "front_o2_atm_comp",
    0x058902: "front_o2_scaling",
    0x004A2C: "front_o2_adc",
    0x04A94C: "sched_periodic_dispatch",
    0x043470: "low_pw_gate",
    0x0BE874: "low_pw_table_proc",
    0x0BECA8: "low_pw_axis_lookup",
    0x030674: "post_start_enrich",
}

# Calibration region labels
CAL_LABELS = {
    0x0C009E: "WG_duty_freq",
    0x0C0BC8: "boost_disable_fuelcut",
}


# ─── Helpers ─────────────────────────────────────────────────────────────────

def sign_extend_8(val):
    if val & 0x80: return val - 0x100
    return val

def sign_extend_12(val):
    if val & 0x800: return val - 0x1000
    return val

def read_u32(rom, off):
    return struct.unpack_from('>I', rom, off)[0]

def read_u16(rom, off):
    return struct.unpack_from('>H', rom, off)[0]

def read_floats(rom, addr, count):
    return [struct.unpack('>f', rom[addr+i*4:addr+i*4+4])[0] for i in range(count)]

def read_uint16s(rom, addr, count):
    return [struct.unpack('>H', rom[addr+i*2:addr+i*2+2])[0] for i in range(count)]

def read_uint8s(rom, addr, count):
    return list(rom[addr:addr+count])


# ═════════════════════════════════════════════════════════════════════════════
# INSTRUCTION DECODER
# ═════════════════════════════════════════════════════════════════════════════

def decode_insn(code, pc, rom):
    """Decode a single 16-bit SH-2 instruction. Returns (mnemonic, length)."""
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
            if 0x3F000000 <= val <= 0x4F000000 or 0xBF000000 <= val <= 0xCF000000:
                comment += f" ({fval:.6g})"
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


# ═════════════════════════════════════════════════════════════════════════════
# MODULE: DISASM — Disassembly utilities + knock/fuel analysis
# ═════════════════════════════════════════════════════════════════════════════

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


def resolve_register_load(rom, jsr_addr, reg):
    """Look backwards from a jsr to find the mov.l @(disp,PC),Rn that loaded the register."""
    for back in range(2, 42, 2):
        check_addr = jsr_addr - back
        if check_addr < 0 or check_addr + 2 > len(rom):
            break
        prev_opcode = struct.unpack_from('>H', rom, check_addr)[0]
        if (prev_opcode >> 12) == 0xD and ((prev_opcode >> 8) & 0xF) == reg:
            disp8 = prev_opcode & 0xFF
            pool_addr = (check_addr & 0xFFFFFFFC) + 4 + disp8 * 4
            if pool_addr + 4 <= len(rom):
                return struct.unpack_from('>I', rom, pool_addr)[0]
            break
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
        if (opcode & 0xF0FF) == 0x400B:
            rn = (opcode >> 8) & 0xF
            target_addr = resolve_register_load(rom, pc, rn)
            targets.append((pc, rn, target_addr))
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


# Disasm analysis targets
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


def cmd_disasm(rom, rom_path, args):
    """Handle 'disasm' subcommand."""
    print(f"; ROM: {rom_path}")
    print(f"; Size: {len(rom)} bytes (0x{len(rom):X})")
    print(f"; SH-2 Big-Endian Disassembly")
    print()

    if not args or args[0] == "all":
        run_knock_analysis(rom)
        run_fuel_analysis(rom)
    elif args[0] == "knock":
        run_knock_analysis(rom)
    elif args[0] == "fuel":
        run_fuel_analysis(rom)
    elif args[0].startswith("0x") and len(args) >= 2:
        start = int(args[0], 16)
        end = int(args[1], 16)
        label = args[2] if len(args) > 2 else f"Region 0x{start:06X}-0x{end:06X}"
        print(disassemble_region(rom, start, end, label))
    else:
        print(f"Usage: disasm [all|knock|fuel|0xSTART 0xEND [label]]")
        sys.exit(1)


# ═════════════════════════════════════════════════════════════════════════════
# MODULE: CLOL — CL/OL mode flag function trace
# ═════════════════════════════════════════════════════════════════════════════

CLOL_START = 0x034600
CLOL_END   = 0x034B40

CLOL_WRITE_ADDRS = {0x03476C, 0x034822, 0x034830, 0x03487A, 0x0348D6,
                    0x03496A, 0x034A26, 0x034A42, 0x034A4E, 0x034B02, 0x034B08}


def clol_annotate_val(val):
    if val == 0xFFFF7448:
        return "CL/OL mode flag"
    if 0xFFFF0000 <= val <= 0xFFFFFFFF:
        return "RAM"
    if 0x000C0000 <= val <= 0x000FFFFF:
        return "CAL table"
    if 0 < val < 0x100000:
        return "ROM"
    return ""


def clol_resolve_pool_l(rom, addr, opcode):
    disp8 = opcode & 0xFF
    ea = (addr & 0xFFFFFFFC) + 4 + disp8 * 4
    if ea + 4 <= len(rom):
        return ea, struct.unpack(">I", rom[ea:ea+4])[0]
    return ea, None


def clol_resolve_pool_w(rom, addr, opcode):
    disp8 = opcode & 0xFF
    ea = addr + 4 + disp8 * 2
    if ea + 2 <= len(rom):
        return ea, struct.unpack(">H", rom[ea:ea+2])[0]
    return ea, None


def cmd_clol(rom, rom_path, args):
    """Handle 'clol' subcommand — CL/OL mode flag function trace."""
    START = CLOL_START
    END = CLOL_END

    # Pass 1: collect branch targets and literal pool refs
    branch_targets = set()
    pool_longs = {}
    pool_words = {}

    addr = START
    while addr < END:
        if addr + 2 > len(rom):
            break
        op = struct.unpack(">H", rom[addr:addr+2])[0]
        t4 = (op >> 12) & 0xF
        sub8 = (op >> 8) & 0xF

        if t4 == 0x8 and sub8 in (0x9, 0xB, 0xD, 0xF):
            d = op & 0xFF
            disp = d if d < 128 else d - 256
            branch_targets.add(addr + 4 + disp * 2)
        elif t4 == 0xA:
            d12 = op & 0xFFF
            disp = d12 if d12 < 0x800 else d12 - 0x1000
            branch_targets.add(addr + 4 + disp * 2)
        elif t4 == 0xB:
            d12 = op & 0xFFF
            disp = d12 if d12 < 0x800 else d12 - 0x1000
            branch_targets.add(addr + 4 + disp * 2)

        if t4 == 0xD:
            rn = sub8
            ea, val = clol_resolve_pool_l(rom, addr, op)
            pool_longs[ea] = (addr, rn, val)
        elif t4 == 0x9:
            rn = sub8
            ea, val = clol_resolve_pool_w(rom, addr, op)
            pool_words[ea] = (addr, rn, val)

        addr += 2

    # Pass 2: disassemble
    print("=" * 110)
    print("FULL DISASSEMBLY: CL/OL Mode Flag Function (0x034600 - 0x034B20)")
    print("Writes to RAM FFFF7448 marked with >>>")
    print("=" * 110)

    addr = START
    while addr < END:
        if addr + 2 > len(rom):
            break

        if addr in pool_longs:
            _, _, val = pool_longs[addr]
            if val is not None:
                b = rom[addr:addr+4]
                a = clol_annotate_val(val)
                print("  0x%06X:  %02X%02X %02X%02X  .long 0x%08X      ; %s" % (addr, b[0], b[1], b[2], b[3], val, a))
                addr += 4
                continue

        if addr in branch_targets:
            print("loc_%06X:" % addr)

        marker = ">>>" if addr in CLOL_WRITE_ADDRS else "   "
        op = struct.unpack(">H", rom[addr:addr+2])[0]
        mnem, _ = decode_insn(op, addr, rom)

        comment = ""
        t4 = (op >> 12) & 0xF
        if t4 == 0xD:
            ea, val = clol_resolve_pool_l(rom, addr, op)
            if val is not None:
                a = clol_annotate_val(val)
                comment = "=0x%08X" % val
                if a:
                    comment += " (%s)" % a
        elif t4 == 0x9:
            ea, val = clol_resolve_pool_w(rom, addr, op)
            if val is not None:
                comment = "=0x%04X (%d)" % (val, val)

        if addr in CLOL_WRITE_ADDRS:
            comment += "  *** WRITE FFFF7448 ***"

        print("%s 0x%06X:  %04X    %-42s ; %s" % (marker, addr, op, mnem, comment))
        addr += 2

    # Pass 3: trace each write
    print()
    print("=" * 110)
    print("DETAILED WRITE TRACE: Values written to FFFF7448")
    print("=" * 110)

    for wa in sorted(CLOL_WRITE_ADDRS):
        op = struct.unpack(">H", rom[wa:wa+2])[0]
        src_reg = (op >> 4) & 0xF
        dst_reg = (op >> 8) & 0xF

        print()
        print("--- WRITE @ 0x%06X: mov.b R%d,@R%d ---" % (wa, src_reg, dst_reg))

        # Trace source register
        trace_reg = src_reg
        scan = wa - 2
        for _ in range(50):
            if scan < START:
                break
            sop = struct.unpack(">H", rom[scan:scan+2])[0]
            st4 = (sop >> 12) & 0xF
            sn = (sop >> 8) & 0xF
            sm = (sop >> 4) & 0xF

            if st4 == 0xE and sn == trace_reg:
                imm = sop & 0xFF
                simm = imm if imm < 128 else imm - 256
                print("  Value: %d (0x%02X)   (mov #%d,R%d at 0x%06X)" % (simm, imm, simm, sn, scan))
                break
            if st4 == 0x6 and sn == trace_reg and (sop & 0xF) == 0xE:
                trace_reg = sm
                scan -= 2
                continue
            if st4 == 0x6 and sn == trace_reg and (sop & 0xF) == 0x3:
                trace_reg = sm
                scan -= 2
                continue
            if st4 == 0x6 and sn == trace_reg and (sop & 0xF) == 0x0:
                print("  Value: byte from @R%d   (mov.b @R%d,R%d at 0x%06X)" % (sm, sm, sn, scan))
                break
            if st4 == 0x8 and (sop >> 8 & 0xF) == 0x4 and trace_reg == 0:
                disp = sop & 0xF
                print("  Value: byte from @(%d,R%d)   (at 0x%06X)" % (disp, sm, scan))
                break
            if st4 == 0xD and sn == trace_reg:
                ea, val = clol_resolve_pool_l(rom, scan, sop)
                print("  Value: 0x%08X from pool   (at 0x%06X)" % (val, scan))
                break
            if st4 == 0x7 and sn == trace_reg:
                scan -= 2
                continue
            scan -= 2
        else:
            print("  Value: could not trace")

        # Find controlling branch
        print("  Condition:")
        scan = wa - 2
        for _ in range(40):
            if scan < START:
                break
            sop = struct.unpack(">H", rom[scan:scan+2])[0]
            st4 = (sop >> 12) & 0xF
            sub8 = (sop >> 8) & 0xF

            if st4 == 0x8 and sub8 in (0x9, 0xB, 0xD, 0xF):
                d = sop & 0xFF
                disp = d if d < 128 else d - 256
                target = scan + 4 + disp * 2
                bnames = {0x9: "bt", 0xB: "bf", 0xD: "bt/s", 0xF: "bf/s"}
                btype = bnames[sub8]

                if target > wa:
                    rel = "skips over write (write is fall-through)"
                elif target == wa:
                    rel = "branches directly to write"
                elif abs(target - wa) <= 4:
                    rel = "branches near write"
                else:
                    rel = "branches to 0x%06X" % target

                cscan = scan - 2
                cmp_str = ""
                for __ in range(10):
                    if cscan < START:
                        break
                    cop = struct.unpack(">H", rom[cscan:cscan+2])[0]
                    ct4 = (cop >> 12) & 0xF
                    cn = (cop >> 8) & 0xF
                    cm = (cop >> 4) & 0xF

                    if ct4 == 0x8 and cn == 0x8:
                        cimm = cop & 0xFF
                        csimm = cimm if cimm < 128 else cimm - 256
                        cmp_str = "cmp/eq #%d,R0" % csimm
                        break
                    if ct4 == 0x3 and (cop & 0xF) == 0x0:
                        cmp_str = "cmp/eq R%d,R%d" % (cm, cn)
                        break
                    if ct4 == 0x3 and (cop & 0xF) in (0x2, 0x3, 0x6, 0x7):
                        names = {0x2: "cmp/hs", 0x3: "cmp/ge", 0x6: "cmp/hi", 0x7: "cmp/gt"}
                        cmp_str = "%s R%d,R%d" % (names[cop & 0xF], cm, cn)
                        break
                    if ct4 == 0x2 and (cop & 0xF) == 0x8:
                        cmp_str = "tst R%d,R%d" % (cm, cn)
                        break
                    if ct4 == 0xC and cn == 0x8:
                        cmp_str = "tst #%d,R0" % (cop & 0xFF)
                        break
                    cscan -= 2

                print("    %s 0x%06X at 0x%06X -> %s" % (btype, target, scan, rel))
                if cmp_str:
                    print("    Test: %s at 0x%06X" % (cmp_str, cscan))
                break

            if st4 == 0xA:
                d12 = sop & 0xFFF
                disp = d12 if d12 < 0x800 else d12 - 0x1000
                target = scan + 4 + disp * 2
                print("    bra 0x%06X at 0x%06X" % (target, scan))
                break

            if sop == 0x000B:
                print("    (after rts at 0x%06X)" % scan)
                break

            if scan in CLOL_WRITE_ADDRS and scan != wa:
                print("    (preceded by another write at 0x%06X)" % scan)
                break

            scan -= 2

    # Pass 4: Literal pool summary
    print()
    print("=" * 110)
    print("LITERAL POOL ENTRIES (32-bit)")
    print("=" * 110)
    for ea in sorted(pool_longs.keys()):
        ia, rn, val = pool_longs[ea]
        if val is not None:
            a = clol_annotate_val(val)
            print("  Pool 0x%06X: 0x%08X  R%d @ 0x%06X  %s" % (ea, val, rn, ia, a))

    # Pass 5: Calibration addresses
    print()
    print("=" * 110)
    print("CALIBRATION ADDRESSES (0x0Cxxxx)")
    print("=" * 110)
    for ea in sorted(pool_longs.keys()):
        _, rn, val = pool_longs[ea]
        if val is not None and 0x000C0000 <= val <= 0x000FFFFF:
            if val + 2 <= len(rom):
                b = rom[val]
                w = struct.unpack(">H", rom[val:val+2])[0]
                print("  0x%06X: byte=0x%02X (%3d), word=0x%04X (%5d)  (pool 0x%06X, R%d)" % (val, b, b, w, w, ea, rn))
            else:
                print("  0x%06X: (out of range)" % val)


# ═════════════════════════════════════════════════════════════════════════════
# MODULE: TASKS — Periodic task table dump
# ═════════════════════════════════════════════════════════════════════════════

def analyze_function(rom, func_addr, max_insns=64):
    """Analyze the first N instructions of a function.
    Returns dict with: gbr_values, ram_refs, cal_refs, calls, has_fpu, rom_refs
    """
    info = {
        'gbr_values': [],
        'ram_refs': {},
        'cal_refs': {},
        'calls_bsr': [],
        'calls_jsr': False,
        'has_fpu': False,
        'rom_refs': {},
        'gbr_offsets': [],
    }

    pc = func_addr
    for _ in range(max_insns):
        if pc + 1 >= len(rom):
            break
        code = read_u16(rom, pc)

        if code == 0x000B:
            pass

        top4 = (code >> 12) & 0xF
        n = (code >> 8) & 0xF
        m = (code >> 4) & 0xF

        # LDC Rn,GBR  (0x4n1E)
        if (code & 0xF0FF) == 0x401E:
            info['gbr_values'].append(f"r{n}")

        # mov.l @(disp,PC),Rn - literal pool load
        if top4 == 0xD:
            disp = code & 0xFF
            target = (pc & ~3) + 4 + disp * 4
            if target + 3 < len(rom):
                val = read_u32(rom, target)
                if val >= 0xFFFF0000:
                    label = KNOWN_RAM.get(val, "")
                    info['ram_refs'][val] = label
                elif 0x000C0000 <= val <= 0x000FFFFF:
                    label = CAL_LABELS.get(val, "")
                    info['cal_refs'][val] = label
                elif 0x00000100 <= val <= 0x000BFFFF:
                    label = KNOWN_FUNCS.get(val, "")
                    info['rom_refs'][val] = label

        # BSR
        if top4 == 0xB:
            disp = sign_extend_12(code & 0xFFF)
            call_target = pc + 4 + disp * 2
            info['calls_bsr'].append(call_target)

        # JSR @Rn
        if (code & 0xF0FF) == 0x400B:
            info['calls_jsr'] = True

        # FPU instructions (top4 == 0xF)
        if top4 == 0xF:
            info['has_fpu'] = True

        # GBR-relative access (0xC0-0xC6)
        if top4 == 0xC:
            sub = (code >> 8) & 0xF
            imm = code & 0xFF
            if sub in (0, 1, 2, 4, 5, 6):
                if sub in (0, 4):
                    off = imm
                elif sub in (1, 5):
                    off = imm * 2
                else:
                    off = imm * 4
                rw = 'W' if sub <= 2 else 'R'
                info['gbr_offsets'].append((off, rw))

        # BRA (unconditional branch) - follow if it's a thunk
        if top4 == 0xA and _ == 0:
            disp = sign_extend_12(code & 0xFFF)
            jump_target = pc + 4 + disp * 2
            info['rom_refs'][jump_target] = KNOWN_FUNCS.get(jump_target, "thunk_target")

        pc += 2

    return info


def categorize(info, func_addr):
    """Try to categorize based on references."""
    categories = []

    if func_addr in KNOWN_FUNCS:
        return [KNOWN_FUNCS[func_addr]]

    ram = set(info['ram_refs'].keys())

    knock_ram = {0xFFFF81BA, 0xFFFF81BB, 0xFFFF80FC}
    if ram & knock_ram:
        categories.append("knock")

    flkc_ram = {0xFFFF8290, 0xFFFF323C, 0xFFFF3360}
    if ram & flkc_ram:
        categories.append("FLKC")

    if 0xFFFF6350 in ram:
        categories.append("uses_RPM")
    if 0xFFFF63CC in ram:
        categories.append("uses_ECT")
    if 0xFFFF6624 in ram:
        categories.append("uses_MAF")
    if info['has_fpu']:
        categories.append("FPU")
    if info['gbr_values']:
        categories.append("sets_GBR")

    if not categories:
        categories.append("unknown")

    return categories


def cmd_tasks(rom, rom_path, args):
    """Handle 'tasks' subcommand — dump periodic task table."""
    TABLE_START = 0x4AD40
    TERMINATOR = 0xFFFF8322

    print(f"; AE5L600L Periodic Task Table Dump")
    print(f"; Table base: 0x{TABLE_START:05X}")
    print(f"; ROM: {rom_path}")
    print(f"; {'='*76}")
    print()

    tasks = []
    offset = TABLE_START
    idx = 0
    while True:
        val = read_u32(rom, offset)
        if val == TERMINATOR or val >= 0xFFFF0000:
            print(f"; [TERMINATOR] @ 0x{offset:05X} = 0x{val:08X}")
            break
        tasks.append((idx, offset, val))
        idx += 1
        offset += 4
        if idx > 80:
            break

    print(f"; Total tasks: {len(tasks)}")
    print()
    print(f"; {'Idx':>3s}  {'TblAddr':>7s}  {'FuncAddr':>10s}  {'Label':<30s}  Categories")
    print(f"; {'-'*3}  {'-'*7}  {'-'*10}  {'-'*30}  {'-'*30}")

    for idx, tbl_off, func_addr in tasks:
        info = analyze_function(rom, func_addr)
        cats = categorize(info, func_addr)
        label = KNOWN_FUNCS.get(func_addr, "")

        cat_str = ", ".join(cats)
        print(f"; [{idx:2d}]  0x{tbl_off:05X}  0x{func_addr:08X}  {label:<30s}  {cat_str}")

    # Detailed analysis
    print()
    print(f"; {'='*76}")
    print(f"; DETAILED ANALYSIS")
    print(f"; {'='*76}")

    for idx, tbl_off, func_addr in tasks:
        info = analyze_function(rom, func_addr)
        label = KNOWN_FUNCS.get(func_addr, f"task_{idx:02d}")

        print(f"\n; --- Task [{idx:2d}]: 0x{func_addr:08X} ({label}) ---")

        if info['gbr_values']:
            print(f";   GBR set from: {', '.join(info['gbr_values'])}")

        if info['ram_refs']:
            print(f";   RAM refs:")
            for addr, lbl in sorted(info['ram_refs'].items()):
                extra = f" ({lbl})" if lbl else ""
                print(f";     0x{addr:08X}{extra}")

        if info['cal_refs']:
            print(f";   Calibration refs:")
            for addr, lbl in sorted(info['cal_refs'].items()):
                extra = f" ({lbl})" if lbl else ""
                print(f";     0x{addr:08X}{extra}")

        if info['rom_refs']:
            print(f";   ROM code refs:")
            for addr, lbl in sorted(info['rom_refs'].items()):
                extra = f" ({lbl})" if lbl else ""
                print(f";     0x{addr:08X}{extra}")

        if info['calls_bsr']:
            named_calls = []
            for t in info['calls_bsr']:
                lbl = KNOWN_FUNCS.get(t, "")
                named_calls.append(f"0x{t:08X}" + (f" ({lbl})" if lbl else ""))
            print(f";   BSR calls: {', '.join(named_calls)}")

        if info['calls_jsr']:
            print(f";   Has JSR (indirect calls)")

        if info['has_fpu']:
            print(f";   Uses FPU")

        if info['gbr_offsets']:
            reads = sorted(set(o for o, rw in info['gbr_offsets'] if rw == 'R'))
            writes = sorted(set(o for o, rw in info['gbr_offsets'] if rw == 'W'))
            if reads:
                print(f";   GBR reads: {', '.join(f'+0x{o:X}' for o in reads)}")
            if writes:
                print(f";   GBR writes: {', '.join(f'+0x{o:X}' for o in writes)}")


# ═════════════════════════════════════════════════════════════════════════════
# MODULE: TIPIN — Tip-in enrichment vs Tau analysis
# ═════════════════════════════════════════════════════════════════════════════

def cmd_tipin(rom, rom_path, args):
    """Handle 'tipin' subcommand — tip-in enrichment vs Tau analysis."""

    # Shared ECT axis
    ect_axis_c = read_floats(rom, 0xCC624, 16)
    ect_axis_f = [(x * 1.8) + 32 for x in ect_axis_c]

    print("=" * 78)
    print("TIP-IN ENRICHMENT vs TAU: RELATIONSHIP ANALYSIS")
    print(f"ROM: {rom_path}")
    print("=" * 78)

    # SECTION 1: TIP-IN ENRICHMENT TABLES
    print("\n" + "-" * 78)
    print("SECTION 1: THROTTLE TIP-IN ENRICHMENT (Throttle-Rate Based)")
    print("-" * 78)
    print("""
The Tip-in Enrichment system adds fuel based on THROTTLE ANGLE RATE OF CHANGE.
It is a direct, throttle-position-derivative system that fires when the driver
stabs the throttle.

  Trigger:  delta(throttle_angle) per cycle
  Output:   Additional Injector Pulse Width (ms) added to base IPW
  Purpose:  Compensate for intake manifold fuel film lag on sudden throttle
            opening - prevents lean stumble during tip-in transients.
""")

    tip_a_axis = read_floats(rom, 0xCED08, 18)
    tip_a_data = read_uint16s(rom, 0xCED50, 18)
    tip_a_ms = [x * 0.004 for x in tip_a_data]

    print("  Throttle Tip-in Enrichment A (addr 0xCED50):")
    print(f"  {'Throttle delta (%)':>15s}  {'Added IPW (ms)':>15s}")
    for i in range(len(tip_a_axis)):
        print(f"  {tip_a_axis[i]:>15.1f}  {tip_a_ms[i]:>15.3f}")

    print(f"\n  Activation Requirements:")
    min_thr = read_floats(rom, 0xCC4A0, 1)[0]
    min_ipw_raw = read_floats(rom, 0xCC4A4, 1)[0]
    min_ipw = min_ipw_raw * 0.004
    print(f"    Min Throttle Angle Change:  {min_thr:.1f}%")
    print(f"    Min Calculated IPW Adder:   {min_ipw:.3f} ms (after compensations)")
    print(f"    Applied Counter Reset:      {rom[0xCBC08]} cycles")
    print(f"    Throttle Cumulative Reset:  {rom[0xCBC09]} cycles")

    # Tip-in Compensations
    print("\n  Tip-in Enrichment Compensations (multiply the base tip-in IPW):")

    print("\n  RPM Compensation (addr 0xCD118):")
    rpm_axis = read_floats(rom, 0xCD0D8, 16)
    tip_comp_rpm = read_uint8s(rom, 0xCD118, 16)
    tip_comp_rpm_pct = [(x * 0.78125) - 100 for x in tip_comp_rpm]
    print(f"    {'RPM':>6s}  {'Comp (%)':>10s}")
    for i in range(len(rpm_axis)):
        print(f"    {rpm_axis[i]:>6.0f}  {tip_comp_rpm_pct[i]:>10.1f}")
    print("    NOTE: At low RPM (<2000), tip-in enrichment is heavily reduced.")
    print("          Full enrichment only at ~4800+ RPM.")

    print("\n  ECT Compensation B (addr 0xCEDE0) - cold engine boost:")
    tip_comp_b = read_uint16s(rom, 0xCEDE0, 16)
    tip_comp_b_pct = [(x * 0.01220703125) - 100 for x in tip_comp_b]
    print(f"    {'ECT (F)':>10s}  {'Comp (%)':>10s}")
    for i in range(len(ect_axis_f)):
        if tip_comp_b_pct[i] != 0:
            print(f"    {ect_axis_f[i]:>10.0f}  {tip_comp_b_pct[i]:>10.1f}")
    print("    Cold engines get up to 350% total tip-in enrichment (250% + base).")
    print("    At 140F+, no additional ECT compensation.")

    # SECTION 2: TAU TABLES
    print("\n" + "-" * 78)
    print("SECTION 2: TAU - ALPHA TRANSIENT FUELING (Load-Rate Based)")
    print("-" * 78)
    print("""
The Tau system adds fuel based on ENGINE LOAD RATE OF CHANGE. It is a
load-derivative system that responds to changes in volumetric efficiency
and manifold filling - a fundamentally different trigger than tip-in.

  Trigger:  delta(engine_load) per cycle (g/rev change rate)
  Output:   Enrichment Adder Multiplier (dimensionless, multiplies a base adder)
  Purpose:  Compensate for fuel film dynamics during load transients that
            may NOT correspond to throttle changes (e.g., boost spool,
            gear changes, altitude changes).

The Tau value is an "Enrichment Adder Multiplier" - it scales how much
additional fuel is added during transient load conditions.
""")

    print("  Tau Input A Rising Load Activation (addr 0xCD6E6):")
    print("  (When engine load is INCREASING)")
    eload_axis = read_floats(rom, 0xCCDCC, 3)
    tau_rising = read_uint16s(rom, 0xCD6E6, 48)
    tau_rising_val = [x * 0.00048828125 for x in tau_rising]
    print(f"\n    {'':>10s}", end="")
    for t in ect_axis_f:
        print(f"  {t:>6.0f}F", end="")
    print()
    for row in range(3):
        print(f"    {eload_axis[row]:>6.2f}g/r", end="")
        for col in range(16):
            print(f"  {tau_rising_val[row*16+col]:>7.3f}", end="")
        print()

    print("\n  Tau Input A Falling Load Activation (addr 0xCD746):")
    print("  (When engine load is DECREASING - fuel cut / decel)")
    tau_falling = read_uint16s(rom, 0xCD746, 16)
    tau_falling_val = [x * 0.00048828125 for x in tau_falling]
    print(f"    {'ECT (F)':>10s}  {'Tau Multiplier':>15s}")
    for i in range(len(ect_axis_f)):
        print(f"    {ect_axis_f[i]:>10.0f}  {tau_falling_val[i]:>15.4f}")

    print("\n  Tau Falling Load Variants:")
    for label, addr in [("A", 0xCD766), ("B", 0xCD848), ("C", 0xCD868)]:
        vals = [x * 0.00048828125 for x in read_uint16s(rom, addr, 16)]
        cold = vals[0]
        warm = vals[10]
        hot = vals[15]
        print(f"    Variant {label} (addr 0x{addr:X}): cold={cold:.4f}  warm(140F)={warm:.4f}  hot={hot:.4f}")

    # SECTION 3: THE RELATIONSHIP
    print("\n" + "-" * 78)
    print("SECTION 3: THE RELATIONSHIP BETWEEN TIP-IN AND TAU")
    print("-" * 78)
    print("""
  SUMMARY: Tip-in and Tau are TWO INDEPENDENT transient fueling systems
  that operate on DIFFERENT input signals but combine additively in the
  final fuel correction accumulator.

  +---------------------------------------------------------------------+
  |                    TRANSIENT FUELING PIPELINE                        |
  |                                                                      |
  |  THROTTLE POSITION --> delta(throttle)/dt --> Tip-in Enrichment      |
  |                                                    |                 |
  |                                                    v                 |
  |                                              Additional IPW (ms)     |
  |                                              x RPM Comp              |
  |                                              x ECT Comp              |
  |                                              x Boost Error Comp      |
  |                                                    |                 |
  |                                                    |  (if > min      |
  |                                                    |   threshold)    |
  |                                                    v                 |
  |  ENGINE LOAD ----------> delta(load)/dt ------> Tau Multiplier       |
  |                                                    |                 |
  |                                                    v                 |
  |                                              Tau x Base Adder        |
  |                                                    |                 |
  |                                                    v                 |
  |              +---------------------------------------------+         |
  |              |                                                       |
  |              v                                                       |
  |     Final Fuel Correction Accumulator (0x320AE)                      |
  |     Final IPW = Base IPW x (1 + AFC) x (1 + LTFT) x corrections     |
  |                          + Tip-in Adder + Tau Adder                  |
  +---------------------------------------------------------------------+

  KEY DIFFERENCES:
  -------------------------------------------------------------------
  Property              Tip-in Enrichment           Tau (Alpha Transient)
  -------------------------------------------------------------------
  Trigger               Throttle angle change       Engine load change
  Units                 IPW adder (ms)              Enrichment multiplier
  Sensitivity           Throttle rate               Load rate (g/rev/cycle)
  Direction             Rising throttle only        Rising AND falling load
  Cold compensation     Yes (ECT B/C: up to +250%)  Yes (built into tables)
  RPM compensation      Yes (0-100% by RPM)         No (load-indexed)
  Boost compensation    Yes (reduces with boost)    Via manifold pressure axis
  Disable mechanism     Counter + cumulative        Separate variants (A-C)
  -------------------------------------------------------------------

  HOW THEY INTERACT DURING A TYPICAL TIP-IN EVENT:
  -------------------------------------------------

  1. Driver stabs throttle -> large delta(throttle)
     -> Tip-in system activates immediately with IPW adder (0.4-1.5 ms)
     -> Compensations applied (RPM, ECT, boost error)
     -> Result must exceed 1.32 ms minimum to actually fire

  2. As turbo spools and manifold fills -> engine load rises
     -> Tau system detects rising load rate
     -> Tau multiplier applied (1.5-3.4x at cold, 0.25-1.5x at warm)
     -> Adds enrichment proportional to load change rate

  3. The two systems overlap in time but trigger on different signals:
     - Tip-in fires FIRST (throttle moves before load changes)
     - Tau fires SECOND (load follows throttle with turbo lag)
     - Together they "bridge the gap" from throttle movement to full boost

  4. During tip-OUT (throttle closing):
     - Tip-in system: INACTIVE (only responds to rising throttle)
     - Tau falling load: ACTIVE (handles the fuel film evaporation
       during falling load - prevents rich spike on decel)

  TEMPERATURE RELATIONSHIP:
  -------------------------
  Both systems provide MORE enrichment when the engine is COLD:
    - Tip-in ECT Comp B:  +250% at -40F, tapering to 0% at 140F
    - Tau Rising (1.75 g/r): 3.40x at -40F, tapering to 0.32x at 176F+

  This makes physical sense: cold intake ports have more fuel film
  condensation, requiring more aggressive transient compensation.

  LOAD/BOOST RELATIONSHIP:
  ------------------------
  - Tip-in reduces enrichment WITH boost error (up to -90.6% at 0 psi error)
    meaning when boost is ON TARGET, tip-in enrichment is nearly eliminated
  - Tau INCREASES enrichment at higher loads (3.40x vs 0.32x multiplier
    comparing 1.75 g/rev to 8.0 g/rev at hot temps)

  This is complementary: as boost builds and tip-in fades, tau picks up
  the transient fuel compensation role.
""")


# ═════════════════════════════════════════════════════════════════════════════
# CLI DISPATCHER
# ═════════════════════════════════════════════════════════════════════════════

USAGE = """
AE5L600L ECU ROM Analysis Toolkit

Usage:
    python ae5l600l_tools.py                          Run all modules
    python ae5l600l_tools.py disasm [all|knock|fuel]  SH-2 disassembly
    python ae5l600l_tools.py disasm 0xSTART 0xEND     Arbitrary range
    python ae5l600l_tools.py clol                     CL/OL mode flag trace
    python ae5l600l_tools.py tasks                    Task table dump
    python ae5l600l_tools.py tipin                    Tip-in vs Tau analysis
""".strip()


def main():
    rom, rom_path = load_rom()
    args = sys.argv[1:]

    if not args or args[0] == "all":
        print("=" * 78)
        print("AE5L600L ECU ROM Analysis Toolkit — Running All Modules")
        print(f"ROM: {rom_path} ({len(rom)} bytes)")
        print("=" * 78)
        print()
        cmd_disasm(rom, rom_path, ["all"])
        print("\n\n")
        cmd_clol(rom, rom_path, [])
        print("\n\n")
        cmd_tasks(rom, rom_path, [])
        print("\n\n")
        cmd_tipin(rom, rom_path, [])
    elif args[0] == "disasm":
        cmd_disasm(rom, rom_path, args[1:])
    elif args[0] == "clol":
        cmd_clol(rom, rom_path, args[1:])
    elif args[0] == "tasks":
        cmd_tasks(rom, rom_path, args[1:])
    elif args[0] == "tipin":
        cmd_tipin(rom, rom_path, args[1:])
    elif args[0] == "-h" or args[0] == "--help":
        print(USAGE)
    else:
        print(f"Unknown command: {args[0]}")
        print(USAGE)
        sys.exit(1)


if __name__ == '__main__':
    main()
