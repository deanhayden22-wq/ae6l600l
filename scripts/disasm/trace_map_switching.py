#!/usr/bin/env python3
"""
AE5L600L Map Switching & Timing Blend Subsystem Trace
======================================================
Traces the cruise/non-cruise map switching and timing blend code paths.

Task 31: task31_timing_blend_ratio   @ 0x3FFD6 -- Blend ratio calculator
Task 32: task32_timing_blend_app     @ 0x4004A -- Blend ratio application
Task 33: task33_timing_ws_init       @ 0x40918 -- Timing workspace init
Task 50: task50_timing_blend_int     @ 0x3F368 -- Timing blend interpolation

Key RAM:
  0xFFFF7F60 = cruise/non-cruise blend ratio (0.0=cruise, 1.0=non-cruise)
  0xFFFF7F0C = timing blend GBR base
  0xFFFF7FD4 = timing workspace GBR base

Calibration block: 0xD29AC - 0xD2B1C (~40 parameters)

Output: disassembly/analysis/map_switching_raw.txt
"""
import os
import struct
import sys
import math

sys.stdout.reconfigure(encoding='utf-8')

ROM_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "rom", "ae5l600l.bin")
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "disassembly", "analysis", "map_switching_raw.txt")

with open(ROM_PATH, "rb") as f:
    rom = f.read()

ROM_LEN = len(rom)

# ============================================================================
# Known addresses
# ============================================================================

KNOWN_RAM = {
    0xFFFF7F60: "map_ratio",
    0xFFFF7F0C: "timing_blend_gbr",
    0xFFFF7FD4: "timing_ws_gbr",
    0xFFFF9230: "blend_ratio_workspace_A",
    0xFFFF9234: "blend_ratio_workspace_B",
    0xFFFF9164: "blend_timing_ws_A",
    0xFFFF9168: "blend_timing_ws_B",
    0xFFFF91F9: "blend_state_flag",
    0xFFFF7F3C: "blend_output_scratch",
    0xFFFF90A8: "blend_app_scratch",
    0xFFFF679C: "gear_current",
    0xFFFF7BE2: "idle_mode_flag",
    0xFFFF8075: "si_drive_mode",
    0xFFFF804C: "timing_base_select",
    0xFFFF90BE: "timing_ws_scratch",
    0xFFFF8E7E: "timing_ws_state",
    0xFFFF6624: "rpm_current",
    0xFFFF6350: "ect_current",
    0xFFFF63F8: "iat_current",
    0xFFFF65C0: "throttle_position",
    0xFFFF6898: "manifold_pressure",
    0xFFFF61CC: "vehicle_speed",
    0xFFFF6810: "maf_gps",
    0xFFFF6254: "engine_state",
    0xFFFF67EC: "engine_run_time",
    0xFFFF7448: "cl_ol_mode_flag",
    0xFFFF64F5: "boost_related_flag",
    0xFFFF5E94: "gear_position",
    0xFFFF7F82: "throttle_timing_corr",
    0xFFFF802E: "multiaxis_timing_corr",
    0xFFFF8EDC: "sched_disable_flag",
    0xFFFF7D18: "sched_status_R1",
}

KNOWN_FUNCS = {
    0x0003FFD6: "task31_timing_blend_ratio",
    0x0004004A: "task32_timing_blend_app",
    0x00040918: "task33_timing_ws_init",
    0x0003F368: "task50_timing_blend_int",
    0x000BDA0C: "check_engine_running",
    0x000BE830: "table_desc_1d_float",
    0x000BE8E4: "table_desc_2d_typed",
    0x000BDBCC: "desc_read_float_safe",
    0x000BDE0C: "float_lerp",
    0x000BDE68: "float_max",
    0x000BDE78: "float_min",
    0x000BDE28: "float_clamp",
    0x000BE2C0: "desc_processor_2d",
    0x000BE480: "desc_axis_lookup",
    0x000BDFE0: "table_interp_1d",
    0x000BE040: "table_interp_2d",
    0x000BE6D0: "table_read_1d",
    0x000BE770: "table_read_2d",
    0x000BB434: "desc_eval_dispatch",
}

CAL_LABELS = {
    0x0D29AC: "MapSwitch_CruiseSwitchCounterA",
    0x0D29AE: "MapSwitch_CruiseSwitchMinDelayA",
    0x0D29B0: "MapSwitch_CruiseSwitchCounterB",
    0x0D29B2: "MapSwitch_CruiseSwitchMinDelayB",
    0x0D29D4: "MapSwitch_BlendAppCal",
    0x0D2A08: "MapSwitch_EngineSpeedThreshold",
    0x0D2A0C: "MapSwitch_TorqueRatioThreshold",
    0x0D2A10: "MapSwitch_MAFLoadThreshold",
    0x0D2A14: "MapSwitch_VehicleSpeedLow",
    0x0D2A18: "MapSwitch_VehicleSpeedHigh",
    0x0D2A1C: "MapSwitch_IATThreshold",
    0x0D2A34: "MapSwitch_IdleModeThreshold",
    0x0D2A38: "MapSwitch_SIDriveThreshold",
    0x0D2A40: "MapSwitch_ECTColdLow",
    0x0D2A44: "MapSwitch_ECTColdHigh",
    0x0D2A50: "MapSwitch_ECTHotA",
    0x0D2A54: "MapSwitch_ECTHotB",
    0x0D2A58: "MapSwitch_RatioModMin",
    0x0D2A5C: "MapSwitch_RatioModScale",
    0x0D2A60: "MapSwitch_RampAdderA",
    0x0D2A64: "MapSwitch_RampAdderB",
    0x0D2A68: "MapSwitch_MAFSensorA",
    0x0D2A6C: "MapSwitch_MAFSensorB",
    0x0D2A70: "MapSwitch_ReqTorqueMin",
    0x0D2A74: "MapSwitch_GearRPM_1",
    0x0D2A78: "MapSwitch_GearRPM_2",
    0x0D2A7C: "MapSwitch_GearRPM_3",
    0x0D2A80: "MapSwitch_GearRPM_4",
    0x0D2A84: "MapSwitch_GearRPM_5",
    0x0D2A88: "MapSwitch_GearRPM_6",
    0x0D2A8C: "MapSwitch_BaseRPMThreshold",
    0x0D2A90: "MapSwitch_ECTCompA",
    0x0D2A94: "MapSwitch_ECTCompB",
    0x0D2A98: "MapSwitch_ECTThreshold",
    0x0D2A9C: "MapSwitch_RPMOverride",
    0x0D2AA0: "MapSwitch_LoadOverride",
    0x0D2AA4: "MapSwitch_SpeedLoadCheck",
    0x0D2AA8: "MapSwitch_RPMHystLow",
    0x0D2AAC: "MapSwitch_RPMHystHigh",
    0x0D2AB0: "MapSwitch_RatioMinBound",
    0x0D2AB4: "MapSwitch_RatioMaxBound",
    0x0D2ABC: "MapSwitch_PctCeiling",
    0x0D2AE8: "TimBlend_LookupInputThreshold",
    0x0D2AEC: "TimBlend_RPMActivation",
    0x0D2AF0: "TimBlend_RPMSecondary",
    0x0D2AF4: "TimBlend_IAT_A",
    0x0D2AF8: "TimBlend_IAT_B",
    0x0D2AFC: "TimBlend_CorrOffset",
    0x0D2B00: "TimBlend_RPMMax",
    0x0D2B04: "TimBlend_RampRate",
    0x0D2B08: "TimBlend_CorrThreshold",
    0x0D2B0C: "TimBlend_HalfRatio",
    0x0D2B10: "TimBlend_MinRatio",
    0x0D2B14: "TimBlend_RPMLimit",
    0x0D2B18: "TimBlend_RatioFloor",
    0x0D2B1C: "TimBlend_RatioCeiling",
}

# ============================================================================
# Primitives
# ============================================================================

def r_u8(a):  return rom[a]
def r_u16(a): return struct.unpack_from(">H", rom, a)[0]
def r_s16(a): return struct.unpack_from(">h", rom, a)[0]
def r_u32(a): return struct.unpack_from(">I", rom, a)[0]
def r_f32(a): return struct.unpack_from(">f", rom, a)[0]

def is_rom_ptr(v): return 0x1000 <= v < ROM_LEN
def is_ram_ptr(v): return 0xFFFF0000 <= v <= 0xFFFFFFFF

def sign_extend_8(val):
    return val - 0x100 if val & 0x80 else val

def sign_extend_12(val):
    return val - 0x1000 if val & 0x800 else val

# ============================================================================
# Instruction decoder (from ae5l600l_tools.py)
# ============================================================================

def decode_insn(code, pc):
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

    if top4 == 0x0:
        if (code & 0xF00F) == 0x0003: return f"bsrf   r{n}", 2
        if (code & 0xF0FF) == 0x0012: return f"stc    GBR,r{n}", 2
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
        if (code & 0xF00F) == 0x0002: return f"stc    SR,r{n}", 2
        return f".word  0x{code:04X}", 2

    if top4 == 0x1: return f"mov.l  r{m},@({d*4},r{n})", 2
    if top4 == 0x2:
        op = code & 0xF
        ops = {0:"mov.b",1:"mov.w",2:"mov.l",4:"mov.b",5:"mov.w",6:"mov.l",
               7:"div0s",8:"tst",9:"and",0xA:"xor",0xB:"or",0xC:"cmp/str",
               0xD:"xtrct",0xE:"mulu.w",0xF:"muls.w"}
        if op in (0,1,2): return f"{ops[op]}  r{m},@r{n}", 2
        if op in (4,5,6): return f"{ops[op]}  r{m},@-r{n}", 2
        if op in ops: return f"{ops[op]} r{m},r{n}", 2
        return f".word  0x{code:04X}", 2

    if top4 == 0x3:
        op = code & 0xF
        ops3 = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",4:"div1",5:"dmulu.l",
                6:"cmp/hi",7:"cmp/gt",8:"sub",0xA:"subc",0xB:"subv",
                0xC:"add",0xD:"dmuls.l",0xE:"addc",0xF:"addv"}
        if op in ops3: return f"{ops3[op]} r{m},r{n}", 2
        return f".word  0x{code:04X}", 2

    if top4 == 0x4:
        mid8 = code & 0xFF
        lo4 = code & 0xF
        ops4 = {0x00:"shll",0x01:"shlr",0x04:"rotl",0x05:"rotr",0x08:"shll2",
                0x09:"shlr2",0x10:"dt",0x11:"cmp/pz",0x15:"cmp/pl",0x18:"shll8",
                0x19:"shlr8",0x1B:"tas.b",0x20:"shal",0x21:"shar",0x24:"rotcl",
                0x25:"rotcr",0x28:"shll16",0x29:"shlr16"}
        if mid8 in ops4: return f"{ops4[mid8]}  r{n}", 2
        if mid8 == 0x0B: return f"jsr    @r{n}", 2
        if mid8 == 0x2B: return f"jmp    @r{n}", 2
        if mid8 == 0x0A: return f"lds    r{n},MACH", 2
        if mid8 == 0x1A: return f"lds    r{n},MACL", 2
        if mid8 == 0x2A: return f"lds    r{n},PR", 2
        if mid8 == 0x0E: return f"ldc    r{n},SR", 2
        if mid8 == 0x1E: return f"ldc    r{n},GBR", 2
        if mid8 == 0x2E: return f"ldc    r{n},VBR", 2
        if mid8 == 0x22: return f"sts.l  PR,@-r{n}", 2
        if mid8 == 0x26: return f"lds.l  @r{n}+,PR", 2
        if mid8 == 0x02: return f"sts.l  MACH,@-r{n}", 2
        if mid8 == 0x12: return f"sts.l  MACL,@-r{n}", 2
        if mid8 == 0x06: return f"lds.l  @r{n}+,MACH", 2
        if mid8 == 0x16: return f"lds.l  @r{n}+,MACL", 2
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
        return f".word  0x{code:04X}", 2

    if top4 == 0x5: return f"mov.l  @({d*4},r{m}),r{n}", 2
    if top4 == 0x6:
        op = code & 0xF
        ops6 = {0:"mov.b  @",1:"mov.w  @",2:"mov.l  @",3:"mov    ",
                4:"mov.b  @",5:"mov.w  @",6:"mov.l  @",7:"not    ",
                8:"swap.b ",9:"swap.w ",0xA:"negc   ",0xB:"neg    ",
                0xC:"extu.b ",0xD:"extu.w ",0xE:"exts.b ",0xF:"exts.w "}
        if op <= 2: return f"mov.{['b','w','l'][op]}  @r{m},r{n}", 2
        if op == 3: return f"mov    r{m},r{n}", 2
        if op <= 6: return f"mov.{['','b','w','l'][op-3]}  @r{m}+,r{n}", 2
        if op in ops6: return f"{ops6[op]}r{m},r{n}", 2
        return f".word  0x{code:04X}", 2

    if top4 == 0x7: return f"add    #{sign_extend_8(i)},r{n}", 2

    if top4 == 0x8:
        sub = (code >> 8) & 0xF
        if sub == 0x0: return f"mov.b  r0,@({d},r{m})", 2
        if sub == 0x1: return f"mov.w  r0,@({d*2},r{m})", 2
        if sub == 0x4: return f"mov.b  @({d},r{m}),r0", 2
        if sub == 0x5: return f"mov.w  @({d*2},r{m}),r0", 2
        if sub == 0x8: return f"cmp/eq #{sign_extend_8(code & 0xFF)},r0", 2
        if sub == 0x9:
            target = pc + 4 + sign_extend_8(code & 0xFF) * 2
            return f"bt     0x{target:05X}", 2
        if sub == 0xB:
            target = pc + 4 + sign_extend_8(code & 0xFF) * 2
            return f"bf     0x{target:05X}", 2
        if sub == 0xD:
            target = pc + 4 + sign_extend_8(code & 0xFF) * 2
            return f"bt/s   0x{target:05X}", 2
        if sub == 0xF:
            target = pc + 4 + sign_extend_8(code & 0xFF) * 2
            return f"bf/s   0x{target:05X}", 2
        return f".word  0x{code:04X}", 2

    if top4 == 0x9:
        disp = code & 0xFF
        target = pc + 4 + disp * 2
        if target < ROM_LEN:
            val = r_u16(target)
            return f"mov.w  @(0x{target:05X}),r{n}  ; =0x{val:04X} ({val})", 2
        return f"mov.w  @(0x{target:05X}),r{n}", 2

    if top4 == 0xA:
        target = pc + 4 + sign_extend_12(code & 0xFFF) * 2
        return f"bra    0x{target:05X}", 2

    if top4 == 0xB:
        target = pc + 4 + sign_extend_12(code & 0xFFF) * 2
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
            target = (pc & ~3) + 4 + imm * 4
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
        if target + 3 < ROM_LEN:
            val = r_u32(target)
            fval = r_f32(target)
            comment = f"=0x{val:08X}"
            if 0x3F000000 <= val <= 0x4F000000 or 0xBF000000 <= val <= 0xCF000000:
                comment += f" ({fval:.6g})"
            elif is_ram_ptr(val):
                ram_name = KNOWN_RAM.get(val, "")
                comment += f" (RAM)"
                if ram_name: comment += f" [{ram_name}]"
            elif is_rom_ptr(val):
                cal_name = CAL_LABELS.get(val, "")
                func_name = KNOWN_FUNCS.get(val, "")
                if cal_name: comment += f" [cal:{cal_name}]"
                elif func_name: comment += f" [func:{func_name}]"
                else: comment += f" (ROM)"
            return f"mov.l  @(0x{target:05X}),r{n}  ; {comment}", 2
        return f"mov.l  @(0x{target:05X}),r{n}", 2

    if top4 == 0xE: return f"mov    #{sign_extend_8(i)},r{n}", 2

    if top4 == 0xF:
        lo4 = code & 0xF
        fpu = {0:"fadd",1:"fsub",2:"fmul",3:"fdiv",4:"fcmp/eq",5:"fcmp/gt",
               6:"fmov.s @(r0,",7:"fmov.s ",8:"fmov.s @",9:"fmov.s @",
               0xA:"fmov.s ",0xB:"fmov.s ",0xC:"fmov   "}
        if lo4 <= 5: return f"{fpu[lo4]} fr{m},fr{n}", 2
        if lo4 == 6: return f"fmov.s @(r0,r{m}),fr{n}", 2
        if lo4 == 7: return f"fmov.s fr{m},@(r0,r{n})", 2
        if lo4 == 8: return f"fmov.s @r{m},fr{n}", 2
        if lo4 == 9: return f"fmov.s @r{m}+,fr{n}", 2
        if lo4 == 0xA: return f"fmov.s fr{m},@r{n}", 2
        if lo4 == 0xB: return f"fmov.s fr{m},@-r{n}", 2
        if lo4 == 0xC: return f"fmov   fr{m},fr{n}", 2
        if lo4 == 0xD:
            mid = (code >> 4) & 0xF
            fpu_s = {0:"fsts   FPUL,",1:"flds   ",2:"float  FPUL,",3:"ftrc   ",
                     4:"fneg   ",5:"fabs   ",6:"fsqrt  ",8:"fldi0  ",9:"fldi1  "}
            if mid in fpu_s:
                if mid == 1: return f"flds   fr{n},FPUL", 2
                if mid == 3: return f"ftrc   fr{n},FPUL", 2
                return f"{fpu_s[mid]}fr{n}", 2
            return f".word  0x{code:04X}  ; FPU special", 2
        if lo4 == 0xE: return f"fmac   fr0,fr{m},fr{n}", 2
        return f".word  0x{code:04X}  ; FPU", 2

    return f".word  0x{code:04X}", 2

# ============================================================================
# Disassembly engine
# ============================================================================

def find_function_end(start, max_len=2048):
    i = 0
    found_epilogue = False
    while i < max_len and start + i < ROM_LEN - 3:
        opcode = r_u16(start + i)
        if opcode == 0x4F26:  # lds.l @R15+,PR
            found_epilogue = True
        if found_epilogue and opcode == 0x000B:  # rts
            return start + i + 4
        if found_epilogue and i > 10:
            found_epilogue = False
        i += 2
    return start + min(max_len, ROM_LEN - start)

def disasm_function(start, label="", max_len=2048):
    end = find_function_end(start, max_len)
    lines = []
    if label:
        lines.append(f"\n{'='*78}")
        lines.append(f"  {label}  @  0x{start:05X}")
        lines.append(f"{'='*78}")

    # Collect all literal pool references first
    pool_refs = {}
    pc = start
    while pc < end:
        if pc + 1 >= ROM_LEN: break
        code = r_u16(pc)
        top4 = (code >> 12) & 0xF
        if top4 == 0xD:
            disp = code & 0xFF
            target = (pc & ~3) + 4 + disp * 4
            if target + 3 < ROM_LEN:
                val = r_u32(target)
                pool_refs[pc] = (target, val)
        pc += 2

    # Now disassemble
    pc = start
    while pc < end:
        if pc + 1 >= ROM_LEN: break
        code = r_u16(pc)
        mnemonic, length = decode_insn(code, pc)
        lines.append(f"  {pc:06X}: {code:04X}  {mnemonic}")
        pc += length

    # Literal pool summary
    if pool_refs:
        lines.append(f"\n  --- Literal Pool References ---")
        seen = set()
        for src_pc in sorted(pool_refs):
            target, val = pool_refs[src_pc]
            if target in seen: continue
            seen.add(target)
            fval = struct.unpack_from(">f", rom, target)[0]
            annotation = ""
            if is_ram_ptr(val):
                name = KNOWN_RAM.get(val, "unknown")
                annotation = f"  RAM [{name}]"
            elif is_rom_ptr(val):
                name = CAL_LABELS.get(val, KNOWN_FUNCS.get(val, ""))
                if name: annotation = f"  [{name}]"
                else:
                    # Try to read float value at that ROM address
                    try:
                        romfval = r_f32(val)
                        if 0.001 < abs(romfval) < 100000:
                            annotation = f"  (ROM cal: {romfval:.4g})"
                    except: pass
            elif 0x3F000000 <= val <= 0x4F000000 or 0xBF000000 <= val <= 0xCF000000:
                annotation = f"  (float: {fval:.6g})"
            lines.append(f"    0x{target:06X}: 0x{val:08X}{annotation}")

    return '\n'.join(lines)

def trace_subroutines(start, max_len=2048):
    """Find all jsr/bsr calls within a function."""
    end = find_function_end(start, max_len)
    calls = []
    pc = start
    while pc < end:
        if pc + 1 >= ROM_LEN: break
        code = r_u16(pc)
        top4 = (code >> 12) & 0xF
        # BSR
        if top4 == 0xB:
            target = pc + 4 + sign_extend_12(code & 0xFFF) * 2
            name = KNOWN_FUNCS.get(target, f"FUN_{target:06X}")
            calls.append((pc, target, name))
        # JSR @Rn
        if top4 == 0x4 and (code & 0xFF) == 0x0B:
            reg = (code >> 8) & 0xF
            # resolve register
            tgt = resolve_register_load(pc, reg)
            if tgt:
                name = KNOWN_FUNCS.get(tgt, f"FUN_{tgt:06X}")
                calls.append((pc, tgt, name))
            else:
                calls.append((pc, None, f"jsr @r{reg} (unresolved)"))
        pc += 2
    return calls

def resolve_register_load(jsr_addr, reg):
    for back in range(2, 42, 2):
        check_addr = jsr_addr - back
        if check_addr < 0 or check_addr + 2 > ROM_LEN: break
        prev = r_u16(check_addr)
        if (prev >> 12) == 0xD and ((prev >> 8) & 0xF) == reg:
            disp8 = prev & 0xFF
            pool_addr = (check_addr & 0xFFFFFFFC) + 4 + disp8 * 4
            if pool_addr + 4 <= ROM_LEN:
                return r_u32(pool_addr)
            break
        if (prev >> 12) == 0x6 and (prev & 0xF) == 0x3:
            dst = (prev >> 8) & 0xF
            src = (prev >> 4) & 0xF
            if dst == reg:
                return resolve_register_load(check_addr, src)
    return None

# ============================================================================
# Dump calibration block values
# ============================================================================

def dump_calibration_block():
    lines = []
    lines.append("\n" + "="*78)
    lines.append("  CALIBRATION BLOCK: Map Switching Parameters (0xD29AC - 0xD2B1C)")
    lines.append("="*78)

    # uint16 section (counters/delays)
    u16_cals = [
        (0xD29AC, "CruiseSwitchCounterA"),
        (0xD29AE, "CruiseSwitchMinDelayA"),
        (0xD29B0, "CruiseSwitchCounterB"),
        (0xD29B2, "CruiseSwitchMinDelayB"),
    ]
    for addr, name in u16_cals:
        val = r_u16(addr)
        lines.append(f"  0x{addr:06X}: {val:6d}    {name}")

    lines.append("")

    # float section - main map switching
    float_cals = sorted([(a, n) for a, n in CAL_LABELS.items()
                         if a >= 0xD2A08 and a <= 0xD2ABC])
    for addr, name in float_cals:
        val = r_f32(addr)
        lines.append(f"  0x{addr:06X}: {val:12.4f}    {name}")

    lines.append("")

    # timing blend section
    lines.append("  --- Timing Blend Parameters ---")
    tb_cals = sorted([(a, n) for a, n in CAL_LABELS.items()
                      if a >= 0xD2AE8])
    for addr, name in tb_cals:
        val = r_f32(addr)
        lines.append(f"  0x{addr:06X}: {val:12.4f}    {name}")

    return '\n'.join(lines)

# ============================================================================
# Descriptor decode
# ============================================================================

TYPE_NAMES = {0x00:"float32", 0x02:"int8", 0x04:"int16", 0x08:"uint8", 0x0A:"uint16"}
TYPE_SIZES = {0x00:4, 0x02:1, 0x04:2, 0x08:1, 0x0A:2}

def decode_descriptor(desc_addr):
    """Decode a descriptor header at the given ROM address."""
    if desc_addr + 20 > ROM_LEN: return None
    flags = r_u8(desc_addr)
    dtype = r_u8(desc_addr + 1)
    ycnt  = r_u8(desc_addr + 2)
    xcnt  = r_u8(desc_addr + 3)
    is_2d = bool(flags & 0x01)
    data_addr = r_u32(desc_addr + 4)
    xaxis_addr = r_u32(desc_addr + 8)
    yaxis_addr = r_u32(desc_addr + 12) if is_2d else None
    scale_f = r_f32(desc_addr + 16) if desc_addr + 20 <= ROM_LEN else 1.0

    return {
        'addr': desc_addr,
        'flags': flags,
        'dtype': dtype,
        'dtype_name': TYPE_NAMES.get(dtype, f"unk_{dtype:02X}"),
        'ycnt': ycnt,
        'xcnt': xcnt,
        'is_2d': is_2d,
        'data_addr': data_addr,
        'xaxis_addr': xaxis_addr,
        'yaxis_addr': yaxis_addr,
        'scale': scale_f,
    }

def dump_descriptor(desc_addr, label=""):
    d = decode_descriptor(desc_addr)
    if not d: return f"  [Invalid descriptor at 0x{desc_addr:06X}]"
    lines = []
    dim = "2D" if d['is_2d'] else "1D"
    lines.append(f"  Descriptor @ 0x{desc_addr:06X}: {dim} {d['dtype_name']} "
                 f"{'×'.join(str(x) for x in ([d['ycnt']] if d['is_2d'] else []) + [d['xcnt']])}"
                 f"  scale={d['scale']:.6g}")
    if label: lines[-1] += f"  [{label}]"
    lines.append(f"    Data:   0x{d['data_addr']:06X}")
    lines.append(f"    X-axis: 0x{d['xaxis_addr']:06X}")
    if d['is_2d']:
        lines.append(f"    Y-axis: 0x{d['yaxis_addr']:06X}")

    # Dump axis values (float)
    try:
        xvals = [r_f32(d['xaxis_addr'] + i*4) for i in range(d['xcnt'])]
        lines.append(f"    X: [{', '.join(f'{v:.2f}' for v in xvals)}]")
    except: pass

    if d['is_2d']:
        try:
            yvals = [r_f32(d['yaxis_addr'] + i*4) for i in range(d['ycnt'])]
            lines.append(f"    Y: [{', '.join(f'{v:.2f}' for v in yvals)}]")
        except: pass

    return '\n'.join(lines)

# ============================================================================
# Main output
# ============================================================================

def main():
    out = []
    out.append("AE5L600L Map Switching & Timing Blend Disassembly Trace")
    out.append("=" * 78)
    out.append(f"ROM: {ROM_PATH}")
    out.append(f"ROM size: {ROM_LEN} bytes")
    out.append("")

    # 1. Calibration block
    out.append(dump_calibration_block())

    # 2. Timing blend descriptors
    desc_addrs = [0xADB4C, 0xADB60, 0xADB74, 0xADB88, 0xADBB0]
    out.append("\n" + "="*78)
    out.append("  TIMING BLEND DESCRIPTORS")
    out.append("="*78)
    for i, da in enumerate(desc_addrs):
        out.append(dump_descriptor(da, f"desc_timing_blend_{i}"))
        out.append("")

    # 3. Task 31: timing_blend_ratio
    out.append(disasm_function(0x3FFD6, "task31_timing_blend_ratio"))
    calls31 = trace_subroutines(0x3FFD6)
    if calls31:
        out.append("\n  --- Subroutine calls ---")
        for src, tgt, name in calls31:
            out.append(f"    0x{src:06X} -> {name}" + (f" @ 0x{tgt:06X}" if tgt else ""))

    # 4. Task 32: timing_blend_app
    out.append(disasm_function(0x4004A, "task32_timing_blend_app"))
    calls32 = trace_subroutines(0x4004A)
    if calls32:
        out.append("\n  --- Subroutine calls ---")
        for src, tgt, name in calls32:
            out.append(f"    0x{src:06X} -> {name}" + (f" @ 0x{tgt:06X}" if tgt else ""))

    # 5. Task 33: timing_ws_init
    out.append(disasm_function(0x40918, "task33_timing_ws_init"))
    calls33 = trace_subroutines(0x40918)
    if calls33:
        out.append("\n  --- Subroutine calls ---")
        for src, tgt, name in calls33:
            out.append(f"    0x{src:06X} -> {name}" + (f" @ 0x{tgt:06X}" if tgt else ""))

    # 6. Task 50: timing_blend_int
    out.append(disasm_function(0x3F368, "task50_timing_blend_int"))
    calls50 = trace_subroutines(0x3F368)
    if calls50:
        out.append("\n  --- Subroutine calls ---")
        for src, tgt, name in calls50:
            out.append(f"    0x{src:06X} -> {name}" + (f" @ 0x{tgt:06X}" if tgt else ""))

    # 7. Now trace the main map switching evaluator
    # The cruise/non-cruise ratio is computed somewhere and written to FFFF7F60
    # Let's find which functions write to FFFF7F60 by scanning code
    out.append("\n" + "="*78)
    out.append("  XREF SCAN: Writers to FFFF7F60 (map_ratio)")
    out.append("="*78)

    # Search for mov.l that loads 0xFFFF7F60 pointer
    target_ram = 0xFFFF7F60
    writers = []
    for pc in range(0, ROM_LEN - 4, 2):
        code = r_u16(pc)
        if (code >> 12) == 0xD:  # mov.l @(disp,PC),Rn
            disp = code & 0xFF
            pool = (pc & ~3) + 4 + disp * 4
            if pool + 4 <= ROM_LEN:
                val = r_u32(pool)
                if val == target_ram:
                    writers.append(pc)

    out.append(f"  Found {len(writers)} references to 0x{target_ram:08X}:")
    for w in writers:
        # Find which function this is in
        func_name = "unknown"
        for faddr, fname in sorted(KNOWN_FUNCS.items()):
            if faddr <= w <= faddr + 2048:
                func_name = fname
        out.append(f"    0x{w:06X}  (in {func_name})")

    # 8. Disassemble the main map switching evaluator if we can find it
    # From torque_management_analysis, the switching criteria are at D29AC-D2ABC
    # Let's find which function loads those addresses
    out.append("\n" + "="*78)
    out.append("  XREF SCAN: References to MapSwitch calibrations (0xD2A08)")
    out.append("="*78)

    target_cal = 0x000D2A08
    cal_refs = []
    for pc in range(0, ROM_LEN - 4, 2):
        code = r_u16(pc)
        if (code >> 12) == 0xD:
            disp = code & 0xFF
            pool = (pc & ~3) + 4 + disp * 4
            if pool + 4 <= ROM_LEN:
                val = r_u32(pool)
                if val == target_cal:
                    cal_refs.append(pc)

    out.append(f"  Found {len(cal_refs)} references to 0x{target_cal:08X} (MapSwitch_EngineSpeedThreshold):")
    for w in cal_refs:
        func_name = "unknown"
        for faddr, fname in sorted(KNOWN_FUNCS.items()):
            if faddr <= w <= faddr + 2048:
                func_name = fname
        out.append(f"    0x{w:06X}  (in {func_name})")

    # Disassemble the functions that reference the map switch calibrations
    # Usually these will be within task32 or nearby
    seen_funcs = set()
    for w in cal_refs:
        # Find the function start by scanning back for a prologue (sts.l PR,@-R15 = 0x4F22)
        fstart = w
        for back in range(0, 512, 2):
            addr = w - back
            if addr < 0: break
            if r_u16(addr) == 0x4F22:  # sts.l PR,@-R15
                fstart = addr
                break
        if fstart not in seen_funcs:
            seen_funcs.add(fstart)
            name = KNOWN_FUNCS.get(fstart, f"FUN_{fstart:06X}")
            out.append(disasm_function(fstart, f"Map switch evaluator: {name}"))
            calls = trace_subroutines(fstart)
            if calls:
                out.append("\n  --- Subroutine calls ---")
                for src, tgt, nm in calls:
                    out.append(f"    0x{src:06X} -> {nm}" + (f" @ 0x{tgt:06X}" if tgt else ""))

    # Write output
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write('\n'.join(out))
    print(f"Output written to {OUTPUT_PATH}")
    print(f"Total lines: {len(out)}")

if __name__ == "__main__":
    main()
