#!/usr/bin/env python3
"""
AE5L600L Fuel Pump Control Subsystem Trace
============================================
Traces the fuel pump duty control code.

The fuel pump duty constants (66.7% and 33.3%) are at 0x4BBAC/0x4BBB0,
accessed by the function at 0x4B970, called from 0x47C40 (task10 call_52).

Known calibrations:
  0x4BBAC  float  66.7%   Fuel Pump Duty (high)
  0x4BBB0  float  33.3%   Fuel Pump Duty (low)
  0x4BBA0  float  100.0%  Fuel Pump Duty (max)

Output: disassembly/analysis/fuel_pump_raw.txt
"""
import os
import struct
import sys

sys.stdout.reconfigure(encoding='utf-8')

ROM_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "rom", "ae5l600l.bin")
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "disassembly", "analysis", "fuel_pump_raw.txt")

with open(ROM_PATH, "rb") as f:
    rom = f.read()

ROM_LEN = len(rom)

KNOWN_RAM = {
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
    0xFFFF8EDC: "sched_disable_flag",
    0xFFFF8323: "ol_dispatch_gate",
    0xFFFF8354: "fuel_pump_state",
    0xFFFF8364: "fuel_pump_workspace",
    0xFFFF8E98: "fuel_pump_flag",
    0xFFFF5E94: "gear_position",
    0xFFFF4130: "ignition_switch_state",
    0xFFFF62DC: "fuel_rate",
    0xFFFF64F5: "boost_related_flag",
    0xFFFF69F0: "boost_pressure",
}

KNOWN_FUNCS = {
    0x000BDA0C: "check_engine_running",
    0x000BE830: "table_desc_1d_float",
    0x000BE8E4: "table_desc_2d_typed",
    0x000BDBCC: "desc_read_float_safe",
    0x000BDE0C: "float_lerp",
    0x000BDE68: "float_max",
    0x000BDE78: "float_min",
    0x000BDE28: "float_clamp",
    0x000BE960: "float_max",
    0x000BE970: "rate_limit_interp",
    0x000BEA40: "float_lerp",
    0x000BE554: "uint16_add_sat",
    0x0000DF14: "rtos_task10_sensors",
    0x00047C40: "task10_call52_clol_pump",
    0x0004B970: "fuel_pump_duty_ctrl",
    0x0004BA30: "fuel_pump_sub_A",
    0x0000E108: "task10_call52_dispatch",
    0x000080C6: "hw_port_write",
    0x000281DC: "fuel_pump_helper_A",
    0x0005EA4E: "fuel_pump_helper_B",
    0x0005EB1A: "fuel_pump_helper_C",
}

CAL_LABELS = {
    0x04BBAC: "FuelPump_DutyHigh_66pct",
    0x04BBB0: "FuelPump_DutyLow_33pct",
    0x04BBA0: "FuelPump_DutyMax_100pct",
}

# ============================================================================

def r_u8(a):  return rom[a]
def r_u16(a): return struct.unpack_from(">H", rom, a)[0]
def r_u32(a): return struct.unpack_from(">I", rom, a)[0]
def r_f32(a): return struct.unpack_from(">f", rom, a)[0]
def is_rom_ptr(v): return 0x1000 <= v < ROM_LEN
def is_ram_ptr(v): return 0xFFFF0000 <= v <= 0xFFFFFFFF

def sign_extend_8(val):
    return val - 0x100 if val & 0x80 else val

def sign_extend_12(val):
    return val - 0x1000 if val & 0x800 else val

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
        if (code & 0xF0FF) == 0x0029: return f"movt   r{n}", 2
        return f".word  0x{code:04X}", 2

    if top4 == 0x1: return f"mov.l  r{m},@({d*4},r{n})", 2
    if top4 == 0x2:
        op = code & 0xF
        if op <= 2: return f"mov.{'bwl'[op]}  r{m},@r{n}", 2
        if 4 <= op <= 6: return f"mov.{'bwl'[op-4]}  r{m},@-r{n}", 2
        ops2 = {7:"div0s",8:"tst",9:"and",0xA:"xor",0xB:"or",0xC:"cmp/str",0xD:"xtrct",0xE:"mulu.w",0xF:"muls.w"}
        if op in ops2: return f"{ops2[op]} r{m},r{n}", 2
        return f".word  0x{code:04X}", 2

    if top4 == 0x3:
        op = code & 0xF
        ops3 = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",4:"div1",5:"dmulu.l",6:"cmp/hi",7:"cmp/gt",8:"sub",0xA:"subc",0xC:"add",0xD:"dmuls.l",0xE:"addc",0xF:"addv"}
        if op in ops3: return f"{ops3[op]} r{m},r{n}", 2
        return f".word  0x{code:04X}", 2

    if top4 == 0x4:
        mid8 = code & 0xFF
        lo4 = code & 0xF
        simple4 = {0x00:"shll",0x01:"shlr",0x04:"rotl",0x05:"rotr",0x08:"shll2",0x09:"shlr2",
                   0x10:"dt",0x11:"cmp/pz",0x15:"cmp/pl",0x18:"shll8",0x19:"shlr8",
                   0x20:"shal",0x21:"shar",0x24:"rotcl",0x25:"rotcr",0x28:"shll16",0x29:"shlr16"}
        if mid8 in simple4: return f"{simple4[mid8]}  r{n}", 2
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
        if mid8 == 0x1B: return f"tas.b  @r{n}", 2
        if lo4 == 0xC: return f"shad   r{m},r{n}", 2
        if lo4 == 0xD: return f"shld   r{m},r{n}", 2
        return f".word  0x{code:04X}", 2

    if top4 == 0x5: return f"mov.l  @({d*4},r{m}),r{n}", 2
    if top4 == 0x6:
        op = code & 0xF
        if op <= 2: return f"mov.{'bwl'[op]}  @r{m},r{n}", 2
        if op == 3: return f"mov    r{m},r{n}", 2
        if 4 <= op <= 6: return f"mov.{'bwl'[op-4]}  @r{m}+,r{n}", 2
        ops6 = {7:"not",8:"swap.b",9:"swap.w",0xA:"negc",0xB:"neg",0xC:"extu.b",0xD:"extu.w",0xE:"exts.b",0xF:"exts.w"}
        if op in ops6: return f"{ops6[op]} r{m},r{n}", 2
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
                name = KNOWN_RAM.get(val, "")
                comment += f" (RAM)"
                if name: comment += f" [{name}]"
            elif is_rom_ptr(val):
                name = CAL_LABELS.get(val, KNOWN_FUNCS.get(val, ""))
                if name: comment += f" [{name}]"
                else:
                    try:
                        rv = r_f32(val)
                        if 0.001 < abs(rv) < 100000:
                            comment += f" (ROM cal: {rv:.4g})"
                    except: pass
            return f"mov.l  @(0x{target:05X}),r{n}  ; {comment}", 2
        return f"mov.l  @(0x{target:05X}),r{n}", 2

    if top4 == 0xE: return f"mov    #{sign_extend_8(i)},r{n}", 2

    if top4 == 0xF:
        lo4 = code & 0xF
        if lo4 <= 5:
            ops = ["fadd","fsub","fmul","fdiv","fcmp/eq","fcmp/gt"]
            return f"{ops[lo4]} fr{m},fr{n}", 2
        if lo4 == 6: return f"fmov.s @(r0,r{m}),fr{n}", 2
        if lo4 == 7: return f"fmov.s fr{m},@(r0,r{n})", 2
        if lo4 == 8: return f"fmov.s @r{m},fr{n}", 2
        if lo4 == 9: return f"fmov.s @r{m}+,fr{n}", 2
        if lo4 == 0xA: return f"fmov.s fr{m},@r{n}", 2
        if lo4 == 0xB: return f"fmov.s fr{m},@-r{n}", 2
        if lo4 == 0xC: return f"fmov   fr{m},fr{n}", 2
        if lo4 == 0xD:
            mid = (code >> 4) & 0xF
            fpu_s = {0:"fsts   FPUL,fr",1:"flds   fr",2:"float  FPUL,fr",3:"ftrc   fr",
                     4:"fneg   fr",5:"fabs   fr",6:"fsqrt  fr",8:"fldi0  fr",9:"fldi1  fr"}
            if mid in fpu_s:
                s = fpu_s[mid]
                if mid == 1: return f"flds   fr{n},FPUL", 2
                if mid == 3: return f"ftrc   fr{n},FPUL", 2
                return f"{s}{n}", 2
        if lo4 == 0xE: return f"fmac   fr0,fr{m},fr{n}", 2
        return f".word  0x{code:04X}", 2

    return f".word  0x{code:04X}", 2

def find_function_end(start, max_len=2048):
    i = 0
    found_epilogue = False
    while i < max_len and start + i < ROM_LEN - 3:
        opcode = r_u16(start + i)
        if opcode == 0x4F26:
            found_epilogue = True
        if found_epilogue and opcode == 0x000B:
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
    pc = start
    pool_refs = {}
    while pc < end:
        if pc + 1 >= ROM_LEN: break
        code = r_u16(pc)
        if (code >> 12) == 0xD:
            disp = code & 0xFF
            target = (pc & ~3) + 4 + disp * 4
            if target + 3 < ROM_LEN:
                pool_refs[pc] = (target, r_u32(target))
        pc += 2
    pc = start
    while pc < end:
        if pc + 1 >= ROM_LEN: break
        code = r_u16(pc)
        mnemonic, length = decode_insn(code, pc)
        lines.append(f"  {pc:06X}: {code:04X}  {mnemonic}")
        pc += length
    if pool_refs:
        lines.append(f"\n  --- Literal Pool ---")
        seen = set()
        for src_pc in sorted(pool_refs):
            target, val = pool_refs[src_pc]
            if target in seen: continue
            seen.add(target)
            fval = struct.unpack_from(">f", rom, target)[0]
            ann = ""
            if is_ram_ptr(val):
                ann = f"  RAM [{KNOWN_RAM.get(val, 'unknown')}]"
            elif is_rom_ptr(val):
                name = CAL_LABELS.get(val, KNOWN_FUNCS.get(val, ""))
                if name: ann = f"  [{name}]"
                else:
                    try:
                        rv = r_f32(val)
                        if 0.001 < abs(rv) < 100000: ann = f"  (ROM: {rv:.4g})"
                    except: pass
            elif 0x3F000000 <= val <= 0x4F000000 or 0xBF000000 <= val <= 0xCF000000:
                ann = f"  (float: {fval:.6g})"
            lines.append(f"    0x{target:06X}: 0x{val:08X}{ann}")
    return '\n'.join(lines)

def trace_subroutines(start, max_len=2048):
    end = find_function_end(start, max_len)
    calls = []
    pc = start
    while pc < end:
        if pc + 1 >= ROM_LEN: break
        code = r_u16(pc)
        if (code >> 12) == 0xB:
            target = pc + 4 + sign_extend_12(code & 0xFFF) * 2
            name = KNOWN_FUNCS.get(target, f"FUN_{target:06X}")
            calls.append((pc, target, name))
        if (code >> 12) == 0x4 and (code & 0xFF) == 0x0B:
            reg = (code >> 8) & 0xF
            for back in range(2, 42, 2):
                ca = pc - back
                if ca < 0: break
                prev = r_u16(ca)
                if (prev >> 12) == 0xD and ((prev >> 8) & 0xF) == reg:
                    d8 = prev & 0xFF
                    pool = (ca & ~3) + 4 + d8 * 4
                    if pool + 4 <= ROM_LEN:
                        tgt = r_u32(pool)
                        name = KNOWN_FUNCS.get(tgt, f"FUN_{tgt:06X}")
                        calls.append((pc, tgt, name))
                    break
        pc += 2
    return calls

def main():
    out = []
    out.append("AE5L600L Fuel Pump Control Disassembly Trace")
    out.append("=" * 78)
    out.append(f"ROM: {ROM_PATH}")
    out.append("")

    # Calibration values
    out.append("CALIBRATION VALUES:")
    out.append(f"  0x4BBAC: {r_f32(0x4BBAC):.4f}%  (Fuel Pump Duty High)")
    out.append(f"  0x4BBB0: {r_f32(0x4BBB0):.4f}%  (Fuel Pump Duty Low)")
    out.append(f"  0x4BBA0: {r_f32(0x4BBA0):.4f}%  (Fuel Pump Duty Max)")
    out.append("")

    # Main fuel pump duty control function
    out.append(disasm_function(0x4B970, "fuel_pump_duty_ctrl", max_len=512))
    calls = trace_subroutines(0x4B970, 512)
    if calls:
        out.append("\n  --- Subroutine calls ---")
        for src, tgt, name in calls:
            out.append(f"    0x{src:06X} -> {name} @ 0x{tgt:06X}")

    # Sub-function A
    out.append(disasm_function(0x4BA30, "fuel_pump_sub_A", max_len=512))
    calls_a = trace_subroutines(0x4BA30, 512)
    if calls_a:
        out.append("\n  --- Subroutine calls ---")
        for src, tgt, name in calls_a:
            out.append(f"    0x{src:06X} -> {name} @ 0x{tgt:06X}")

    # The parent function that calls fuel_pump_duty_ctrl
    out.append(disasm_function(0x47C40, "task10_call52_clol_pump", max_len=4096))
    calls_parent = trace_subroutines(0x47C40, 4096)
    if calls_parent:
        out.append("\n  --- Subroutine calls ---")
        for src, tgt, name in calls_parent:
            out.append(f"    0x{src:06X} -> {name} @ 0x{tgt:06X}")

    # Helper functions
    for addr, name in [(0x281DC, "fuel_pump_helper_A"), (0x5EA4E, "fuel_pump_helper_B"), (0x5EB1A, "fuel_pump_helper_C")]:
        out.append(disasm_function(addr, name, max_len=512))
        calls_h = trace_subroutines(addr, 512)
        if calls_h:
            out.append("\n  --- Subroutine calls ---")
            for src, tgt, nm in calls_h:
                out.append(f"    0x{src:06X} -> {nm} @ 0x{tgt:06X}")

    # Also dump the hw_port_write function
    out.append(disasm_function(0x80C6, "hw_port_write", max_len=256))

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write('\n'.join(out))
    print(f"Output written to {OUTPUT_PATH}")
    print(f"Total lines: {len(out)}")

if __name__ == "__main__":
    main()
