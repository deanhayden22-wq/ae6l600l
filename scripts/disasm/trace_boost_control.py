#!/usr/bin/env python3
"""
AE5L600L Boost Control System Subsystem Trace
===============================================
Traces wastegate duty / boost target code paths in the SH7058 ROM.

Task 51: task51_boost_wg_calc   @ 0x54852 -- Target boost + WG duty calc
Task 52: task52_boost_feedback  @ 0x549FA -- Boost feedback/trim

Known descriptors:
  - 0xAEFE4, 0xAEFF0, 0xAEFFC  (task 51)

Known calibrations:
  - 0xD6720, 0xD6724, 0xD6718, 0xD671C, 0xD6185, 0xD670C (task 51)
  - 0xD6748 (task 52)

Output: disassembly/analysis/boost_control_raw.txt
"""
import os
import struct
import sys
import math

sys.stdout.reconfigure(encoding='utf-8')

ROM_PATH = "C:/Users/Dean/Documents/GitHub/ae6l600l/rom/ae5l600l.bin"
OUTPUT_PATH = "C:/Users/Dean/Documents/GitHub/ae6l600l/disassembly/analysis/boost_control_raw.txt"

with open(ROM_PATH, "rb") as f:
    rom = f.read()

ROM_LEN = len(rom)

# GBR for boost control workspace (from task_call_graph)
GBR_BOOST = 0xFFFF8B50

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

TYPE_NAMES = {0x00:"float32", 0x02:"int8", 0x04:"int16", 0x08:"uint8", 0x0A:"uint16"}
TYPE_SIZES = {0x00:4, 0x02:1, 0x04:2, 0x08:1, 0x0A:2}

KNOWN_RAM = {
    0xFFFF6624: "rpm_current",
    0xFFFF6350: "ect_current",
    0xFFFF63F8: "iat_current",
    0xFFFF65C0: "throttle_position",
    0xFFFF6898: "manifold_pressure",
    0xFFFF69F0: "boost_pressure",
    0xFFFF61CC: "vehicle_speed",
    0xFFFF62DC: "fuel_rate",
    0xFFFF6640: "maf_voltage_left",
    0xFFFF6644: "maf_voltage_right",
    0xFFFF6810: "maf_gps",
    0xFFFF6254: "engine_state",
    0xFFFF67EC: "engine_run_time",
    0xFFFF4130: "ignition_switch_state",
    0xFFFF7448: "cl_ol_mode_flag",
    0xFFFF8B50: "boost_gbr_base",
    0xFFFF8BD0: "boost_wg_duty_output",
    0xFFFF8BC4: "boost_feedback_trim",
    0xFFFF64F5: "boost_related_flag",
}

KNOWN_FUNCS = {
    0x000BDA0C: "check_engine_running",
    0x000BE830: "table_desc_1d_float",
    0x000BE8E4: "table_desc_2d_typed",
    0x000BDBCC: "desc_read_float_safe",
    0x000BDE0C: "float_lerp",
    0x000BDE44: "float_max",
    0x000BDE64: "float_min",
    0x000BDE84: "float_clamp_range",
    0x000BDEA4: "float_safe_div",
    0x000BDF24: "uint8_add_sat",
    0x0001CF16: "engine_state_helper",
    0x000281DC: "sensor_scale_helper",
    0x00003190: "interrupt_restore",
}

KNOWN_CAL = {
    0x0C009E: "WastegateDutyCycleFreq",
    0x0C0F58: "MaxWastegateDuty",
    0x0C1150: "InitialWastegateDuty",
    0x0C1340: "TargetBoost",
    0x0D2560: "BoostLimit_FuelCut",
    0x0C0BD0: "BoostDisable_FuelCut_RPM",
    0x0C0BCC: "BoostDisable_FuelCut_Load",
    0x0C0BC8: "BoostDisable_FuelCut_BoostThreshold",
    0x0C0CF4: "TargetBoostComp_ECT",
    0x0C0C0C: "TargetBoostComp_1stGear",
    0x0C0C08: "TargetBoostComp_1stGear_SpeedDisable",
    0x0C0E3C: "TargetBoostComp_IAT",
    0x0C0EC4: "TargetBoostComp_AtmPressure",
    0x0C0BFC: "BoostControlDisable_IAM",
    0x0C0BF8: "BoostControlDisable_FineCorrection",
    0x0C0BAD: "BoostControlDisableDelay_FineCorr",
    0x0C0BD4: "TD_ActivationThresholds_TargetBoost",
    0x0C0BF0: "TD_IntegralCumulativeRange_WGDCCorr",
    0x0C0BDC: "TD_IntegralNegActivation_BoostError",
    0x0C0BE0: "TD_IntegralPosActivation_BoostError",
    0x0C0BE4: "TD_IntegralNegActivation_WGDuty",
    0x0C0C94: "InitMaxWGDutyComp_IAT",
    0x0C0CB4: "InitMaxWGDutyComp_ECT",
    0x0C0E7C: "InitMaxWGDutyComp_AtmPressure",
    0x0C0D04: "Proportional_WGDCCorr_BoostError",
    0x0C0D74: "Derivative_WGDCCorr_BoostError",
    0x0C0D3C: "Integral_WGDCCorr_BoostError",
}


# ============================================================================
# SH-2 Disassembler (from trace_avcs.py pattern)
# ============================================================================

def sign8(v):
    return v - 256 if v > 127 else v

def disasm_one(addr, gbr=GBR_BOOST):
    """Disassemble one SH-2 instruction. Returns (mnemonic, comment, is_branch)."""
    if addr + 1 >= ROM_LEN:
        return (".word  ???", "", False)
    op = r_u16(addr)
    n4 = [(op >> 12) & 0xF, (op >> 8) & 0xF, (op >> 4) & 0xF, op & 0xF]
    top = n4[0]
    n = n4[1]; m = n4[2]; d4 = n4[3]
    d8 = op & 0xFF
    rn = f"R{n}"; rm = f"R{m}"
    mn = ""; cmt = ""; is_br = False

    if op == 0x0009: mn = "nop"
    elif op == 0x000B: mn = "rts"; is_br = True
    elif op == 0x0019: mn = "div0u"
    elif op == 0x002B: mn = "rte"; is_br = True
    elif top == 0x0:
        sub = d4
        if sub == 0xC:   mn = f"mov.b  @(R0,{rm}),{rn}"
        elif sub == 0xD: mn = f"mov.w  @(R0,{rm}),{rn}"
        elif sub == 0xE: mn = f"mov.l  @(R0,{rm}),{rn}"
        elif sub == 0x4: mn = f"mov.b  {rm},@(R0,{rn})"
        elif sub == 0x5: mn = f"mov.w  {rm},@(R0,{rn})"
        elif sub == 0x6: mn = f"mov.l  {rm},@(R0,{rn})"
        elif sub == 0x7: mn = f"mul.l  {rm},{rn}"
        elif sub == 0x2:
            if m == 0: mn = f"stc    SR,{rn}"
            elif m == 1: mn = f"stc    GBR,{rn}"
            else: mn = f".word  0x{op:04X}"
        elif sub == 0xA:
            if m == 0: mn = f"sts    MACH,{rn}"
            elif m == 1: mn = f"sts    MACL,{rn}"
            elif m == 2: mn = f"sts    PR,{rn}"
            else: mn = f".word  0x{op:04X}"
        elif sub == 0x3:
            if m == 0: mn = f"bsrf   {rn}"; is_br = True
            elif m == 2: mn = f"braf   {rn}"; is_br = True
            else: mn = f".word  0x{op:04X}"
        else:
            mn = f".word  0x{op:04X}"
    elif top == 0x1:
        disp = d4 * 4
        mn = f"mov.l  {rm},@({disp},{rn})"
    elif top == 0x2:
        sub = d4
        sz_map = {0:".b",1:".w",2:".l"}
        sz_map2 = {4:".b",5:".w",6:".l"}
        if sub in sz_map:
            mn = f"mov{sz_map[sub]}  {rm},@{rn}"
        elif sub in sz_map2:
            mn = f"mov{sz_map2[sub]}  {rm},@-{rn}"
        elif sub == 8: mn = f"tst    {rm},{rn}"
        elif sub == 9: mn = f"and    {rm},{rn}"
        elif sub == 0xA: mn = f"xor    {rm},{rn}"
        elif sub == 0xB: mn = f"or     {rm},{rn}"
        elif sub == 0xD: mn = f"xtrct  {rm},{rn}"
        elif sub == 0xC: mn = f"cmp/str {rm},{rn}"
        elif sub == 0xE: mn = f"mulu.w {rm},{rn}"
        elif sub == 0xF: mn = f"muls.w {rm},{rn}"
        else: mn = f".word  0x{op:04X}"
    elif top == 0x3:
        sub = d4
        ops3 = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",4:"div1",5:"dmulu.l",
                6:"cmp/hi",7:"cmp/gt",8:"sub",0xA:"subc",0xB:"subv",
                0xC:"add",0xD:"dmuls.l",0xE:"addc",0xF:"addv"}
        if sub in ops3: mn = f"{ops3[sub]:7s}{rm},{rn}"
        else: mn = f".word  0x{op:04X}"
    elif top == 0x4:
        low8 = op & 0xFF
        tbl4 = {
            0x22: f"sts.l  PR,@-{rn}", 0x26: f"lds.l  @{rn}+,PR",
            0x13: f"stc.l  GBR,@-{rn}", 0x17: f"ldc.l  @{rn}+,GBR",
            0x1E: f"ldc    {rn},GBR",
            0x0B: f"jsr    @{rn}", 0x2B: f"jmp    @{rn}",
            0x15: f"cmp/pl {rn}", 0x11: f"cmp/pz {rn}", 0x10: f"dt     {rn}",
            0x00: f"shll   {rn}", 0x01: f"shlr   {rn}",
            0x04: f"rotl   {rn}", 0x05: f"rotr   {rn}",
            0x08: f"shll2  {rn}", 0x09: f"shlr2  {rn}",
            0x18: f"shll8  {rn}", 0x19: f"shlr8  {rn}",
            0x28: f"shll16 {rn}", 0x29: f"shlr16 {rn}",
            0x24: f"rotcl  {rn}", 0x25: f"rotcr  {rn}",
            0x20: f"shal   {rn}", 0x21: f"shar   {rn}",
            0x0A: f"lds    {rn},MACH", 0x1A: f"lds    {rn},MACL",
            0x2A: f"lds    {rn},PR",
            0x0E: f"ldc    {rn},SR", 0x2E: f"ldc    {rn},VBR",
        }
        if low8 in tbl4:
            mn = tbl4[low8]
            if low8 in (0x0B, 0x2B): is_br = True
        else:
            sub = d4
            if sub == 0xC: mn = f"shad   {rm},{rn}"
            elif sub == 0xD: mn = f"shld   {rm},{rn}"
            elif sub == 0xF: mn = f"mac.w  @{rm}+,@{rn}+"
            else: mn = f".word  0x{op:04X}"
    elif top == 0x5:
        disp = d4 * 4
        mn = f"mov.l  @({disp},{rm}),{rn}"
    elif top == 0x6:
        sub = d4
        ops6 = {
            0:"mov.b  @{m},{n}", 1:"mov.w  @{m},{n}", 2:"mov.l  @{m},{n}",
            3:"mov    {m},{n}", 4:"mov.b  @{m}+,{n}", 5:"mov.w  @{m}+,{n}",
            6:"mov.l  @{m}+,{n}", 7:"not    {m},{n}", 8:"swap.b {m},{n}",
            9:"swap.w {m},{n}", 0xA:"negc   {m},{n}", 0xB:"neg    {m},{n}",
            0xC:"extu.b {m},{n}", 0xD:"extu.w {m},{n}",
            0xE:"exts.b {m},{n}", 0xF:"exts.w {m},{n}",
        }
        if sub in ops6: mn = ops6[sub].format(m=rm, n=rn)
        else: mn = f".word  0x{op:04X}"
    elif top == 0x7:
        imm = sign8(d8)
        mn = f"add    #{imm},{rn}"
    elif top == 0x8:
        sub = n
        if sub == 0x0:   mn = f"mov.b  R0,@({d8},{rm})"
        elif sub == 0x1: mn = f"mov.w  R0,@({d8*2},{rm})"
        elif sub == 0x4: mn = f"mov.b  @({d8},{rm}),R0"
        elif sub == 0x5: mn = f"mov.w  @({d8*2},{rm}),R0"
        elif sub == 0x8:
            imm = sign8(d8)
            mn = f"cmp/eq #{imm},R0"
        elif sub in (0x9, 0xB, 0xD, 0xF):
            disp = sign8(d8) * 2 + 4
            target = addr + disp
            br_names = {0x9:"bt", 0xB:"bf", 0xD:"bt/s", 0xF:"bf/s"}
            mn = f"{br_names[sub]}    0x{target:06X}"
            is_br = (sub in (0x9, 0xB))
        else: mn = f".word  0x{op:04X}"
    elif top == 0x9:
        disp = d8 * 2
        pool_addr = addr + 4 + disp
        if pool_addr + 1 < ROM_LEN:
            val = r_u16(pool_addr)
            mn = f"mov.w  @(0x{pool_addr:06X}),{rn}"
            cmt = f"  ; #{val} (0x{val:04X})"
        else:
            mn = f"mov.w  @(?),{rn}"
    elif top == 0xA:
        disp12 = op & 0xFFF
        if disp12 > 0x7FF: disp12 -= 0x1000
        target = addr + 4 + disp12 * 2
        mn = f"bra    0x{target:06X}"; is_br = True
    elif top == 0xB:
        disp12 = op & 0xFFF
        if disp12 > 0x7FF: disp12 -= 0x1000
        target = addr + 4 + disp12 * 2
        mn = f"bsr    0x{target:06X}"; is_br = True
    elif top == 0xC:
        sub = n
        if sub == 0x0:
            disp = d8; ga = gbr + disp
            mn = f"mov.b  R0,@(0x{disp:02X},GBR)"; cmt = f"  ; [{ga:08X}]"
        elif sub == 0x1:
            disp = d8*2; ga = gbr + disp
            mn = f"mov.w  R0,@(0x{disp:04X},GBR)"; cmt = f"  ; [{ga:08X}]"
        elif sub == 0x2:
            disp = d8*4; ga = gbr + disp
            mn = f"mov.l  R0,@(0x{disp:04X},GBR)"; cmt = f"  ; [{ga:08X}]"
        elif sub == 0x4:
            disp = d8; ga = gbr + disp
            mn = f"mov.b  @(0x{disp:02X},GBR),R0"; cmt = f"  ; [{ga:08X}]"
        elif sub == 0x5:
            disp = d8*2; ga = gbr + disp
            mn = f"mov.w  @(0x{disp:04X},GBR),R0"; cmt = f"  ; [{ga:08X}]"
        elif sub == 0x6:
            disp = d8*4; ga = gbr + disp
            mn = f"mov.l  @(0x{disp:04X},GBR),R0"; cmt = f"  ; [{ga:08X}]"
        elif sub == 0x7:
            disp = d8*4; pa = ((addr + 4) & ~3) + disp
            mn = f"mova   @(0x{pa:06X}),R0"
        elif sub == 0x8: mn = f"tst    #0x{d8:02X},R0"
        elif sub == 0x9: mn = f"and    #0x{d8:02X},R0"
        elif sub == 0xA: mn = f"xor    #0x{d8:02X},R0"
        elif sub == 0xB: mn = f"or     #0x{d8:02X},R0"
        elif sub == 0xD: mn = f"and.b  #0x{d8:02X},@(R0,GBR)"
        elif sub == 0xF: mn = f"or.b   #0x{d8:02X},@(R0,GBR)"
        else: mn = f".word  0x{op:04X}"
    elif top == 0xD:
        disp = d8 * 4
        pool_addr = ((addr + 4) & ~3) + disp
        if pool_addr + 3 < ROM_LEN:
            val = r_u32(pool_addr)
            mn = f"mov.l  @(0x{pool_addr:06X}),{rn}"
            if val in KNOWN_RAM:
                cmt = f"  ; =0x{val:08X} ({KNOWN_RAM[val]})"
            elif val in KNOWN_FUNCS:
                cmt = f"  ; =0x{val:08X} ({KNOWN_FUNCS[val]})"
            elif val in KNOWN_CAL:
                cmt = f"  ; =0x{val:08X} ({KNOWN_CAL[val]})"
            elif 0xFFFF0000 <= val <= 0xFFFFFFFF:
                cmt = f"  ; =0x{val:08X} (RAM)"
            elif 0xFFFE0000 <= val < 0xFFFF0000:
                cmt = f"  ; =0x{val:08X} (I/O)"
            elif 0x000A0000 <= val <= 0x000BFFFF:
                cmt = f"  ; =0x{val:08X} (desc)"
            elif 0x000C0000 <= val <= 0x000DFFFF:
                cmt = f"  ; =0x{val:08X} (cal)"
                try:
                    fv = r_f32(val)
                    if not math.isnan(fv) and abs(fv) < 1e12:
                        cmt += f" val={fv}"
                except: pass
            elif val < 0x00200000:
                cmt = f"  ; =0x{val:08X} (code)"
            else:
                cmt = f"  ; =0x{val:08X}"
        else:
            mn = f"mov.l  @(?),{rn}"
    elif top == 0xE:
        imm = sign8(d8)
        mn = f"mov    #{imm},{rn}"
    elif top == 0xF:
        sub = d4
        fn = f"FR{n}"; fm = f"FR{m}"
        fpu = {
            0x0: f"fadd   {fm},{fn}", 0x1: f"fsub   {fm},{fn}",
            0x2: f"fmul   {fm},{fn}", 0x3: f"fdiv   {fm},{fn}",
            0x4: f"fcmp/eq {fm},{fn}", 0x5: f"fcmp/gt {fm},{fn}",
            0x6: f"fmov.s @(R0,R{m}),{fn}", 0x7: f"fmov.s {fm},@(R0,R{n})",
            0x8: f"fmov.s @R{m},{fn}", 0x9: f"fmov.s @R{m}+,{fn}",
            0xA: f"fmov.s {fm},@R{n}", 0xB: f"fmov.s {fm},@-R{n}",
            0xC: f"fmov   {fm},{fn}",
        }
        if sub in fpu:
            mn = fpu[sub]
        elif sub == 0xD:
            fpuD = {
                0x0: f"fsts   FPUL,{fn}", 0x1: f"flds   {fn},FPUL",
                0x2: f"float  FPUL,{fn}", 0x3: f"ftrc   {fn},FPUL",
                0x4: f"fneg   {fn}", 0x5: f"fabs   {fn}",
                0x6: f"fsqrt  {fn}", 0x8: f"fldi0  {fn}", 0x9: f"fldi1  {fn}",
            }
            mn = fpuD.get(m, f".word  0x{op:04X}")
        elif sub == 0xE: mn = f"fmac   FR0,{fm},{fn}"
        else:
            mn = f".word  0x{op:04X}"

    if not mn: mn = f".word  0x{op:04X}"
    return (mn, cmt, is_br)


def disasm_range(start, count, out, gbr=GBR_BOOST):
    """Disassemble 'count' instructions starting at 'start', write to out."""
    addr = start
    for _ in range(count):
        if addr + 1 >= ROM_LEN: break
        op = r_u16(addr)
        mn, cmt, _ = disasm_one(addr, gbr)
        out.write(f"  {addr:06X}: {op:04X}  {mn}{cmt}\n")
        addr += 2


def collect_literals(start, count):
    """Collect all literal pool values referenced in a code region."""
    literals = {}
    addr = start
    for _ in range(count):
        if addr + 1 >= ROM_LEN: break
        op = r_u16(addr)
        top = (op >> 12) & 0xF
        if top == 0xD:
            d8 = op & 0xFF
            pool_addr = ((addr + 4) & ~3) + d8 * 4
            if pool_addr + 3 < ROM_LEN:
                val = r_u32(pool_addr)
                reg = (op >> 8) & 0xF
                literals[addr] = (pool_addr, val, reg)
        elif top == 0x9:
            d8 = op & 0xFF
            pool_addr = addr + 4 + d8 * 2
            if pool_addr + 1 < ROM_LEN:
                val = r_u16(pool_addr)
                reg = (op >> 8) & 0xF
                literals[addr] = (pool_addr, val, reg)
        addr += 2
    return literals


# ============================================================================
# Search helpers
# ============================================================================

def find_u32_refs(target_val):
    """Find all addresses where a u32 == target_val appears."""
    results = []
    for a in range(0, ROM_LEN - 3, 4):
        if r_u32(a) == target_val:
            results.append(a)
    return results


def find_movl_pc_refs(target_val):
    """Find mov.l @(disp,PC),Rn instructions that load target_val."""
    results = []
    pool_addrs = find_u32_refs(target_val)
    for pool_addr in pool_addrs:
        for pc in range(max(0, pool_addr - 1024), pool_addr, 2):
            op = r_u16(pc)
            if (op >> 12) == 0xD:
                d8 = op & 0xFF
                calc_pool = ((pc + 4) & ~3) + d8 * 4
                if calc_pool == pool_addr:
                    reg = (op >> 8) & 0xF
                    results.append((pc, reg, pool_addr))
    return results


# ============================================================================
# Descriptor parsing
# ============================================================================

def parse_2d_desc(addr):
    rows = rom[addr + 1]
    cols = rom[addr + 3]
    y_ptr = r_u32(addr + 4)
    x_ptr = r_u32(addr + 8)
    d_ptr = r_u32(addr + 12)
    dtype = rom[addr + 16]
    scale = r_f32(addr + 20)
    bias = r_f32(addr + 24)
    return {"rows":rows, "cols":cols, "y_ptr":y_ptr, "x_ptr":x_ptr,
            "d_ptr":d_ptr, "dtype":dtype,
            "dtype_name":TYPE_NAMES.get(dtype, f"?{dtype}"),
            "scale":scale, "bias":bias}


def parse_1d_desc(addr):
    size = rom[addr + 1]
    dtype = rom[addr + 2]
    axis_ptr = r_u32(addr + 4)
    data_ptr = r_u32(addr + 8)
    scale = r_f32(addr + 12)
    bias = r_f32(addr + 16)
    return {"size":size, "dtype":dtype,
            "dtype_name":TYPE_NAMES.get(dtype, f"?{dtype}"),
            "axis_ptr":axis_ptr, "data_ptr":data_ptr,
            "scale":scale, "bias":bias}


def read_axis(ptr, count):
    return [r_f32(ptr + i*4) for i in range(count)]


def read_data(ptr, count, dtype, scale, bias):
    raw = []
    phys = []
    esz = TYPE_SIZES.get(dtype, 1)
    for i in range(count):
        a = ptr + i * esz
        if dtype == 0x00:    rv = r_f32(a)
        elif dtype == 0x02:  rv = rom[a]; rv = rv - 256 if rv > 127 else rv
        elif dtype == 0x04:  rv = r_s16(a)
        elif dtype == 0x08:  rv = rom[a]
        elif dtype == 0x0A:  rv = r_u16(a)
        else:                rv = rom[a]
        raw.append(rv)
        phys.append(rv if dtype == 0x00 else rv * scale + bias)
    return raw, phys


def format_2d_table(y_axis, x_axis, data_2d, label, fmt="{:8.2f}"):
    lines = []
    hdr = f"{'':>10s}"
    for xv in x_axis:
        hdr += f"{xv:>8.1f}"
    lines.append(hdr)
    lines.append("-" * len(hdr))
    for ri, yv in enumerate(y_axis):
        row = f"{yv:>10.1f}"
        for ci in range(len(x_axis)):
            row += fmt.format(data_2d[ri][ci])
        lines.append(row)
    return "\n".join(lines)


def annotate_io(addr):
    io_map = {
        0xFFFE3802: " (PADRL - Port A Data)",
        0xFFFE3812: " (PBDRL - Port B Data)",
        0xFFFE3822: " (PCDRL - Port C Data)",
        0xFFFE3832: " (PDDRL - Port D Data)",
        0xFFFE3842: " (PEDRL - Port E Data)",
        0xFFFE3852: " (PFDRL - Port F Data)",
        0xFFFE4000: " (ATU TSTR - Timer Start)",
    }
    if addr in io_map:
        return io_map[addr]
    if 0xFFFE3800 <= addr < 0xFFFE3900:
        port_num = (addr - 0xFFFE3800) // 0x10
        port_names = "ABCDEFGHJK"
        if port_num < len(port_names):
            offset = (addr - 0xFFFE3800) % 0x10
            return f" (Port {port_names[port_num]} +0x{offset:X})"
    if 0xFFFE4000 <= addr < 0xFFFE4400:
        return f" (ATU Timer +0x{addr - 0xFFFE4000:03X})"
    if 0xFFFE6000 <= addr < 0xFFFE6100:
        return f" (MTU2 +0x{addr - 0xFFFE6000:03X})"
    if 0xFFFEC000 <= addr < 0xFFFEC100:
        return f" (A/D +0x{addr - 0xFFFEC000:03X})"
    return ""


# ============================================================================
# Main analysis
# ============================================================================

def main():
    out_dir = os.path.dirname(OUTPUT_PATH)
    os.makedirs(out_dir, exist_ok=True)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as out:
        out.write("=" * 78 + "\n")
        out.write("AE5L600L BOOST CONTROL SYSTEM -- Raw Trace\n")
        out.write("SH7058 (SH-2, Big-Endian)\n")
        out.write("=" * 78 + "\n\n")
        out.write(f"ROM: {ROM_PATH}\n")
        out.write(f"ROM size: {ROM_LEN} bytes (0x{ROM_LEN:X})\n")
        out.write(f"GBR (boost workspace): 0x{GBR_BOOST:08X}\n")
        out.write(f"Generated by trace_boost_control.py\n\n")

        boost_code_regions = []

        # ==================================================================
        # PART 1: Task 51 -- Boost/WG Target Calculation
        # ==================================================================
        out.write("=" * 78 + "\n")
        out.write("PART 1: TASK 51 -- BOOST/WASTEGATE TARGET CALCULATION\n")
        out.write("Entry: 0x54852 (task51_boost_wg_calc)\n")
        out.write("=" * 78 + "\n\n")

        # Disassemble task 51 -- generous range to catch full function + literal pool
        t51_start = 0x54852
        t51_count = 220  # ~440 bytes, should cover function + literals
        boost_code_regions.append((t51_start, t51_start + t51_count * 2))

        out.write(f"--- Full disassembly: 0x{t51_start:06X} ({t51_count} instructions) ---\n\n")
        disasm_range(t51_start, t51_count, out)

        out.write(f"\n--- Literal pool values ---\n\n")
        lits = collect_literals(t51_start, t51_count)
        for la in sorted(lits.keys()):
            pa, val, reg = lits[la]
            ann = ""
            if val in KNOWN_RAM:     ann = f" ({KNOWN_RAM[val]})"
            elif val in KNOWN_FUNCS: ann = f" ({KNOWN_FUNCS[val]})"
            elif val in KNOWN_CAL:   ann = f" ({KNOWN_CAL[val]})"
            elif is_ram_ptr(val):    ann = " (RAM)"
            elif 0xFFFE0000 <= val < 0xFFFF0000: ann = " (I/O)"
            elif 0x000A0000 <= val <= 0x000BFFFF: ann = " (desc)"
            elif 0x000C0000 <= val <= 0x000DFFFF:
                ann = " (cal)"
                try:
                    fv = r_f32(val)
                    if not math.isnan(fv) and abs(fv) < 1e12:
                        ann += f" val={fv}"
                except: pass
            elif is_rom_ptr(val):    ann = " (code)"
            out.write(f"  0x{la:06X} -> pool 0x{pa:06X} = 0x{val:08X} -> R{reg}{ann}\n")
        out.write("\n")

        # ==================================================================
        # PART 2: Task 52 -- Boost Feedback/Trim
        # ==================================================================
        out.write("=" * 78 + "\n")
        out.write("PART 2: TASK 52 -- BOOST FEEDBACK / TRIM\n")
        out.write("Entry: 0x549FA (task52_boost_feedback)\n")
        out.write("=" * 78 + "\n\n")

        t52_start = 0x549FA
        t52_count = 120  # smaller task
        boost_code_regions.append((t52_start, t52_start + t52_count * 2))

        out.write(f"--- Full disassembly: 0x{t52_start:06X} ({t52_count} instructions) ---\n\n")
        disasm_range(t52_start, t52_count, out)

        out.write(f"\n--- Literal pool values ---\n\n")
        lits2 = collect_literals(t52_start, t52_count)
        for la in sorted(lits2.keys()):
            pa, val, reg = lits2[la]
            ann = ""
            if val in KNOWN_RAM:     ann = f" ({KNOWN_RAM[val]})"
            elif val in KNOWN_FUNCS: ann = f" ({KNOWN_FUNCS[val]})"
            elif val in KNOWN_CAL:   ann = f" ({KNOWN_CAL[val]})"
            elif is_ram_ptr(val):    ann = " (RAM)"
            elif 0xFFFE0000 <= val < 0xFFFF0000: ann = " (I/O)"
            elif 0x000A0000 <= val <= 0x000BFFFF: ann = " (desc)"
            elif 0x000C0000 <= val <= 0x000DFFFF:
                ann = " (cal)"
                try:
                    fv = r_f32(val)
                    if not math.isnan(fv) and abs(fv) < 1e12:
                        ann += f" val={fv}"
                except: pass
            elif is_rom_ptr(val):    ann = " (code)"
            out.write(f"  0x{la:06X} -> pool 0x{pa:06X} = 0x{val:08X} -> R{reg}{ann}\n")
        out.write("\n")

        # ==================================================================
        # PART 3: Decode boost control descriptors
        # ==================================================================
        out.write("=" * 78 + "\n")
        out.write("PART 3: BOOST CONTROL DESCRIPTORS\n")
        out.write("=" * 78 + "\n\n")

        boost_descs = {
            0x0AEFE4: "Task51 Descriptor A",
            0x0AEFF0: "Task51 Descriptor B (RPM-indexed)",
            0x0AEFFC: "Task51 Descriptor C",
        }

        for desc_addr, desc_name in boost_descs.items():
            out.write(f"--- {desc_name} @ 0x{desc_addr:06X} ---\n\n")
            out.write(f"  Raw bytes:\n")
            for i in range(0, 28, 4):
                if desc_addr + i + 3 < ROM_LEN:
                    val = r_u32(desc_addr + i)
                    out.write(f"    +0x{i:02X}: 0x{val:08X}\n")

            b3 = rom[desc_addr + 3]
            if b3 != 0:
                desc = parse_2d_desc(desc_addr)
                out.write(f"  2D table: {desc['rows']}x{desc['cols']}, "
                          f"type={desc['dtype_name']}, "
                          f"scale={desc['scale']:.6f}, bias={desc['bias']:.2f}\n")
                y = read_axis(desc['y_ptr'], desc['rows'])
                x = read_axis(desc['x_ptr'], desc['cols'])
                out.write(f"  Y-axis @ 0x{desc['y_ptr']:06X}: {', '.join(f'{v:.2f}' for v in y)}\n")
                out.write(f"  X-axis @ 0x{desc['x_ptr']:06X}: {', '.join(f'{v:.2f}' for v in x)}\n")
                raw, phys = read_data(desc['d_ptr'], desc['rows']*desc['cols'],
                                      desc['dtype'], desc['scale'], desc['bias'])
                data_2d = []
                for ri in range(desc['rows']):
                    data_2d.append(phys[ri*desc['cols']:(ri+1)*desc['cols']])
                out.write(f"  Data @ 0x{desc['d_ptr']:06X}:\n\n")
                out.write("  " + format_2d_table(y, x, data_2d, desc_name) + "\n\n")
            else:
                desc = parse_1d_desc(desc_addr)
                out.write(f"  1D table: size={desc['size']}, "
                          f"type={desc['dtype_name']}, "
                          f"scale={desc['scale']:.6f}, bias={desc['bias']:.2f}\n")
                if is_rom_ptr(desc['axis_ptr']) and is_rom_ptr(desc['data_ptr']):
                    axis = read_axis(desc['axis_ptr'], desc['size'])
                    out.write(f"  Axis @ 0x{desc['axis_ptr']:06X}: {', '.join(f'{v:.2f}' for v in axis)}\n")
                    raw, phys = read_data(desc['data_ptr'], desc['size'],
                                          desc['dtype'], desc['scale'], desc['bias'])
                    out.write(f"  Data @ 0x{desc['data_ptr']:06X}:\n")
                    for i in range(desc['size']):
                        out.write(f"    [{i:2d}] axis={axis[i]:10.2f}  raw={raw[i]:6}  phys={phys[i]:10.4f}\n")
                else:
                    out.write(f"  Axis ptr: 0x{desc['axis_ptr']:08X}, Data ptr: 0x{desc['data_ptr']:08X}\n")
                    out.write(f"  (pointers may be invalid -- check if this is a control descriptor)\n")
            out.write("\n")

        # Also scan boost-indexed descriptors from the named_descriptors list
        out.write("--- Additional boost-indexed descriptors ---\n\n")
        boost_1d_descs = [
            0x0AA820, 0x0AB430, 0x0AB674, 0x0AC2D0, 0x0AC2E8,
            0x0AC300, 0x0AC318, 0x0AC498, 0x0AC56C, 0x0AC594,
            0x0AC698, 0x0AC6AC, 0x0AC6D4, 0x0ACCBC, 0x0ACCD0,
            0x0ACCE4, 0x0ACCF8, 0x0ACD0C, 0x0ACD20, 0x0AD37C,
            0x0AD47C, 0x0AD494, 0x0AD4AC, 0x0ADAFC, 0x0ADDCC,
            0x0AE14C,
        ]
        boost_2d_descs = [0x0AF058, 0x0AF074, 0x0AB058]

        out.write(f"  26 x 1D_Boost descriptors + 2 x 2D_Boostxrange + 1 x 2D_RPMxBoost\n")
        out.write(f"  (Decoding first few for cross-reference)\n\n")

        for desc_addr in boost_1d_descs[:6]:
            b3 = rom[desc_addr + 3]
            if b3 == 0:
                desc = parse_1d_desc(desc_addr)
                out.write(f"  1D @ 0x{desc_addr:06X}: size={desc['size']}, "
                          f"type={desc['dtype_name']}, "
                          f"scale={desc['scale']:.6f}, bias={desc['bias']:.2f}")
                if is_rom_ptr(desc['axis_ptr']):
                    axis = read_axis(desc['axis_ptr'], min(desc['size'], 4))
                    out.write(f"  axis=[{', '.join(f'{v:.1f}' for v in axis)}...]")
                out.write("\n")

        for desc_addr in boost_2d_descs:
            b3 = rom[desc_addr + 3]
            if b3 != 0:
                desc = parse_2d_desc(desc_addr)
                out.write(f"  2D @ 0x{desc_addr:06X}: {desc['rows']}x{desc['cols']}, "
                          f"type={desc['dtype_name']}, "
                          f"scale={desc['scale']:.6f}, bias={desc['bias']:.2f}\n")
        out.write("\n")

        # ==================================================================
        # PART 4: Calibration values at known boost addresses
        # ==================================================================
        out.write("=" * 78 + "\n")
        out.write("PART 4: BOOST CALIBRATION VALUES\n")
        out.write("=" * 78 + "\n\n")

        # Task 51 calibrations
        task51_cals = [
            0xD6720, 0xD6724, 0xD6718, 0xD671C, 0xD6185, 0xD670C,
            0xD670E, 0xD6710,  # +2 from task_call_graph
        ]
        out.write("--- Task 51 calibration references ---\n\n")
        for addr in task51_cals:
            try:
                fv = r_f32(addr)
                u32 = r_u32(addr)
                u16 = r_u16(addr)
                u8 = r_u8(addr)
                out.write(f"  0x{addr:06X}: u32=0x{u32:08X}  u16=0x{u16:04X}  u8=0x{u8:02X}")
                if not math.isnan(fv) and abs(fv) < 1e12:
                    out.write(f"  float={fv:.6f}")
                # Cross-ref with known cal names
                if addr in KNOWN_CAL:
                    out.write(f"  ({KNOWN_CAL[addr]})")
                out.write("\n")
            except:
                out.write(f"  0x{addr:06X}: (read error)\n")

        out.write(f"\n--- Task 52 calibration references ---\n\n")
        t52_cals = [0xD6748]
        for addr in t52_cals:
            try:
                fv = r_f32(addr)
                u32 = r_u32(addr)
                u16 = r_u16(addr)
                u8 = r_u8(addr)
                out.write(f"  0x{addr:06X}: u32=0x{u32:08X}  u16=0x{u16:04X}  u8=0x{u8:02X}")
                if not math.isnan(fv) and abs(fv) < 1e12:
                    out.write(f"  float={fv:.6f}")
                if addr in KNOWN_CAL:
                    out.write(f"  ({KNOWN_CAL[addr]})")
                out.write("\n")
            except:
                out.write(f"  0x{addr:06X}: (read error)\n")

        out.write(f"\n--- Known boost calibration table values ---\n\n")
        for addr in sorted(KNOWN_CAL.keys()):
            try:
                fv = r_f32(addr)
                u32 = r_u32(addr)
                u16 = r_u16(addr)
                u8 = r_u8(addr)
                out.write(f"  0x{addr:06X} ({KNOWN_CAL[addr]:45s}): "
                          f"u32=0x{u32:08X}  u16=0x{u16:04X}  u8=0x{u8:02X}")
                if not math.isnan(fv) and abs(fv) < 1e12:
                    out.write(f"  float={fv:.6f}")
                out.write("\n")
            except:
                out.write(f"  0x{addr:06X} ({KNOWN_CAL[addr]}): (read error)\n")
        out.write("\n")

        # ==================================================================
        # PART 5: Wider code scan -- related boost functions
        # ==================================================================
        out.write("=" * 78 + "\n")
        out.write("PART 5: RELATED BOOST CODE (WIDER SCAN)\n")
        out.write("=" * 78 + "\n\n")

        # Scan area around tasks 51/52 for adjacent functions
        # Also check cross-references mentioned in explore
        related_addrs = [
            (0x4FD5E, "boost_related_call_A"),
            (0x4F368, "boost_integration_point"),
            (0x4F206, "boost_control_logic"),
        ]

        for raddr, rname in related_addrs:
            out.write(f"--- {rname} @ 0x{raddr:06X} ---\n\n")
            region_start = max(0, (raddr - 40) & ~1)
            disasm_range(region_start, 60, out)
            out.write("\n")
            lits_r = collect_literals(region_start, 60)
            if lits_r:
                out.write("  Literals:\n")
                for la in sorted(lits_r.keys()):
                    pa, val, reg = lits_r[la]
                    ann = ""
                    if val in KNOWN_RAM: ann = f" ({KNOWN_RAM[val]})"
                    elif val in KNOWN_FUNCS: ann = f" ({KNOWN_FUNCS[val]})"
                    elif val in KNOWN_CAL: ann = f" ({KNOWN_CAL[val]})"
                    elif is_ram_ptr(val): ann = " (RAM)"
                    elif 0x000A0000 <= val <= 0x000BFFFF: ann = " (desc)"
                    elif 0x000C0000 <= val <= 0x000DFFFF: ann = " (cal)"
                    out.write(f"    0x{la:06X} -> 0x{val:08X} R{reg}{ann}\n")
            out.write("\n")

        # ==================================================================
        # PART 6: RAM and I/O reference summary
        # ==================================================================
        out.write("=" * 78 + "\n")
        out.write("PART 6: RAM AND I/O REFERENCE SUMMARY\n")
        out.write("=" * 78 + "\n\n")

        all_ram = {}
        all_io = {}
        all_cal = {}
        all_desc = {}
        all_code = {}

        for region_start, region_end in boost_code_regions:
            lits_all = collect_literals(region_start, (region_end - region_start) // 2)
            for la in sorted(lits_all.keys()):
                pa, val, reg = lits_all[la]
                if is_ram_ptr(val):
                    all_ram.setdefault(val, []).append(la)
                elif 0xFFFE0000 <= val < 0xFFFF0000:
                    all_io.setdefault(val, []).append(la)
                elif 0x000A0000 <= val <= 0x000BFFFF:
                    all_desc.setdefault(val, []).append(la)
                elif 0x000C0000 <= val <= 0x000DFFFF:
                    all_cal.setdefault(val, []).append(la)
                elif is_rom_ptr(val) and val < 0x00200000:
                    all_code.setdefault(val, []).append(la)

        out.write("--- RAM addresses ---\n\n")
        for val in sorted(all_ram.keys()):
            refs = all_ram[val]
            name = KNOWN_RAM.get(val, "")
            out.write(f"  0x{val:08X}  {name:30s}  refs: {', '.join(f'0x{a:06X}' for a in refs)}\n")

        out.write(f"\n  Total unique RAM: {len(all_ram)}\n\n")

        out.write("--- I/O addresses ---\n\n")
        for val in sorted(all_io.keys()):
            refs = all_io[val]
            ann = annotate_io(val)
            out.write(f"  0x{val:08X}{ann}  refs: {', '.join(f'0x{a:06X}' for a in refs)}\n")

        out.write(f"\n  Total unique I/O: {len(all_io)}\n\n")

        out.write("--- Descriptor addresses ---\n\n")
        for val in sorted(all_desc.keys()):
            refs = all_desc[val]
            out.write(f"  0x{val:06X}  refs: {', '.join(f'0x{a:06X}' for a in refs)}\n")

        out.write(f"\n  Total unique descriptors: {len(all_desc)}\n\n")

        out.write("--- Calibration addresses ---\n\n")
        for val in sorted(all_cal.keys()):
            refs = all_cal[val]
            name = KNOWN_CAL.get(val, "")
            try:
                fv = r_f32(val)
                fstr = f"  float={fv:.4f}" if not math.isnan(fv) and abs(fv) < 1e12 else ""
            except:
                fstr = ""
            out.write(f"  0x{val:06X}  {name:45s}{fstr}  refs: {', '.join(f'0x{a:06X}' for a in refs)}\n")

        out.write(f"\n  Total unique cal: {len(all_cal)}\n\n")

        out.write("--- Code/function addresses ---\n\n")
        for val in sorted(all_code.keys()):
            refs = all_code[val]
            name = KNOWN_FUNCS.get(val, "")
            out.write(f"  0x{val:06X}  {name:30s}  refs: {', '.join(f'0x{a:06X}' for a in refs)}\n")

        out.write(f"\n  Total unique code refs: {len(all_code)}\n\n")

        # ==================================================================
        # PART 7: Extended code -- scan before task 51 for preamble
        # ==================================================================
        out.write("=" * 78 + "\n")
        out.write("PART 7: EXTENDED CONTEXT (PRE-TASK51 AND POST-TASK52)\n")
        out.write("=" * 78 + "\n\n")

        # Look at code before task 51 entry for setup/dispatcher
        pre_start = max(0, 0x54800)
        pre_count = (0x54852 - pre_start) // 2
        if pre_count > 0:
            out.write(f"--- Pre-task51 (0x{pre_start:06X} - 0x54852) ---\n\n")
            disasm_range(pre_start, pre_count, out)
            out.write("\n")

        # Look at code after task 52 ends
        post_start = 0x54AE0
        out.write(f"--- Post-task52 (0x{post_start:06X}, 60 insns) ---\n\n")
        disasm_range(post_start, 60, out)
        out.write("\n")

        # ==================================================================
        # Summary
        # ==================================================================
        out.write("=" * 78 + "\n")
        out.write("SUMMARY\n")
        out.write("=" * 78 + "\n\n")
        out.write(f"Task 51 entry: 0x{t51_start:06X} (boost/WG target calc)\n")
        out.write(f"Task 52 entry: 0x{t52_start:06X} (boost feedback/trim)\n")
        out.write(f"GBR base: 0x{GBR_BOOST:08X}\n")
        out.write(f"Boost code regions traced:\n")
        for s, e in boost_code_regions:
            out.write(f"  0x{s:06X} - 0x{e:06X}\n")
        out.write(f"\nUnique RAM addresses: {len(all_ram)}\n")
        out.write(f"Unique I/O addresses: {len(all_io)}\n")
        out.write(f"Unique descriptors:   {len(all_desc)}\n")
        out.write(f"Unique cal addresses: {len(all_cal)}\n")
        out.write(f"Unique code refs:     {len(all_code)}\n")

    print(f"Output written to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
