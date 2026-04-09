#!/usr/bin/env python3
"""
Diagnostic Task Disassembly -- AE5L600L
Deep trace of all 5 remaining diagnostic scheduler tasks:
  [53] task53_diag_monitor   @ 0x602DC
  [55] task55_mps_diag       @ 0x900B4
  [56] task56_evap_purge     @ 0x66580
  [57] task57_egr_emissions  @ 0x758CA
  [58] task58_maf_diag       @ 0x6F0B8

Also traces key sub-functions called by these tasks.
"""
import sys, io, struct, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# ── ROM loading ─────────────────────────────────────────────────────────
ROM_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "rom")
rom = None
for name in ["ae5l600l.bin"]:
    p = os.path.join(ROM_DIR, name)
    if os.path.isfile(p):
        with open(p, "rb") as f:
            rom = f.read()
        break
if rom is None:
    # fallback: any .bin
    for fn in os.listdir(ROM_DIR):
        if fn.lower().endswith(".bin"):
            with open(os.path.join(ROM_DIR, fn), "rb") as f:
                rom = f.read()
            break
if rom is None:
    print("ERROR: no ROM found", file=sys.stderr)
    sys.exit(1)

print(f"Loaded ROM: {len(rom)} bytes")

# ── Helpers ─────────────────────────────────────────────────────────────
def u8(a):  return rom[a]
def u16(a): return struct.unpack('>H', rom[a:a+2])[0]
def u32(a): return struct.unpack('>I', rom[a:a+4])[0]
def s8(v):  return v - 256 if v > 127 else v
def s12(v): return v - 4096 if v > 2047 else v
def flt(a): return struct.unpack('>f', rom[a:a+4])[0]

KNOWN_RAM = {
    0xFFFF6350: "ect_current",
    0xFFFF6354: "vehicle_speed",
    0xFFFF6624: "rpm_current",
    0xFFFF63CC: "ram_ECT",
    0xFFFF65FC: "engine_load_current",
    0xFFFF5E94: "gear_position",
    0xFFFF3234: "IAM_value",
    0xFFFF81BA: "KNOCK_FLAG",
    0xFFFF81BB: "KNOCK_BANK_FLAG",
    0xFFFF323C: "FLKC_BASE_STEP",
    0xFFFF4158: "sched_tick_count",
    0xFFFF8EDC: "sched_disable_flag",
    0xFFFF7D18: "sched_status_R1",
    0xFFFF9080: "diag_readiness_ws",
    0xFFFF9084: "diag_readiness_val",
    0xFFFF9088: "diag_readiness_in",
    0xFFFF908C: "diag_readiness_out",
    0xFFFF9090: "diag_readiness_ctrl",
    0xFFFF96A4: "maf_diag_state",
    0xFFFF96A5: "maf_diag_flag",
    0xFFFF96AC: "maf_hw_fault_a",
    0xFFFF96AE: "maf_hw_fault_b",
    0xFFFFABF4: "mps_diag_state",
    0xFFFFB71C: "dtc_master_enable",
    0xFFFF36F4: "dtc_enable_flag",
    0xFFFF36F0: "diag_status",
    0xFFFFAD52: "diag_state_E_base",
    0xFFFF85D7: "warmup_complete",
    0xFFFF67EC: "engine_run_time",
    0xFFFF65C0: "engine_state_byte",
    0xFFFF8E98: "engine_state_flag",
    0xFFFF4494: "diag_threshold_input",
    0xFFFF895C: "afl_learning_val",
    0xFFFF7FBC: "timing_correction",
    0xFFFF4130: "iat_adc_value",
    0xFFFF64F5: "throttle_pos",
    0xFFFF2368: "evap_workspace_base",
    0xFFFF4330: "egr_state_a",
    0xFFFFA198: "egr_gbr_base",
    0xFFFFA224: "egr_state_b",
    0xFFFF43B1: "egr_flag_byte",
}

KNOWN_FUNCS = {
    0x0582AC: "check_diag_state",
    0x0582D2: "check_engine_running",
    0x0584BE: "check_diag_preconditions",
    0x0584C8: "check_monitor_enable",
    0x09ED90: "dtc_set_pending",
    0x09EDEC: "dtc_clear_fault",
    0x0A1CC0: "dtc_pending_set_handler",
    0x0A240C: "dtc_confirm_set_handler",
    0x0A4FE4: "dtc_already_confirmed",
    0x0A58D6: "dtc_clear_pending_handler",
    0x0A5ABC: "dtc_clear_confirmed_handler",
    0x0A5AF0: "dtc_force_clear",
    0x0A6728: "engine_running_eval",
    0x0BE53C: "uint8_add_sat",
    0x0BE598: "table_1d_lookup",
    0x0BE628: "interp_readiness",
    0x0BE874: "low_pw_table_proc",
    0x0BECA8: "low_pw_axis_lookup",
    0x0BE9B0: "desc_read_float",
    0x0BE9A0: "desc_read_u16",
    0x0D118:  "clamp_filter",
    0x00BA84: "critical_section_enter",
    0x00BAC0: "critical_section_exit",
    0x07BF3C: "egr_sub_a",
    0x07C242: "egr_sub_b",
    0x06035A: "diag_readiness_path_a",
    0x060392: "diag_readiness_path_b",
    0x06F0CE: "maf_diag_sub_a",
    0x066D20: "evap_sub_disabled_a",
    0x066DEC: "evap_sub_disabled_b",
    0x066EBC: "evap_sub_disabled_c",
    0x066C40: "evap_test_sequence",
}

def rn(n): return f"R{n}"
def frn(n): return f"FR{n}"

def annotate_ram(val):
    name = KNOWN_RAM.get(val, "")
    return f" [{name}]" if name else ""

def annotate_func(val):
    name = KNOWN_FUNCS.get(val, "")
    return f" [{name}]" if name else ""

# ── SH-2 disassembler ──────────────────────────────────────────────────
def disasm_range(start, end, label=""):
    addr = start
    lines = []
    if label:
        lines.append(f"\n{'='*78}")
        lines.append(f"  {label}")
        lines.append(f"  0x{start:05X} - 0x{end:05X}  ({end-start} bytes)")
        lines.append(f"{'='*78}")

    while addr < end and addr + 1 < len(rom):
        op = u16(addr)
        nib = [(op >> 12) & 0xF, (op >> 8) & 0xF, (op >> 4) & 0xF, op & 0xF]
        n = nib[1]; m = nib[2]; d8 = op & 0xFF; d4 = op & 0xF
        top = nib[0]
        mnem = ""; cmt = ""

        if op == 0x0009: mnem = "nop"
        elif op == 0x000B: mnem = "rts"
        elif op == 0x0019: mnem = "div0u"
        elif op == 0x0008: mnem = "clrt"
        elif op == 0x0018: mnem = "sett"
        elif op == 0x0028: mnem = "clrmac"
        elif op == 0x001B: mnem = "sleep"
        elif op == 0x002B: mnem = "rte"
        elif top == 0x0:
            sub = nib[3]
            if sub == 0x2:
                ss = nib[2]
                if ss == 0: mnem = f"stc    SR,{rn(n)}"
                elif ss == 1: mnem = f"stc    GBR,{rn(n)}"
                elif ss == 2: mnem = f"stc    VBR,{rn(n)}"
            elif sub == 0x3:
                ss = nib[2]
                if ss == 0: mnem = f"bsrf   {rn(n)}"
                elif ss == 2: mnem = f"braf   {rn(n)}"
            elif sub == 0x4: mnem = f"mov.b  {rn(m)},@(R0,{rn(n)})"
            elif sub == 0x5: mnem = f"mov.w  {rn(m)},@(R0,{rn(n)})"
            elif sub == 0x6: mnem = f"mov.l  {rn(m)},@(R0,{rn(n)})"
            elif sub == 0x7: mnem = f"mul.l  {rn(m)},{rn(n)}"
            elif sub == 0xC: mnem = f"mov.b  @(R0,{rn(m)}),{rn(n)}"
            elif sub == 0xD: mnem = f"mov.w  @(R0,{rn(m)}),{rn(n)}"
            elif sub == 0xE: mnem = f"mov.l  @(R0,{rn(m)}),{rn(n)}"
            elif sub == 0xA:
                sr = nib[2]
                if sr == 0: mnem = f"sts    MACH,{rn(n)}"
                elif sr == 1: mnem = f"sts    MACL,{rn(n)}"
                elif sr == 2: mnem = f"sts    PR,{rn(n)}"
                elif sr == 5: mnem = f"sts    FPUL,{rn(n)}"
                elif sr == 6: mnem = f"sts    FPSCR,{rn(n)}"
            elif sub == 0x9:
                mnem = f"movt   {rn(n)}"
            elif sub == 0xF: mnem = f"mac.l  @{rn(m)}+,@{rn(n)}+"
        elif top == 0x1:
            d = nib[3]
            mnem = f"mov.l  {rn(m)},@({d*4},{rn(n)})"
        elif top == 0x2:
            sub = nib[3]
            ops2 = {
                0: f"mov.b  {rn(m)},@{rn(n)}", 1: f"mov.w  {rn(m)},@{rn(n)}",
                2: f"mov.l  {rn(m)},@{rn(n)}", 4: f"mov.b  {rn(m)},@-{rn(n)}",
                5: f"mov.w  {rn(m)},@-{rn(n)}", 6: f"mov.l  {rn(m)},@-{rn(n)}",
                7: f"div0s  {rn(m)},{rn(n)}", 8: f"tst    {rn(m)},{rn(n)}",
                9: f"and    {rn(m)},{rn(n)}", 0xA: f"xor    {rn(m)},{rn(n)}",
                0xB: f"or     {rn(m)},{rn(n)}", 0xC: f"cmp/str {rn(m)},{rn(n)}",
                0xD: f"xtrct  {rn(m)},{rn(n)}", 0xE: f"mulu.w {rn(m)},{rn(n)}",
                0xF: f"muls.w {rn(m)},{rn(n)}",
            }
            mnem = ops2.get(sub, "")
        elif top == 0x3:
            sub = nib[3]
            ops3 = {
                0: f"cmp/eq {rn(m)},{rn(n)}", 2: f"cmp/hs {rn(m)},{rn(n)}",
                3: f"cmp/ge {rn(m)},{rn(n)}", 4: f"div1   {rn(m)},{rn(n)}",
                5: f"dmulu.l {rn(m)},{rn(n)}", 6: f"cmp/hi {rn(m)},{rn(n)}",
                7: f"cmp/gt {rn(m)},{rn(n)}", 8: f"sub    {rn(m)},{rn(n)}",
                0xA: f"subc   {rn(m)},{rn(n)}", 0xC: f"add    {rn(m)},{rn(n)}",
                0xD: f"dmuls.l {rn(m)},{rn(n)}", 0xE: f"addc   {rn(m)},{rn(n)}",
            }
            mnem = ops3.get(sub, "")
        elif top == 0x4:
            sub = (nib[2] << 4) | nib[3]
            ops4 = {
                0x00: f"shll   {rn(n)}", 0x01: f"shlr   {rn(n)}",
                0x04: f"rotl   {rn(n)}", 0x05: f"rotr   {rn(n)}",
                0x08: f"shll2  {rn(n)}", 0x09: f"shlr2  {rn(n)}",
                0x10: f"dt     {rn(n)}", 0x11: f"cmp/pz {rn(n)}",
                0x15: f"cmp/pl {rn(n)}", 0x18: f"shll8  {rn(n)}",
                0x19: f"shlr8  {rn(n)}", 0x1A: f"lds    {rn(n)},MACL",
                0x20: f"shal   {rn(n)}", 0x21: f"shar   {rn(n)}",
                0x24: f"rotcl  {rn(n)}", 0x25: f"rotcr  {rn(n)}",
                0x28: f"shll16 {rn(n)}", 0x29: f"shlr16 {rn(n)}",
                0x0B: f"jsr    @{rn(n)}", 0x2B: f"jmp    @{rn(n)}",
                0x0E: f"ldc    {rn(n)},SR", 0x1E: f"ldc    {rn(n)},GBR",
                0x2E: f"ldc    {rn(n)},VBR",
                0x0A: f"lds    {rn(n)},MACH",
                0x2A: f"lds    {rn(n)},PR",
                0x06: f"lds.l  @{rn(n)}+,MACH", 0x16: f"lds.l  @{rn(n)}+,MACL",
                0x26: f"lds.l  @{rn(n)}+,PR",
                0x03: f"stc.l  SR,@-{rn(n)}", 0x13: f"stc.l  GBR,@-{rn(n)}",
                0x02: f"sts.l  MACH,@-{rn(n)}", 0x12: f"sts.l  MACL,@-{rn(n)}",
                0x22: f"sts.l  PR,@-{rn(n)}",
                0x52: f"sts.l  FPUL,@-{rn(n)}", 0x56: f"lds.l  @{rn(n)}+,FPUL",
                0x5A: f"lds    {rn(n)},FPUL",
                0x62: f"sts.l  FPSCR,@-{rn(n)}", 0x66: f"lds.l  @{rn(n)}+,FPSCR",
                0x6A: f"lds    {rn(n)},FPSCR",
            }
            mnem = ops4.get(sub, "")
            if not mnem:
                if nib[3] == 0xF: mnem = f"mac.w  @{rn(m)}+,@{rn(n)}+"
                elif nib[3] == 0xC: mnem = f"shad   {rn(m)},{rn(n)}"
                elif nib[3] == 0xD: mnem = f"shld   {rn(m)},{rn(n)}"
                elif sub == 0x07: mnem = f"ldc.l  @{rn(n)}+,SR"
                elif sub == 0x17: mnem = f"ldc.l  @{rn(n)}+,GBR"
                elif sub == 0x27: mnem = f"ldc.l  @{rn(n)}+,VBR"
        elif top == 0x5:
            d = nib[3]
            mnem = f"mov.l  @({d*4},{rn(m)}),{rn(n)}"
        elif top == 0x6:
            sub = nib[3]
            ops6 = {
                0: f"mov.b  @{rn(m)},{rn(n)}", 1: f"mov.w  @{rn(m)},{rn(n)}",
                2: f"mov.l  @{rn(m)},{rn(n)}", 3: f"mov    {rn(m)},{rn(n)}",
                4: f"mov.b  @{rn(m)}+,{rn(n)}", 5: f"mov.w  @{rn(m)}+,{rn(n)}",
                6: f"mov.l  @{rn(m)}+,{rn(n)}", 7: f"not    {rn(m)},{rn(n)}",
                8: f"swap.b {rn(m)},{rn(n)}", 9: f"swap.w {rn(m)},{rn(n)}",
                0xA: f"negc   {rn(m)},{rn(n)}", 0xB: f"neg    {rn(m)},{rn(n)}",
                0xC: f"extu.b {rn(m)},{rn(n)}", 0xD: f"extu.w {rn(m)},{rn(n)}",
                0xE: f"exts.b {rn(m)},{rn(n)}", 0xF: f"exts.w {rn(m)},{rn(n)}",
            }
            mnem = ops6.get(sub, "")
        elif top == 0x7:
            imm = s8(d8)
            mnem = f"add    #{imm},{rn(n)}"
        elif top == 0x8:
            sub = nib[1]
            if sub == 0: mnem = f"mov.b  R0,@({d4},{rn(m)})"
            elif sub == 1: mnem = f"mov.w  R0,@({d4*2},{rn(m)})"
            elif sub == 4: mnem = f"mov.b  @({d4},{rn(m)}),R0"
            elif sub == 5: mnem = f"mov.w  @({d4*2},{rn(m)}),R0"
            elif sub == 8: mnem = f"cmp/eq #{s8(d8)},R0"
            elif sub == 9:
                target = addr + 4 + s8(d8) * 2
                mnem = f"bt     0x{target:05X}"
            elif sub == 0xB:
                target = addr + 4 + s8(d8) * 2
                mnem = f"bf     0x{target:05X}"
            elif sub == 0xD:
                target = addr + 4 + s8(d8) * 2
                mnem = f"bt/s   0x{target:05X}"
            elif sub == 0xF:
                target = addr + 4 + s8(d8) * 2
                mnem = f"bf/s   0x{target:05X}"
        elif top == 0x9:
            ea = addr + 4 + d8 * 2
            val = u16(ea) if ea + 1 < len(rom) else 0
            mnem = f"mov.w  @(0x{ea:05X}),{rn(n)}"
            cmt = f"; =0x{val:04X} ({val})"
        elif top == 0xA:
            disp = op & 0xFFF
            if disp & 0x800: disp -= 0x1000
            target = addr + 4 + disp * 2
            mnem = f"bra    0x{target:05X}"
            cmt = annotate_func(target)
        elif top == 0xB:
            disp = op & 0xFFF
            if disp & 0x800: disp -= 0x1000
            target = addr + 4 + disp * 2
            mnem = f"bsr    0x{target:05X}"
            cmt = annotate_func(target)
        elif top == 0xC:
            sub = nib[1]
            if sub == 0: mnem = f"mov.b  R0,@({d8},GBR)"
            elif sub == 1: mnem = f"mov.w  R0,@({d8*2},GBR)"
            elif sub == 2: mnem = f"mov.l  R0,@({d8*4},GBR)"
            elif sub == 3: mnem = f"trapa  #{d8}"
            elif sub == 4: mnem = f"mov.b  @({d8},GBR),R0"
            elif sub == 5: mnem = f"mov.w  @({d8*2},GBR),R0"
            elif sub == 6: mnem = f"mov.l  @({d8*4},GBR),R0"
            elif sub == 7: mnem = f"mova   @(0x{(addr&~3)+4+d8*4:05X}),R0"
            elif sub == 8: mnem = f"tst    #0x{d8:02X},R0"
            elif sub == 9: mnem = f"and    #0x{d8:02X},R0"
            elif sub == 0xA: mnem = f"xor    #0x{d8:02X},R0"
            elif sub == 0xB: mnem = f"or     #0x{d8:02X},R0"
            elif sub == 0xC: mnem = f"tst.b  #0x{d8:02X},@(R0,GBR)"
            elif sub == 0xD: mnem = f"and.b  #0x{d8:02X},@(R0,GBR)"
            elif sub == 0xE: mnem = f"xor.b  #0x{d8:02X},@(R0,GBR)"
            elif sub == 0xF: mnem = f"or.b   #0x{d8:02X},@(R0,GBR)"
        elif top == 0xD:
            ea = (addr & ~3) + 4 + d8 * 4
            if ea + 3 < len(rom):
                val = u32(ea)
                mnem = f"mov.l  @(0x{ea:05X}),{rn(n)}"
                if val >= 0xFFFF0000:
                    cmt = f"; =0x{val:08X} (RAM){annotate_ram(val)}"
                elif val < 0x100000:
                    cmt = f"; =0x{val:08X} (ROM){annotate_func(val)}"
                else:
                    try:
                        fv = struct.unpack('>f', struct.pack('>I', val))[0]
                        if 1e-10 < abs(fv) < 1e10:
                            cmt = f"; =0x{val:08X} ({fv:.6g})"
                        else:
                            cmt = f"; =0x{val:08X}"
                    except:
                        cmt = f"; =0x{val:08X}"
            else:
                mnem = f"mov.l  @(0x{ea:05X}),{rn(n)}"
        elif top == 0xE:
            imm = s8(d8)
            mnem = f"mov    #{imm},{rn(n)}"
        elif top == 0xF:
            sub = nib[3]
            if sub == 0xC: mnem = f"fmov   {frn(m)},{frn(n)}"
            elif sub == 0x8: mnem = f"fmov.s @{rn(m)},{frn(n)}"
            elif sub == 0x6: mnem = f"fmov.s @(R0,{rn(m)}),{frn(n)}"
            elif sub == 0x9: mnem = f"fmov.s @{rn(m)}+,{frn(n)}"
            elif sub == 0xA: mnem = f"fmov.s {frn(m)},@{rn(n)}"
            elif sub == 0x7: mnem = f"fmov.s {frn(m)},@(R0,{rn(n)})"
            elif sub == 0xB: mnem = f"fmov.s {frn(m)},@-{rn(n)}"
            elif sub == 0x0: mnem = f"fadd   {frn(m)},{frn(n)}"
            elif sub == 0x1: mnem = f"fsub   {frn(m)},{frn(n)}"
            elif sub == 0x2: mnem = f"fmul   {frn(m)},{frn(n)}"
            elif sub == 0x3: mnem = f"fdiv   {frn(m)},{frn(n)}"
            elif sub == 0x4: mnem = f"fcmp/eq {frn(m)},{frn(n)}"
            elif sub == 0x5: mnem = f"fcmp/gt {frn(m)},{frn(n)}"
            elif sub == 0xE:
                mnem = f"fmac   FR0,{frn(m)},{frn(n)}"
            elif sub == 0xD:
                ss = nib[2]
                if ss == 0: mnem = f"float  FPUL,{frn(n)}"
                elif ss == 2: mnem = f"ftrc   {frn(n)},FPUL"
                elif ss == 1: mnem = f"fneg   {frn(n)}"
                elif ss == 4: mnem = f"fcnvsd FPUL,{frn(n)}"
                elif ss == 5: mnem = f"fcnvds {frn(n)},FPUL"
                elif ss == 8: mnem = f"sts    FPUL,{rn(n)}"
                elif ss == 0xA: mnem = f"lds    {rn(n)},FPUL"

        if not mnem:
            mnem = f".word  0x{op:04X}"

        line = f"  0x{addr:05X}:  {op:04X}  {mnem:<44s} {cmt}"
        lines.append(line)
        addr += 2

    return lines


def print_lines(lines):
    for l in lines:
        print(l)


def print_cal_floats(label, addr, count):
    """Dump calibration floats at given address."""
    print(f"\n  {label} @ 0x{addr:05X}:")
    for i in range(count):
        a = addr + i * 4
        v = u32(a)
        try:
            fv = flt(a)
            print(f"    [+{i*4:02X}] 0x{a:05X}: {fv:12.6g}  (0x{v:08X})")
        except:
            print(f"    [+{i*4:02X}] 0x{a:05X}: 0x{v:08X}")


# ════════════════════════════════════════════════════════════════════════
# TASK 53: DIAGNOSTIC MONITOR @ 0x602DC
# ════════════════════════════════════════════════════════════════════════
print("\n" + "#"*78)
print("#  TASK 53: DIAGNOSTIC MONITOR / READINESS")
print("#"*78)

print_lines(disasm_range(0x602DC, 0x6035A, "task53_diag_monitor @ 0x602DC"))
print_lines(disasm_range(0x6035A, 0x60392, "sub_6035A: readiness_path_a"))
print_lines(disasm_range(0x60392, 0x6048E, "sub_60392: readiness_path_b (main computation)"))
print_lines(disasm_range(0x6048E, 0x60530, "sub_6048E: readiness_output_filter"))

print_cal_floats("task53 readiness thresholds", 0xD9A3C, 10)


# ════════════════════════════════════════════════════════════════════════
# TASK 55: MAP SWITCH / MPS DIAGNOSTIC @ 0x900B4
# ════════════════════════════════════════════════════════════════════════
print("\n" + "#"*78)
print("#  TASK 55: MPS DIAGNOSTIC (MAP SWITCH)")
print("#"*78)

# Need to determine end of task55 -- disasm a generous range and look for rts
print_lines(disasm_range(0x900B4, 0x90200, "task55_mps_diag @ 0x900B4"))


# ════════════════════════════════════════════════════════════════════════
# TASK 56: EVAP PURGE DIAGNOSTIC @ 0x66580
# ════════════════════════════════════════════════════════════════════════
print("\n" + "#"*78)
print("#  TASK 56: EVAP PURGE DIAGNOSTIC")
print("#"*78)

print_lines(disasm_range(0x66580, 0x66C40, "task56_evap_purge @ 0x66580 (entry + dispatch)"))
print_lines(disasm_range(0x66C40, 0x66D20, "sub_66C40: evap_test_sequence"))
print_lines(disasm_range(0x66D20, 0x66DEC, "sub_66D20: evap_disabled_path_a"))
print_lines(disasm_range(0x66DEC, 0x66EBC, "sub_66DEC: evap_disabled_path_b"))
print_lines(disasm_range(0x66EBC, 0x66F80, "sub_66EBC: evap_disabled_path_c"))


# ════════════════════════════════════════════════════════════════════════
# TASK 57: EGR / EMISSIONS @ 0x758CA
# ════════════════════════════════════════════════════════════════════════
print("\n" + "#"*78)
print("#  TASK 57: EGR / EMISSIONS CONTROL")
print("#"*78)

print_lines(disasm_range(0x758CA, 0x75A00, "task57_egr_emissions @ 0x758CA (entry)"))
# Trace deeper into sub-functions
print_lines(disasm_range(0x7BF3C, 0x7C000, "sub_7BF3C: egr_sub_a"))
print_lines(disasm_range(0x7C242, 0x7C380, "sub_7C242: egr_sub_b"))

# Calibration for EGR
print(f"\n  EGR calibration bytes:")
print(f"    0xC4755: 0x{u8(0xC4755):02X} ({u8(0xC4755)})")
print(f"    0xC4753: 0x{u8(0xC4753):02X} ({u8(0xC4753)})")


# ════════════════════════════════════════════════════════════════════════
# TASK 58: MAF DIAGNOSTIC @ 0x6F0B8
# ════════════════════════════════════════════════════════════════════════
print("\n" + "#"*78)
print("#  TASK 58: MAF SENSOR DIAGNOSTIC")
print("#"*78)

print_lines(disasm_range(0x6F0B8, 0x6F0CE, "task58_maf_diag @ 0x6F0B8 (entry)"))
print_lines(disasm_range(0x6F0CE, 0x6F114, "sub_6F0CE: maf_diag_precondition_check"))
print_lines(disasm_range(0x6F114, 0x6F260, "sub_6F114: maf_diag_maturation"))
print_lines(disasm_range(0x6F260, 0x6F380, "sub_6F260: maf_hw_fault_check"))

# MAF diagnostic calibration
print(f"\n  MAF diagnostic calibration:")
print(f"    0xD8B14 (IAT threshold):       {flt(0xD8B14):.6g}")
print(f"    0xD8B18 (load threshold):      {flt(0xD8B18):.6g}")
try:
    print(f"    0xD8A40 (maturation thresh):   {flt(0xD8A40):.6g}")
except:
    print(f"    0xD8A40 (maturation thresh):   0x{u32(0xD8A40):08X}")
print(f"    0xD8A5D (hw fault thresh):     0x{u8(0xD8A5D):02X} ({u8(0xD8A5D)})")


# ════════════════════════════════════════════════════════════════════════
# SHARED DIAGNOSTIC HELPERS
# ════════════════════════════════════════════════════════════════════════
print("\n" + "#"*78)
print("#  SHARED DIAGNOSTIC HELPERS")
print("#"*78)

print_lines(disasm_range(0x582AC, 0x582D2, "check_diag_state @ 0x582AC"))
print_lines(disasm_range(0x582D2, 0x58310, "check_engine_running @ 0x582D2"))
print_lines(disasm_range(0x584BE, 0x584C8, "check_diag_preconditions @ 0x584BE"))
print_lines(disasm_range(0x584C8, 0x58530, "check_monitor_enable @ 0x584C8"))


print("\n" + "="*78)
print("  DONE — diagnostic task disassembly complete")
print("="*78)
