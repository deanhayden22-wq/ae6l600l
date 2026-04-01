#!/usr/bin/env python3
"""
Knock detection and FLKC (Fine Learning Knock Correction) disassembly analysis.
AE5L600L - 2013 Subaru WRX - SH7058 / SH-2 architecture

Functions covered:
  0x043750  knock_wrapper          - cylinder gate + status check
  0x043782  knock_detector         - signal processing + threshold comparison
  0x043B7C  knock_wrapper_cont     - post-detector continuation
  0x043D68  task12_knock_post      - post-processing task
  0x04438C  task11_knock_flag_read - scheduler entry for knock flag read
  0x045BFE  flkc_path_J            - fast-response FLKC retard
  0x0463BA  flkc_paths_FG          - sustained-knock FLKC state machine
"""
import os
import struct
import sys

ROM_PATH = os.path.join(os.path.dirname(__file__), "..", "rom", "ae5l600l.bin")

# ---------------------------------------------------------------------------
# Known names
# ---------------------------------------------------------------------------
RAM_NAMES = {
    # ADC raw
    0xFFFF4042: "adc_raw_ADDR15_MAF",
    0xFFFF4050: "adc_raw_ADDR22_MAP",
    0xFFFF405C: "adc_raw_ADDR28_O2",
    0xFFFF405E: "adc_raw_ADDR29_ECT",
    0xFFFF4060: "adc_raw_ADDR30_IAT",
    0xFFFF4064: "adc_snap_grp0_start",
    0xFFFF407C: "adc_snap_grp1_start",
    # Knock ADC channels
    0xFFFF4088: "adc_raw_ADDR28_knock_snap",
    # Key knock RAM
    0xFFFF4304: "knock_ref_level_fr",   # float: background/reference level
    0xFFFF4308: "knock_status_4308",    # byte: knock event status
    0xFFFF430C: "knock_raw_signal",     # float: raw knock signal
    0xFFFF4310: "knock_struct_base",
    # Processed sensors
    0xFFFF4144: "ECT_processed",
    0xFFFF4128: "IAT_processed",
    0xFFFF40B4: "MAF_processed",
    0xFFFF43FC: "MAP_processed",
    0xFFFF41E8: "FuelTemp_processed",
    0xFFFF42FC: "BARO_processed",
    # Heavily-referenced processed area
    0xFFFF6624: "proc_6624",   # 301 refs - likely RPM or load
    0xFFFF6350: "proc_6350",   # 205 refs
    0xFFFF65FC: "proc_65FC",   # 135 refs
    0xFFFF63F8: "proc_63F8",   # knock load/TPS area
    0xFFFF67EC: "proc_67EC_word",
    # Knock GBR base
    0xFFFF80FC: "knock_det_GBR_base",
    0xFFFF8158: "knock_struct_8158",
    0xFFFF81AC: "knock_status_81AC",
    # Standard sensors
    0xFFFF8244: "RPM",
    0xFFFF824C: "ECT_raw",
    0xFFFF8264: "MAF_voltage",
    0xFFFF828C: "TPS",
    0xFFFF82B0: "IAT",
    0xFFFF8398: "Vehicle_Speed",
    # FLKC working area (0xFFFF32xx)
    0xFFFF3234: "FLKC_work_bank1",      # float: working FLKC bank1 (degrees, +ve=retard)
    0xFFFF3238: "FLKC_work_bank1b",
    0xFFFF323C: "FLKC_work_bank2",      # float: working FLKC bank2
    0xFFFF3240: "FLKC_work_bank2b",
    0xFFFF3244: "FLKC_enable_byte",     # byte: FLKC active status
    0xFFFF3248: "FLKC_percyl_arr",      # float[35]: per-cylinder FLKC array (8-byte entries)
    0xFFFF3360: "FLKC_percyl_result",   # word array: per-cylinder FLKC output word
    # FLKC state struct @ 0xFFFF8274
    0xFFFF8274: "FLKC_state_base",      # struct FLKC_state
    0xFFFF8290: "FLKC_FG_GBR_base",    # GBR base for flkc_paths_FG
    0xFFFF8294: "FLKC_counter",         # word: FLKC recovery counter
    0xFFFF8298: "FLKC_cyl_idx",         # byte: current cylinder index
    0xFFFF829C: "FLKC_mode_29C",        # byte: knock active mode flag
    0xFFFF829D: "FLKC_state_29D",       # byte: knock state (0=no knock, 1=knock active)
    0xFFFF829E: "FLKC_flag_29E",
    0xFFFF82A0: "FLKC_load_flag",       # byte: load/TGV flag copy
    0xFFFF82A1: "FLKC_flag_A1",
    0xFFFF82AA: "FLKC_cyl_state",       # byte: per-cylinder knock state counter
    0xFFFF82AB: "FLKC_flag_AB",
    0xFFFF82AC: "FLKC_load_copy",       # byte: copy of load flag
    # Knock state
    0xFFFF81BA: "knock_event_flag",     # byte: set by knock_detector when knock detected
    0xFFFF81BB: "knock_flag_B",         # byte: secondary knock flag
    0xFFFF81D8: "knock_rpmgate",        # byte: 1=above RPM threshold (~7200 RPM)
    0xFFFF81B1: "knock_level_code",     # byte: 0/2/4/5/6/7 intensity band
    # Helper structs
    0xFFFF818C: "knock_percyl_float",   # float[4]: per-cylinder knock level
    0xFFFF8233: "knock_active",
    0xFFFF8258: "knock_metric",         # float: cumulative knock metric
    # Key knock calibration scalars (ROM addresses as well)
    0xFFFF7D18: "knock_suppress_flag",  # byte: 1=suppress FLKC (fuel cut etc.)
    # Timing / FLKC
    0xFFFF9270: "IAM",
    0xFFFF9374: "Knock_Sum",
    0xFFFF93DC: "FBKC",
    0xFFFF93E0: "FLKC",
    # Misc
    0xFFFF5E58: "TGV_Left_GBR",
    0xFFFF5F1C: "TGV_Right_GBR",
}

FUNC_NAMES = {
    0x00000BFA: "DefaultExceptionHandler",
    0x00000BAC: "NMI_Handler",
    0x00000C0C: "Reset_Entry",
    0x00043750: "knock_wrapper",
    0x00043782: "knock_detector",
    0x00043D68: "task12_knock_post",
    0x0004438C: "task11_knock_flag_read",
    0x00045BFE: "flkc_path_J",
    0x000463BA: "flkc_paths_FG",
    0x0004A94C: "sched_periodic_dispatch",
    0x00045EEA: "FLKC_commit_write",
    0x00046A42: "FLKC_output_write",
    0x000BE56C: "clamp_float",          # clamp(fr4, fr5=lo, fr6=hi) -> fr0
    0x000BE970: "max_float",            # max(fr4, fr5) -> fr0
    0x000BDBCC: "write_float_ptr",      # write fr4 to @r4 with IIR
    0x000BE608: "Pull2DFloat",
    0x000BE830: "Pull3DFloat",
    0x000BE874: "LowPW_TableProcessor",
    0x000BECA8: "LowPW_AxisLookup",
}

# ADC channel map (offsets from 0xFFFFF800)
ADC_CHAN_MAP = {}
for i in range(12):
    ADC_CHAN_MAP[i*2]   = f"ADDR{i}H"
    ADC_CHAN_MAP[i*2+1] = f"ADDR{i}L"
ADC_CHAN_MAP[0x18] = "ADCSR0"; ADC_CHAN_MAP[0x19] = "ADCR0"
for i in range(12):
    ADC_CHAN_MAP[0x20+i*2]   = f"ADDR{12+i}H"
    ADC_CHAN_MAP[0x20+i*2+1] = f"ADDR{12+i}L"
ADC_CHAN_MAP[0x38] = "ADCSR1"; ADC_CHAN_MAP[0x39] = "ADCR1"
for i in range(8):
    ADC_CHAN_MAP[0x40+i*2]   = f"ADDR{24+i}H"
    ADC_CHAN_MAP[0x40+i*2+1] = f"ADDR{24+i}L"
ADC_CHAN_MAP[0x58] = "ADCSR2"; ADC_CHAN_MAP[0x59] = "ADCR2"

# ---------------------------------------------------------------------------
# Decoder (SH-2)
# ---------------------------------------------------------------------------
def sign_extend_8(val):
    return val - 0x100 if val & 0x80 else val

def sign_extend_12(val):
    return val - 0x1000 if val & 0x800 else val

def decode_insn(code, pc, rom):
    n = (code >> 8) & 0xF
    m = (code >> 4) & 0xF
    d = code & 0xF
    i = code & 0xFF
    top4 = (code >> 12) & 0xF

    if code == 0x0009: return "nop", 2
    if code == 0x000B: return "rts", 2
    if code == 0x002B: return "rte", 2
    if code == 0x0019: return "div0u", 2
    if code == 0x001B: return "sleep", 2

    if top4 == 0x0:
        if (code & 0xF00F) == 0x0003: return f"bsrf   r{n}", 2
        if (code & 0xF0FF) == 0x0012: return f"stc    GBR,r{n}", 2
        if (code & 0xF0FF) == 0x0022: return f"stc    VBR,r{n}", 2
        if (code & 0xF0FF) == 0x0029: return f"movt   r{n}", 2      # move T-bit to Rn
        if (code & 0xF00F) == 0x0004: return f"mov.b  r{m},@(r0,r{n})", 2
        if (code & 0xF00F) == 0x0005: return f"mov.w  r{m},@(r0,r{n})", 2
        if (code & 0xF00F) == 0x0006: return f"mov.l  r{m},@(r0,r{n})", 2
        if (code & 0xF00F) == 0x0007: return f"mul.l  r{m},r{n}", 2
        if (code & 0xF00F) == 0x000C: return f"mov.b  @(r0,r{m}),r{n}", 2
        if (code & 0xF00F) == 0x000D: return f"mov.w  @(r0,r{m}),r{n}", 2
        if (code & 0xF00F) == 0x000E: return f"mov.l  @(r0,r{m}),r{n}", 2
        if (code & 0xF00F) == 0x000F: return f"mac.l  @r{m}+,@r{n}+", 2
        return f"??       ; 0x{code:04X}", 2

    if top4 == 0x1:
        disp = code & 0xF
        return f"mov.l  r{m},@({disp*4},r{n})", 2

    if top4 == 0x2:
        sub = code & 0xF
        ops = {0:"mov.b",1:"mov.w",2:"mov.l",4:"mov.b",5:"mov.w",6:"mov.l",
               7:"div0s",8:"tst",9:"and",0xA:"xor",0xB:"or",0xC:"cmp/str",
               0xD:"xtrct",0xE:"mulu.w",0xF:"muls.w"}
        if sub in (0,1,2): return f"{ops[sub]}  r{m},@r{n}", 2
        if sub == 3: return f"cas.l  r{m},r{n},@r0", 2
        if sub in (4,5,6): return f"{ops[sub]}  r{m},@-r{n}", 2
        if sub in ops: return f"{ops[sub]}  r{m},r{n}", 2
        return f"??       ; 0x{code:04X}", 2

    if top4 == 0x3:
        sub = code & 0xF
        cmpops = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",4:"div1",5:"dmulu.l",
                  6:"cmp/hi",7:"cmp/gt",8:"sub",0xA:"subc",0xB:"subv",
                  0xC:"add",0xD:"dmuls.l",0xE:"addc",0xF:"addv"}
        if sub in cmpops: return f"{cmpops[sub]}  r{m},r{n}", 2
        return f"??       ; 0x{code:04X}", 2

    if top4 == 0x4:
        lo = code & 0xFF
        if lo == 0x18: return f"shll8  r{n}", 2
        if lo == 0x19: return f"shlr8  r{n}", 2
        if lo == 0x28: return f"shll16 r{n}", 2
        if lo == 0x29: return f"shlr16 r{n}", 2
        if lo == 0x00: return f"shll   r{n}", 2
        if lo == 0x01: return f"shlr   r{n}", 2
        if lo == 0x04: return f"rotl   r{n}", 2
        if lo == 0x05: return f"rotr   r{n}", 2
        if lo == 0x08: return f"shll2  r{n}", 2
        if lo == 0x09: return f"shlr2  r{n}", 2
        if lo == 0x10: return f"dt     r{n}", 2
        if lo == 0x11: return f"cmp/pz r{n}", 2
        if lo == 0x15: return f"cmp/pl r{n}", 2
        if lo == 0x20: return f"shal   r{n}", 2
        if lo == 0x21: return f"shar   r{n}", 2
        if lo == 0x24: return f"rotcl  r{n}", 2
        if lo == 0x25: return f"rotcr  r{n}", 2
        if (code & 0xF00F) == 0x400B: return f"jsr    @r{m}", 2
        # GBR/VBR checks BEFORE SR to avoid 0x4n1E being caught by 0x4n0E mask
        if (code & 0xF0FF) == 0x401E: return f"ldc    r{n},GBR", 2
        if (code & 0xF0FF) == 0x402E: return f"ldc    r{n},VBR", 2
        if (code & 0xF00F) == 0x400E: return f"ldc    r{m},SR", 2
        if lo == 0x13: return f"stc.l  GBR,@-r{n}", 2   # push GBR onto stack
        if lo == 0x17: return f"ldc.l  @r{n}+,GBR", 2   # pop GBR from stack
        if lo == 0x5A: return f"lds    r{n},FPUL", 2     # load Rn into FPUL
        if lo == 0x56: return f"lds.l  @r{n}+,FPUL", 2  # load @Rn+ into FPUL
        if lo == 0x22: return f"sts.l  pr,@-r{n}", 2
        if lo == 0x26: return f"lds.l  @r{n}+,pr", 2
        if lo == 0x02: return f"sts.l  mach,@-r{n}", 2
        if lo == 0x06: return f"lds.l  @r{n}+,mach", 2
        if lo == 0x12: return f"sts.l  macl,@-r{n}", 2
        if lo == 0x16: return f"lds.l  @r{n}+,macl", 2
        if lo == 0x2A: return f"lds    r{n},pr", 2
        if lo == 0x0A: return f"lds    r{n},mach", 2
        if lo == 0x1A: return f"lds    r{n},macl", 2
        if (code & 0xF00F) == 0x400F: return f"mac.w  @r{m}+,@r{n}+", 2
        return f"??       ; 0x{code:04X} (grp4)", 2

    if top4 == 0x5:
        disp = code & 0xF
        return f"mov.l  @({disp*4},r{m}),r{n}", 2

    if top4 == 0x6:
        sub = code & 0xF
        ops = {0:"mov.b",1:"mov.w",2:"mov.l",3:"mov",4:"mov.b",5:"mov.w",
               6:"mov.l",7:"not",8:"swap.b",9:"swap.w",0xA:"negc",0xB:"neg",
               0xC:"extu.b",0xD:"extu.w",0xE:"exts.b",0xF:"exts.w"}
        if sub in (0,1,2): return f"{ops[sub]}  @r{m},r{n}", 2
        if sub == 3: return f"mov    r{m},r{n}", 2
        if sub in (4,5,6): return f"{ops[sub]}  @r{m}+,r{n}", 2
        if sub in ops: return f"{ops[sub]}  r{m},r{n}", 2
        return f"??       ; 0x{code:04X}", 2

    if top4 == 0x7:
        imm = sign_extend_8(i)
        return f"add    #{imm},r{n}", 2

    if top4 == 0x8:
        sub = (code >> 8) & 0xF
        if sub == 0: return f"mov.b  r0,@({d},r{m})", 2
        if sub == 1: return f"mov.w  r0,@({d*2},r{m})", 2
        if sub == 4: return f"mov.b  @({d},r{m}),r0", 2
        if sub == 5: return f"mov.w  @({d*2},r{m}),r0", 2
        if sub == 8:
            imm = sign_extend_8(i)
            return f"cmp/eq #{imm},r0", 2
        if sub == 9:
            disp = sign_extend_8(i)
            target = pc + 4 + disp * 2
            tname = FUNC_NAMES.get(target, "")
            extra = f"  [{tname}]" if tname else ""
            return f"bt     0x{target:05X}{extra}", 2
        if sub == 0xB:
            disp = sign_extend_8(i)
            target = pc + 4 + disp * 2
            tname = FUNC_NAMES.get(target, "")
            extra = f"  [{tname}]" if tname else ""
            return f"bf     0x{target:05X}{extra}", 2
        if sub == 0xD:
            disp = sign_extend_8(i)
            target = pc + 4 + disp * 2
            return f"bt/s   0x{target:05X}", 2
        if sub == 0xF:
            disp = sign_extend_8(i)
            target = pc + 4 + disp * 2
            return f"bf/s   0x{target:05X}", 2
        return f"??       ; 0x{code:04X} (grp8)", 2

    if top4 == 0x9:
        disp = code & 0xFF
        target = pc + 4 + disp * 2
        if target + 2 <= len(rom):
            val = struct.unpack_from(">H", rom, target)[0]
            return f"mov.w  @(0x{target:05X}),r{n}  ; =0x{val:04X}", 2
        return f"mov.w  @(0x{target:05X}),r{n}", 2

    if top4 == 0xA:
        disp = sign_extend_12(code & 0xFFF)
        target = pc + 4 + disp * 2
        tname = FUNC_NAMES.get(target, "")
        extra = f"  [{tname}]" if tname else ""
        return f"bra    0x{target:05X}{extra}", 2

    if top4 == 0xB:
        disp = sign_extend_12(code & 0xFFF)
        target = pc + 4 + disp * 2
        tname = FUNC_NAMES.get(target, "")
        extra = f"  [{tname}]" if tname else ""
        return f"bsr    0x{target:05X}{extra}", 2

    if top4 == 0xC:
        sub = (code >> 8) & 0xF
        if sub == 0: return f"mov.b  r0,@({i},GBR)", 2
        if sub == 1: return f"mov.w  r0,@({i*2},GBR)", 2
        if sub == 2: return f"mov.l  r0,@({i*4},GBR)", 2
        if sub == 3: return f"trapa  #{i}", 2
        if sub == 4: return f"mov.b  @({i},GBR),r0", 2
        if sub == 5: return f"mov.w  @({i*2},GBR),r0", 2
        if sub == 6: return f"mov.l  @({i*4},GBR),r0", 2
        if sub == 7:
            disp = i
            target = (pc & ~3) + 4 + disp * 4
            if target + 4 <= len(rom):
                val = struct.unpack_from(">I", rom, target)[0]
                vname = FUNC_NAMES.get(val, RAM_NAMES.get(val, ""))
                extra = f" ({vname})" if vname else ""
                return f"mova   @(0x{target:05X}),r0  ; =0x{val:08X}{extra}", 2
            return f"mova   @(0x{target:05X}),r0", 2
        if sub == 8: return f"tst    #0x{i:02X},r0", 2
        if sub == 9: return f"and    #0x{i:02X},r0", 2
        if sub == 0xA: return f"xor    #0x{i:02X},r0", 2
        if sub == 0xB: return f"or     #0x{i:02X},r0", 2
        if sub == 0xC: return f"tst.b  #0x{i:02X},@(r0,GBR)", 2
        if sub == 0xD: return f"and.b  #0x{i:02X},@(r0,GBR)", 2
        if sub == 0xE: return f"xor.b  #0x{i:02X},@(r0,GBR)", 2
        if sub == 0xF: return f"or.b   #0x{i:02X},@(r0,GBR)", 2

    if top4 == 0xD:
        disp = code & 0xFF
        target = (pc & ~3) + 4 + disp * 4
        if target + 4 <= len(rom):
            val = struct.unpack_from(">I", rom, target)[0]
            vname = FUNC_NAMES.get(val, RAM_NAMES.get(val, ""))
            extra = f" ({vname})" if vname else ""
            return f"mov.l  @(0x{target:05X}),r{n}  ; =0x{val:08X}{extra}", 2
        return f"mov.l  @(0x{target:05X}),r{n}", 2

    if top4 == 0xE:
        imm = sign_extend_8(i)
        return f"mov    #{imm},r{n}", 2

    if top4 == 0xF:
        sub = code & 0xF
        if sub <= 5:
            fpu_ops = {0:"fadd",1:"fsub",2:"fmul",3:"fdiv",4:"fcmp/eq",5:"fcmp/gt"}
            return f"{fpu_ops[sub]}  fr{m},fr{n}", 2
        if sub == 6: return f"fmov.s @(r0,r{m}),fr{n}", 2
        if sub == 7: return f"fmov.s fr{m},@(r0,r{n})", 2
        if sub == 8: return f"fmov.s @r{m},fr{n}", 2
        if sub == 9: return f"fmov.s @r{m}+,fr{n}", 2
        if sub == 0xA: return f"fmov.s fr{m},@r{n}", 2
        if sub == 0xB: return f"fmov.s fr{m},@-r{n}", 2
        if sub == 0xC: return f"fmov   fr{m},fr{n}", 2
        if sub == 0xE: return f"fmac   fr0,fr{m},fr{n}", 2   # frn += fr0 * frm
        if (code & 0xF0FF) == 0xF02D: return f"float  FPUL,fr{n}", 2
        if (code & 0xF0FF) == 0xF03D: return f"ftrc   fr{n},FPUL", 2
        if (code & 0xF0FF) == 0xF04D: return f"fneg   fr{n}", 2
        if (code & 0xF0FF) == 0xF05D: return f"fabs   fr{n}", 2
        if (code & 0xF0FF) == 0xF08D: return f"fldi0  fr{n}", 2
        if (code & 0xF0FF) == 0xF09D: return f"fldi1  fr{n}", 2
        if (code & 0xF0FF) == 0xF00D: return f"fsts   FPUL,fr{n}", 2
        if (code & 0xF0FF) == 0xF01D: return f"flds   fr{n},FPUL", 2
        if (code & 0xF0FF) == 0xF06D: return f"fsqrt  fr{n}", 2
        return f"??fpu    ; 0x{code:04X}", 2

    return f"??       ; 0x{code:04X}", 2

# ---------------------------------------------------------------------------
# Helper: annotate literal value
# ---------------------------------------------------------------------------
def annotate_val(val):
    if val in FUNC_NAMES: return f"-> {FUNC_NAMES[val]}"
    if val in RAM_NAMES:  return f"-> {RAM_NAMES[val]}"
    # Float check: IEEE 754
    try:
        f = struct.unpack(">f", struct.pack(">I", val))[0]
        if 0.0001 < abs(f) < 1e9 and not (val & 0x7F800000 == 0x7F800000):
            return f"-> float {f:.6g}"
    except Exception:
        pass
    return ""

# ---------------------------------------------------------------------------
# Disassembler with GBR tracking and literal annotation
# ---------------------------------------------------------------------------
def disasm(rom, start, nbytes, title="", gbr_base=None):
    end = start + nbytes
    sep = "=" * 78
    print(f"\n{sep}")
    print(f"  {title}  [0x{start:05X} - 0x{end:05X}]")
    print(sep)

    # GBR tracking across the whole function
    gbr = gbr_base  # known GBR if passed in
    reg_vals = {}   # rN -> int (known value)

    pc = start
    in_literal_pool = False
    pool_end = 0

    while pc < end:
        # Check if we're inside a known literal pool run
        if in_literal_pool and pc < pool_end:
            val = struct.unpack_from(">I", rom, pc)[0]
            ann = annotate_val(val)
            print(f"  {pc:05X}:  [pool] 0x{val:08X}  {ann}")
            pc += 4
            continue
        in_literal_pool = False

        if pc + 2 > len(rom):
            break
        code = struct.unpack_from(">H", rom, pc)[0]
        mnem, size = decode_insn(code, pc, rom)

        # --- register tracking ---
        top4 = (code >> 12) & 0xF
        nn   = (code >> 8) & 0xF
        mm   = (code >> 4) & 0xF

        annotation = ""

        # mov #imm, Rn
        if top4 == 0xE:
            imm = sign_extend_8(code & 0xFF) & 0xFFFFFFFF
            reg_vals[nn] = imm

        # shll8 Rn
        elif (code & 0xF0FF) == 0x4018:
            rn = (code >> 8) & 0xF
            if rn in reg_vals:
                reg_vals[rn] = (reg_vals[rn] << 8) & 0xFFFFFFFF

        # shll16 Rn
        elif (code & 0xF0FF) == 0x4028:
            rn = (code >> 8) & 0xF
            if rn in reg_vals:
                reg_vals[rn] = (reg_vals[rn] << 16) & 0xFFFFFFFF

        # add #imm, Rn
        elif top4 == 0x7:
            rn = (code >> 8) & 0xF
            imm = sign_extend_8(code & 0xFF)
            if rn in reg_vals:
                reg_vals[rn] = (reg_vals[rn] + imm) & 0xFFFFFFFF

        # mov Rm,Rn
        elif top4 == 0x6 and (code & 0xF) == 0x3:
            rm = (code >> 4) & 0xF
            rn = (code >> 8) & 0xF
            if rm in reg_vals:
                reg_vals[rn] = reg_vals[rm]

        # mov.l @(pool),Rn  -> track literal value
        elif top4 == 0xD:
            disp = code & 0xFF
            target = (pc & ~3) + 4 + disp * 4
            if target + 4 <= len(rom):
                val = struct.unpack_from(">I", rom, target)[0]
                reg_vals[nn] = val

        # ldc Rn,GBR
        elif (code & 0xF0FF) == 0x401E:
            rn = (code >> 8) & 0xF
            if rn in reg_vals:
                gbr = reg_vals[rn]
                annotation = f"  ; GBR <- 0x{gbr:08X}"

        # stc GBR,Rn (0x0n12)
        elif (code & 0xF0FF) == 0x0012:
            rn = (code >> 8) & 0xF
            if gbr is not None:
                reg_vals[rn] = gbr

        # GBR-relative: mov.l @(d*4, GBR), r0  (0xC6xx)
        elif top4 == 0xC and ((code >> 8) & 0xF) == 6:
            if gbr is not None:
                offset = (code & 0xFF) * 4
                addr = gbr + offset
                ann = RAM_NAMES.get(addr, "")
                if ann: annotation = f"  ; @GBR+{offset} = 0x{addr:08X} ({ann})"
                else:   annotation = f"  ; @GBR+{offset} = 0x{addr:08X}"

        # GBR-relative: mov.b @(d, GBR), r0  (0xC4xx)
        elif top4 == 0xC and ((code >> 8) & 0xF) == 4:
            if gbr is not None:
                offset = code & 0xFF
                addr = gbr + offset
                ann = RAM_NAMES.get(addr, "")
                if ann: annotation = f"  ; @GBR+{offset} = 0x{addr:08X} ({ann})"
                else:   annotation = f"  ; @GBR+{offset} = 0x{addr:08X}"

        # GBR-relative: mov.w @(d*2, GBR), r0  (0xC5xx)
        elif top4 == 0xC and ((code >> 8) & 0xF) == 5:
            if gbr is not None:
                offset = (code & 0xFF) * 2
                addr = gbr + offset
                ann = RAM_NAMES.get(addr, "")
                if ann: annotation = f"  ; @GBR+{offset} = 0x{addr:08X} ({ann})"
                else:   annotation = f"  ; @GBR+{offset} = 0x{addr:08X}"

        # GBR-relative store: mov.l r0,@(d*4, GBR)  (0xC2xx)
        elif top4 == 0xC and ((code >> 8) & 0xF) == 2:
            if gbr is not None:
                offset = (code & 0xFF) * 4
                addr = gbr + offset
                ann = RAM_NAMES.get(addr, "")
                if ann: annotation = f"  ; @GBR+{offset} = 0x{addr:08X} ({ann})"
                else:   annotation = f"  ; @GBR+{offset} = 0x{addr:08X}"

        # GBR-relative store: mov.b r0,@(d, GBR)  (0xC0xx)
        elif top4 == 0xC and ((code >> 8) & 0xF) == 0:
            if gbr is not None:
                offset = code & 0xFF
                addr = gbr + offset
                ann = RAM_NAMES.get(addr, "")
                if ann: annotation = f"  ; @GBR+{offset} = 0x{addr:08X} ({ann})"
                else:   annotation = f"  ; @GBR+{offset} = 0x{addr:08X}"

        # Register-indirect: annotate if we know register value
        elif top4 == 0x6 and (code & 0xF) in (0,1,2):
            rm = (code >> 4) & 0xF
            rn = (code >> 8) & 0xF
            sub = code & 0xF
            if rm in reg_vals:
                addr = reg_vals[rm]
                ann = RAM_NAMES.get(addr, "")
                if ann: annotation = f"  ; @0x{addr:08X} ({ann})"
                else:   annotation = f"  ; @0x{addr:08X}"

        elif top4 == 0x2 and (code & 0xF) in (0,1,2):
            rm = (code >> 4) & 0xF
            rn = (code >> 8) & 0xF
            if rn in reg_vals:
                addr = reg_vals[rn]
                ann = RAM_NAMES.get(addr, "")
                if ann: annotation = f"  ; -> 0x{addr:08X} ({ann})"
                else:   annotation = f"  ; -> 0x{addr:08X}"

        # @(disp*4, Rm) load
        elif top4 == 0x5:
            rm = (code >> 4) & 0xF
            rn = (code >> 8) & 0xF
            disp = (code & 0xF) * 4
            if rm in reg_vals:
                addr = (reg_vals[rm] + disp) & 0xFFFFFFFF
                ann = RAM_NAMES.get(addr, "")
                if ann: annotation = f"  ; @0x{addr:08X} ({ann})"
                else:   annotation = f"  ; @0x{addr:08X}"
                reg_vals[rn] = addr  # not quite right but helps tracking

        # @(disp*4, Rn) store
        elif top4 == 0x1:
            rm = (code >> 4) & 0xF
            rn = (code >> 8) & 0xF
            disp = (code & 0xF) * 4
            if rn in reg_vals:
                addr = (reg_vals[rn] + disp) & 0xFFFFFFFF
                ann = RAM_NAMES.get(addr, "")
                if ann: annotation = f"  ; -> 0x{addr:08X} ({ann})"
                else:   annotation = f"  ; -> 0x{addr:08X}"

        # jsr @Rn
        elif (code & 0xF00F) == 0x400B:
            rm = (code >> 4) & 0xF
            if rm in reg_vals:
                addr = reg_vals[rm]
                fn = FUNC_NAMES.get(addr, "")
                if fn: annotation = f"  ; CALL {fn} @ 0x{addr:05X}"
                else:  annotation = f"  ; CALL @ 0x{addr:05X}"

        print(f"  {pc:05X}: {code:04X}  {mnem:<40}{annotation}")
        pc += size

    print()

# ---------------------------------------------------------------------------
# Dump literal pool
# ---------------------------------------------------------------------------
def dump_pool(rom, start, count, title=""):
    if title:
        print(f"\n  --- {title} ---")
    for i in range(count):
        addr = start + i*4
        if addr + 4 > len(rom): break
        val = struct.unpack_from(">I", rom, addr)[0]
        ann = annotate_val(val)
        print(f"  {addr:05X}:  [pool] 0x{val:08X}  {ann}")

# ---------------------------------------------------------------------------
# Main: disassemble all relevant functions
# ---------------------------------------------------------------------------
def main():
    with open(ROM_PATH, "rb") as f:
        rom = f.read()

    print("AE5L600L Knock / FLKC Disassembly Analysis")
    print("=" * 78)
    print(f"ROM size: 0x{len(rom):X} bytes")

    # ------------------------------------------------------------------
    # 1. knock_detector continuation (past literal pool at ~0x439A0)
    #    First: dump the literal pool we hit before (0x439A0 - 0x439FC)
    # ------------------------------------------------------------------
    print("\n\n[1] knock_detector (0x43782) - literal pool dump (0x439A0..0x439FC)")
    dump_pool(rom, 0x439A0, (0x439FC - 0x439A0)//4)

    # Now continue the function code from after the pool
    disasm(rom, 0x439FC, 0x400,
           "knock_detector (0x43782) - continuation from 0x439FC",
           gbr_base=0xFFFF80FC)

    # ------------------------------------------------------------------
    # 2. knock_wrapper continuation at 0x43B7C
    # ------------------------------------------------------------------
    disasm(rom, 0x43B7C, 0x200,
           "knock_wrapper continuation (0x43B7C)")

    # ------------------------------------------------------------------
    # 3. task12_knock_post (0x43D68)
    # ------------------------------------------------------------------
    disasm(rom, 0x43D68, 0x300,
           "task12_knock_post (0x43D68)")

    # ------------------------------------------------------------------
    # 4. task11_knock_flag_read (0x4438C)
    # ------------------------------------------------------------------
    disasm(rom, 0x4438C, 0x200,
           "task11_knock_flag_read (0x4438C)")

    # ------------------------------------------------------------------
    # 5. flkc_path_J (0x45BFE) - fast-response FLKC retard
    # ------------------------------------------------------------------
    disasm(rom, 0x45BFE, 0x400,
           "flkc_path_J (0x45BFE) - fast-response knock retard")

    # ------------------------------------------------------------------
    # 6. flkc_paths_FG (0x463BA) - sustained-knock state machine
    # ------------------------------------------------------------------
    disasm(rom, 0x463BA, 0x600,
           "flkc_paths_FG (0x463BA) - sustained knock state machine")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
