#!/usr/bin/env python3
"""
Disassemble the unanalyzed AFC pipeline stages from CL_fuel_dispatcher.
Stages 3-5 (0x33658, 0x33FCE, 0x340A0) and stages 7-8 (0x3439E, 0x343CE).

AE5L600L (2013 Subaru WRX MT) — Renesas SH7058 (SH-2, Big-Endian)
"""

import struct
import os

# Try multiple ROM paths
ROM_CANDIDATES = [
    r"rom/ae5l600l.bin",
    r"rom/AE5L600L 20g rev 20.5 tiny wrex.bin",
]

ROM_PATH = None
for candidate in ROM_CANDIDATES:
    # Try relative to script dir and cwd
    for base in [os.path.dirname(os.path.abspath(__file__)), os.getcwd()]:
        p = os.path.normpath(os.path.join(base, "..", "..", candidate))
        if os.path.isfile(p):
            ROM_PATH = p
            break
        p2 = os.path.normpath(os.path.join(base, candidate))
        if os.path.isfile(p2):
            ROM_PATH = p2
            break
    if ROM_PATH:
        break

if not ROM_PATH:
    print("ERROR: Could not find ROM file. Tried:", ROM_CANDIDATES)
    exit(1)

# ============================================================
# AFC pipeline stages to disassemble
# ============================================================
STAGES = [
    {"name": "Stage 3: func_33658", "addr": 0x33658, "max_len": 0x33FCE - 0x33658 + 256},
    {"name": "Stage 4: func_33FCE", "addr": 0x33FCE, "max_len": 0x340A0 - 0x33FCE + 256},
    {"name": "Stage 5: func_340A0", "addr": 0x340A0, "max_len": 0x342A8 - 0x340A0 + 256},
    {"name": "Stage 7: func_3439E", "addr": 0x3439E, "max_len": 0x343CE - 0x3439E + 256},
    {"name": "Stage 8: func_343CE", "addr": 0x343CE, "max_len": 512},
]

STAGES_IPW = [
    {"name": "Main IPW Calculator: func_38158", "addr": 0x38158, "max_len": 0x38D16 - 0x38158 + 512},
]

STAGES_TABLEB = [
    {"name": "fuel_overrun_cutoff: func_3EB8C",   "addr": 0x3EB8C, "max_len": 0x403C4 - 0x3EB8C + 256},
    {"name": "Table_B_19: func_403C4",             "addr": 0x403C4, "max_len": 1024},
    {"name": "fuel_cut_output_tail: func_46BCC",   "addr": 0x46BCC, "max_len": 1024},
    {"name": "ect_warmup_consumer: func_3F374",    "addr": 0x3F374, "max_len": 2048},
]

STAGES_INJECT = [
    {"name": "injector_output: func_3190",          "addr": 0x3190,  "max_len": 1024},
    {"name": "system_scheduler_isr: func_48732",    "addr": 0x48732, "max_len": 2048},
    {"name": "per_cyl_pulse_emit: func_82DE",       "addr": 0x82DE,  "max_len": 512},
    {"name": "per_cyl_mode_sub: func_82B6",         "addr": 0x82B6,  "max_len": 256},
    {"name": "pulse_lookup: func_4760A",            "addr": 0x4760A, "max_len": 512},
    {"name": "injector_latency_user: func_30378",   "addr": 0x30378, "max_len": 256},
    {"name": "mtu_write_gate: func_3664",           "addr": 0x3664,  "max_len": 256},
    {"name": "dead_time_store: func_9E4A",          "addr": 0x9E4A,  "max_len": 256},
    {"name": "cyl_injection_cb: func_BDBCC",        "addr": 0xBDBCC, "max_len": 256},
    {"name": "raise_ipl: func_317C",                "addr": 0x317C,  "max_len": 64},
    {"name": "injector_output: func_3190 (gate)",   "addr": 0x3190,  "max_len": 64},
    {"name": "inj_param_stage: func_56022",         "addr": 0x56022, "max_len": 512},
    {"name": "isr22_epilogue: func_4B298",          "addr": 0x4B298, "max_len": 128},
]

STAGES_INJDATA = [
    {"name": "injdata_writer_A: func_304BE",        "addr": 0x304BE, "max_len": 512},
    {"name": "injdata_writer_B: func_37604",        "addr": 0x37604, "max_len": 512},
    {"name": "injdata_writer_C: func_3757E",        "addr": 0x3757E, "max_len": 256},
    {"name": "injdata_writer_D: func_40528",        "addr": 0x40528, "max_len": 1024},
    {"name": "injdata_writer_E: func_410D4",        "addr": 0x410D4, "max_len": 1024},
    {"name": "injdata_writer_F: func_23BA4",        "addr": 0x23BA4, "max_len": 512},
    {"name": "injdata_writer_G: func_558AC",        "addr": 0x558AC, "max_len": 512},
    {"name": "injdata_writer_H: func_60392",        "addr": 0x60392, "max_len": 512},
]

STAGES_HELPERS = [
    {"name": "per_cyl_helper_37C9E", "addr": 0x37C9E, "max_len": 256},
    {"name": "per_cyl_helper_37CA6", "addr": 0x37CA6, "max_len": 256},
    {"name": "per_cyl_helper_37E96", "addr": 0x37E96, "max_len": 512},
    {"name": "per_cyl_helper_37F62", "addr": 0x37F62, "max_len": 256},
    {"name": "per_cyl_helper_37F9A", "addr": 0x37F9A, "max_len": 512},
    {"name": "float_util_BE960",     "addr": 0xBE960, "max_len": 256},
]

# Known RAM labels
KNOWN_LABELS = {
    0xFFFF77C8: "CL_base_params_struct",
    0xFFFF77DC: "CL_target_comp_A_output",
    0xFFFF77E0: "CL_target_comp_B_output",
    0xFFFF77E4: "CL_target_comp_C_output",
    0xFFFF77E8: "CL_target_comp_D_output",
    0xFFFF77F0: "CL_target_rates_struct",
    0xFFFF781C: "AFC_pipeline_result",
    0xFFFF782A: "CL_target_comp_status",
    0xFFFF7828: "aggregator_struct",
    0xFFFF7864: "AFC_struct_base",
    0xFFFF7904: "aggregator_output",
    0xFFFF7348: "fuel_base_factor",
    0xFFFF4130: "battery_voltage_float",
    0xFFFF7350: "injector_dead_time_ticks",
    0xFFFF4280: "injector_dead_time_applied",
    0xFFFF831C: "rpm_scale_byte",
    0xFFFF7344: "fuel_per_cyl_struct",
    0xFFFF7AB4: "afl_multiplier_output",
    0xFFFF73A4: "fuel_correction_A",
    0xFFFF7A08: "fuel_correction_B",
    0xFFFF7BC4: "fuel_correction_C",
    0xFFFF76D4: "fuel_enrichment_A",
    0xFFFF7878: "fuel_enrichment_B",
    0xFFFF7AE4: "fuel_enrichment_C",
    0xFFFF7B6C: "fuel_blend_A",
    0xFFFF7B70: "fuel_blend_B",
    0xFFFF7B74: "fuel_blend_C",
    0xFFFF7B78: "fuel_blend_D",
    0xFFFF6624: "engine_load_float",
    0xFFFF63F8: "RPM_float",
    0xFFFF63C4: "processed_sensor_A",
    0xFFFF68D8: "processed_sensor_B",
    0xFFFF6540: "sensor_state",
    0xFFFF65F0: "CL_OL_status_byte",
    0xFFFF6574: "filtered_sensor",
    0xFFFF7448: "CLOL_mode_flag",
    0xFFFF7452: "CL_readiness_flags",
    0xFFFF7A44: "CL_integral_term",
    0xFFFF7BEC: "AFC_status",
    0xFFFF7BE4: "AFC_working_value",
    0xFFFF8E7E: "operating_mode_flag",
    0xFFFF8E46: "condition_flag",
    0xFFFF68D0: "sensor_C",
    0xFFFF85D7: "status_byte",
    0xFFFF74BC: "fuel_corr_mode",
    0xFFFF74BD: "fuel_corr_status",
    0xFFFF984D: "AT_MT_flag",
    0xFFFF895C: "inj_struct_895C (written by func_517A0)",
    0xFFFF8964: "inj_struct_8964 (copy of 895C post-update)",
    0xFFFF8960: "inj_struct_8960",
    0xFFFF8958: "inj_struct_8958",
    0xFFFF8948: "inj_struct_8948",
    0xFFFF8934: "inj_struct_8934",
    0xFFFF893C: "inj_struct_893C",
    0xFFFF8920: "inj_struct_8920",
    0xFFFF7F8C: "inj_struct_895C_shadow (Table_B_19 output)",
    0xFFFF7B3A: "fuel_ipw_state_A",
    0xFFFF7AF4: "fuel_ipw_state_B",
    0xFFFF7AF8: "fuel_ipw_state_C",
    0xFFFF7B40: "fuel_ipw_state_D",
    0xFFFF7FBC: "fuel_ipw_output_struct",
    0xFFFF798C: "fuel_load_state",
    0xFFFF8998: "sensor_state_8998",
    0xFFFF89C4: "sensor_state_89C4",
    0xFFFF99A8: "per_cyl_state_A",
    0xFFFF99AC: "per_cyl_state_B",
    0xFFFF99B0: "per_cyl_state_C",
    0xFFFF3158: "afl_state_3158",
    0xFFFF6388: "RPM_word",
    0xFFFF65BC: "throttle_pos_byte",
    0xFFFF6598: "MAP_float",
    0xFFFF65A0: "MAP_float_B",
    0xFFFF7AC0: "afl_rate_limit_state",
    0xFFFF7ADD: "afl_counter_state",
    0xFFFF8998: "sensor_struct_8998",
    0xFFFF89C4: "sensor_float_89C4",
    0xFFFF647D: "sensor_byte_647D",
    0xFFFF6364: "RPM_float_B",
    0xFFFF6350: "ECT_float",
    0xFFFF65BD: "decel_flag",
    0xFFFF7E8C: "overrun_state",
    0xFFFF7E8E: "overrun_counter",
    0xFFFF7F68: "ect_warmup_correction",
    0xFFFF90BE: "ect_mode_flag",
    0xFFFF3D08: "cyl1_desc_base",
    0xFFFF3D10: "cyl2_desc_base",
    0xFFFF3D18: "cyl3_desc_base",
    0xFFFF3D1C: "cyl4_desc_end",
    0xFFFF36BE: "cyl_sync_word",
    0xFFFF1288: "inj_gate_hook_ptr",
    0xFFFF12A0: "inj_gate_ctrl_ptr",
    0xFFFF1290: "inj_state_flags",
    # Stage 3-8 input/output labels (confirmed from AFC analysis + CL/OL analysis)
    0xFFFF6254: "gear_position_byte",
    0xFFFF65C0: "engine_running_state",
    0xFFFF62F8: "secondary_throttle_float",
    0xFFFF65FC: "base_pulse_width",
    0xFFFF67EC: "RPM_raw_word",
    0xFFFF6354: "speed_threshold_float",
    0xFFFF7870: "AFC_pi_blended_output",
    0xFFFF7820: "AFC_clamped_output",
    0xFFFF782C: "AFC_working_struct",
    0xFFFF78B0: "AFC_pi_working_struct",
    0xFFFF68DC: "AFC_sensor_blend_float",
    0xFFFF79C2: "CL_OL_counter_A",
    0xFFFF79C4: "CL_OL_counter_B",
    0xFFFF64D8: "AFC_load_input_float",
}

# Known subroutine labels
KNOWN_SUBS = {
    0x22CF4: "sub_22CF4 (AT/MT detect?)",
    0xBE8E4: "table_lookup_2D",
    0xBE944: "table_lookup_2D_int",
    0x303C0: "injector_dead_time_calc",
    0x517A0: "inj_struct_895C_writer (func_517A0)",
    0x9E4A:  "injector_dead_time_store",
    0xBE830: "table_lookup_1D",
    0xBEA40: "clamp_blend",
    0xBE970: "rate_limit_interp",
    0xBE56C: "float_clamp_apply",
    0xBEAB0: "table_lookup_err_scale",
    0xBDBCC: "cyl_injection_cb (per-cyl injection trigger)",
    0xBE980: "desc_read_validate",
    0x3439E: "func_3439E (stage 7)",
    0x343CE: "func_343CE (stage 8)",
    0x33460: "fuel_aggregator_tail",
    0x38158: "Main_IPW_calc (Table_A_15)",
    0x3160A: "major_correction_aggregator",
    0xBE608: "float_clamp_or_scale",
    0xBE628: "float_scale_B",
    0xBE53C: "float_util_53C",
    0xBE554: "float_util_554",
    0xBE598: "float_util_598",
    0x9A007: "sub_9A007",
    0xBE960: "float_max",
    0x317C:  "raise_ipl",
    0x3190:  "injector_output_gate",
    0x3664:  "mtu_write_gate",
    0x56022: "inj_param_stage (func_56022)",
    0x4B298: "system_isr22_epilogue",
    0x48732: "system_scheduler_isr (func_48732)",
    0x300E:  "func_300E (inj_ic_trigger)",
    0x35FC:  "func_35FC (inj_channel_setup, RAM-resident)",
    0x2FEC:  "func_2FEC (inj_hw_write)",
    0x3440:  "func_3440 (inj_timer_setup, RAM-resident)",
    0x3EB8C: "fuel_overrun_cutoff",
    0x46BCC: "fuel_cut_output_tail",
    0x33658: "func_33658 (stage 3)",
    0x33FCE: "func_33FCE (stage 4)",
    0x340A0: "func_340A0 (stage 5)",
    0x342A8: "AFC_PI_controller (stage 6)",
    0x33D1C: "cl_fuel_target_B (stage 1)",
    0x33CC0: "cl_fuel_target_A (stage 2)",
}


def read_u16(rom, offset):
    return struct.unpack(">H", rom[offset:offset+2])[0]

def read_u32(rom, offset):
    return struct.unpack(">I", rom[offset:offset+4])[0]

def read_float(rom, offset):
    return struct.unpack(">f", rom[offset:offset+4])[0]

def sign_extend_8(v):
    return v - 256 if v & 0x80 else v

def sign_extend_12(v):
    return v - 4096 if v & 0x800 else v

def classify_addr(addr):
    if 0xFFFF0000 <= addr <= 0xFFFFFFFF:
        return "RAM"
    elif 0xC0000 <= addr <= 0xDFFFF:
        return "CAL"
    elif addr < 0x100000:
        return "ROM"
    return "CONST"


def disassemble_one(rom, pc):
    """Disassemble a single SH-2 instruction at pc."""
    opcode = read_u16(rom, pc)
    nib0 = (opcode >> 12) & 0xF
    nib1 = (opcode >> 8) & 0xF
    nib2 = (opcode >> 4) & 0xF
    nib3 = opcode & 0xF
    n = nib1; m = nib2; d8 = opcode & 0xFF; d12 = opcode & 0xFFF

    mn = ""; ops = ""; cmt = ""; branch_target = None

    if opcode == 0x000B:
        mn = "rts"
    elif opcode == 0x0009:
        mn = "nop"
    elif nib0 == 0xE:
        mn = "mov"; ops = f"#{sign_extend_8(d8)},R{n}"
    elif nib0 == 0xD:
        disp = d8; lit_addr = (pc & ~3) + 4 + disp * 4
        if lit_addr + 3 < len(rom):
            val = read_u32(rom, lit_addr); cls = classify_addr(val)
            mn = "mov.l"; ops = f"@(0x{lit_addr:X}),R{n}"
            label = KNOWN_LABELS.get(val, "")
            if cls == "CAL":
                try:
                    fv = read_float(rom, val)
                    cmt = f"R{n} = &0x{val:X} [{cls}] = {fv}"
                except:
                    cmt = f"R{n} = &0x{val:X} [{cls}]"
            elif cls == "RAM":
                cmt = f"R{n} = 0x{val:08X} [{cls}] {label}"
            elif cls == "ROM":
                sub_label = KNOWN_SUBS.get(val, "")
                cmt = f"R{n} = 0x{val:X} [{cls}] {sub_label}"
            else:
                cmt = f"R{n} = 0x{val:X}"
        else:
            mn = "mov.l"; ops = f"@(0x{lit_addr:X}),R{n}"; cmt = "OUT OF RANGE"
    elif nib0 == 0x9:
        disp = d8; lit_addr = pc + 4 + disp * 2
        if lit_addr + 1 < len(rom):
            val = read_u16(rom, lit_addr)
            mn = "mov.w"; ops = f"@(0x{lit_addr:X}),R{n}"; cmt = f"R{n} = 0x{val:04X} ({val})"
        else:
            mn = "mov.w"; ops = f"@(0x{lit_addr:X}),R{n}"; cmt = "OUT OF RANGE"
    elif nib0 == 0x6:
        sub = nib3
        tbl = {0:"mov.b",1:"mov.w",2:"mov.l",3:"mov",6:"mov.l",
               0xC:"extu.b",0xD:"extu.w",0xE:"exts.b",0xF:"exts.w"}
        mn = tbl.get(sub, f".word 0x{opcode:04X}")
        if sub in (0,1,2): ops = f"@R{m},R{n}"
        elif sub == 3: ops = f"R{m},R{n}"
        elif sub == 6: ops = f"@R{m}+,R{n}"
        elif sub in (0xC,0xD,0xE,0xF): ops = f"R{m},R{n}"
        else: ops = f"0x{opcode:04X}"
    elif nib0 == 0x2:
        sub = nib3
        tbl = {0:"mov.b",1:"mov.w",2:"mov.l",6:"mov.l",8:"tst",9:"and",
               0xA:"xor",0xB:"or",0xE:"mulu.w",0xF:"muls.w"}
        mn = tbl.get(sub, f".word")
        if sub in (0,1,2): ops = f"R{m},@R{n}"
        elif sub == 6: ops = f"R{m},@-R{n}"
        elif sub in (8,9,0xA,0xB,0xE,0xF): ops = f"R{m},R{n}"
        else: ops = f"0x{opcode:04X}"
    elif nib0 == 0x4:
        sub = (nib2 << 4) | nib3
        tbl = {
            0x0B: ("jsr", f"@R{n}"), 0x2B: ("jmp", f"@R{n}"),
            0x22: ("sts.l", f"PR,@-R{n}"), 0x26: ("lds.l", f"@R{n}+,PR"),
            0x13: ("stc.l", f"GBR,@-R{n}"), 0x1E: ("ldc", f"R{n},GBR"),
            0x17: ("ldc.l", f"@R{n}+,GBR"),
            0x11: ("cmp/pz", f"R{n}"), 0x15: ("cmp/pl", f"R{n}"),
            0x10: ("dt", f"R{n}"),
            0x24: ("rotcl", f"R{n}"), 0x25: ("rotcr", f"R{n}"),
            0x04: ("rotl", f"R{n}"), 0x05: ("rotr", f"R{n}"),
            0x00: ("shll", f"R{n}"), 0x01: ("shlr", f"R{n}"),
            0x20: ("shal", f"R{n}"), 0x21: ("shar", f"R{n}"),
            0x08: ("shll2", f"R{n}"), 0x09: ("shlr2", f"R{n}"),
            0x18: ("shll8", f"R{n}"), 0x19: ("shlr8", f"R{n}"),
            0x28: ("shll16", f"R{n}"), 0x29: ("shlr16", f"R{n}"),
            0x5A: ("lds", f"R{n},FPUL"), 0x6A: ("sts", f"FPUL,R{n}"),
            0x2D: ("float", f"FPUL,FR{n}"), 0x3D: ("ftrc", f"FR{n},FPUL"),
        }
        if sub in tbl:
            mn, ops = tbl[sub]
        elif sub == 0x0C:
            mn = "shad"; ops = f"R{m},R{n}"
        elif sub == 0x0D:
            mn = "shld"; ops = f"R{m},R{n}"
        else:
            mn = ".word"; ops = f"0x{opcode:04X}"; cmt = f"4n sub=0x{sub:02X}"
    elif nib0 == 0x7:
        mn = "add"; ops = f"#{sign_extend_8(d8)},R{n}"
    elif nib0 == 0x3:
        sub = nib3
        tbl = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",6:"cmp/hi",7:"cmp/gt",
               0xC:"add",8:"sub",0xE:"addc",0xA:"subc",0xF:"addv",0xB:"subv",
               0x4:"div1",0xD:"dmuls.l"}
        mn = tbl.get(sub, ".word")
        ops = f"R{m},R{n}" if sub in tbl else f"0x{opcode:04X}"
    elif nib0 == 0x8:
        if nib1 == 0x8:
            mn = "cmp/eq"; ops = f"#{sign_extend_8((nib2<<4)|nib3)},R0"
        elif nib1 == 0x9:
            t = pc + 4 + sign_extend_8((nib2<<4)|nib3) * 2
            mn = "bt"; ops = f"0x{t:X}"; branch_target = t
        elif nib1 == 0xB:
            t = pc + 4 + sign_extend_8((nib2<<4)|nib3) * 2
            mn = "bf"; ops = f"0x{t:X}"; branch_target = t
        elif nib1 == 0xD:
            t = pc + 4 + sign_extend_8((nib2<<4)|nib3) * 2
            mn = "bt/s"; ops = f"0x{t:X}"; branch_target = t
        elif nib1 == 0xF:
            t = pc + 4 + sign_extend_8((nib2<<4)|nib3) * 2
            mn = "bf/s"; ops = f"0x{t:X}"; branch_target = t
        elif nib1 == 0x0:
            mn = "mov.b"; ops = f"R0,@({nib3},R{nib2})"
        elif nib1 == 0x1:
            mn = "mov.w"; ops = f"R0,@({nib3}*2,R{nib2})"
        elif nib1 == 0x4:
            mn = "mov.b"; ops = f"@({nib3},R{nib2}),R0"
        elif nib1 == 0x5:
            mn = "mov.w"; ops = f"@({nib3}*2,R{nib2}),R0"
        else:
            mn = ".word"; ops = f"0x{opcode:04X}"
    elif nib0 == 0xA:
        t = pc + 4 + sign_extend_12(d12) * 2
        mn = "bra"; ops = f"0x{t:X}"; branch_target = t
        sub_label = KNOWN_SUBS.get(t, "")
        if sub_label:
            cmt = sub_label
    elif nib0 == 0xB:
        t = pc + 4 + sign_extend_12(d12) * 2
        mn = "bsr"; ops = f"0x{t:X}"; branch_target = t
        sub_label = KNOWN_SUBS.get(t, "")
        if sub_label:
            cmt = sub_label
    elif nib0 == 0xC:
        disp = (nib2 << 4) | nib3
        ctbl = {0:("mov.b",f"R0,@({disp},GBR)"),1:("mov.w",f"R0,@({disp}*2,GBR)"),
                2:("mov.l",f"R0,@({disp}*4,GBR)"),
                4:("mov.b",f"@({disp},GBR),R0"),5:("mov.w",f"@({disp}*2,GBR),R0"),
                6:("mov.l",f"@({disp}*4,GBR),R0"),
                7:("mova",f"@({disp}*4+PC),R0"),
                8:("tst",f"#{disp},R0"),
                9:("and",f"#{disp},R0")}
        if nib1 in ctbl:
            mn, ops = ctbl[nib1]
            if nib1 == 7:
                target = (pc & ~3) + 4 + disp * 4
                cmt = f"R0 = 0x{target:X}"
        else:
            mn = ".word"; ops = f"0x{opcode:04X}"
    elif nib0 == 0x1:
        mn = "mov.l"; ops = f"R{m},@({nib3}*4,R{n})"
    elif nib0 == 0x5:
        mn = "mov.l"; ops = f"@({nib3}*4,R{m}),R{n}"
    elif nib0 == 0x0:
        if nib3 == 0x6:
            mn = "mov.l"; ops = f"@(R0,R{m}),R{n}"
        elif nib3 == 0xC:
            mn = "mov.b"; ops = f"@(R0,R{m}),R{n}"
        elif nib3 == 0xD:
            mn = "mov.w"; ops = f"@(R0,R{m}),R{n}"
        elif nib3 == 0x7:
            mn = "mul.l"; ops = f"R{m},R{n}"
        elif nib3 == 0x2:
            mn = "stc"; ops = f"SR,R{n}"
        elif nib3 == 0xA:
            mn = "sts"; ops = f"MACH,R{n}"
        elif nib3 == 0x5:
            mn = "mov.w"; ops = f"@(R0,R{m}),R{n}"
        elif nib3 == 0x4:
            mn = "mov.b"; ops = f"@(R0,R{m}),R{n}"
        else:
            mn = ".word"; ops = f"0x{opcode:04X}"
    elif nib0 == 0xF:
        sub = nib3; fn = n; fm = m
        fpu_tbl = {0:"fadd",1:"fsub",2:"fmul",3:"fdiv",4:"fcmp/eq",5:"fcmp/gt",0xE:"fmac"}
        if sub in fpu_tbl:
            mn = fpu_tbl[sub]
            if sub <= 5: ops = f"FR{fm},FR{fn}"
            elif sub == 0xE: ops = f"FR0,FR{fm},FR{fn}"
        elif sub == 6: mn = "fmov.s"; ops = f"@(R0,R{fm}),FR{fn}"
        elif sub == 7: mn = "fmov.s"; ops = f"FR{fm},@(R0,R{fn})"
        elif sub == 8: mn = "fmov.s"; ops = f"@R{fm},FR{fn}"
        elif sub == 9: mn = "fmov.s"; ops = f"@R{fm}+,FR{fn}"
        elif sub == 0xA: mn = "fmov.s"; ops = f"FR{fm},@R{fn}"
        elif sub == 0xB: mn = "fmov.s"; ops = f"FR{fm},@-R{fn}"
        elif sub == 0xC: mn = "fmov"; ops = f"FR{fm},FR{fn}"
        elif sub == 0xD:
            dtbl = {8:"fldi0",9:"fldi1",4:"fneg",5:"fabs",0:"fsts",1:"flds",
                    2:"float",3:"ftrc"}
            mn = dtbl.get(fm, ".word")
            if fm == 8: ops = f"FR{fn}"
            elif fm == 9: ops = f"FR{fn}"
            elif fm in (4,5): ops = f"FR{fn}"
            elif fm in (0,): ops = f"FPUL,FR{fn}"
            elif fm == 1: ops = f"FR{fn},FPUL"
            elif fm == 2: ops = f"FPUL,FR{fn}"
            elif fm == 3: ops = f"FR{fn},FPUL"
            else: ops = f"0x{opcode:04X}"
        else: mn = ".word"; ops = f"0x{opcode:04X}"
    else:
        mn = ".word"; ops = f"0x{opcode:04X}"

    return opcode, mn, ops, cmt, branch_target


def find_function_end(rom, start_addr, max_bytes):
    """Find the end of a function by tracking rts + delay slot,
    but only stop when all branch targets have been covered."""
    branch_targets = set()
    pc = start_addr
    limit = start_addr + max_bytes
    rts_seen = False
    rts_delay = False
    max_target = start_addr

    while pc < limit:
        opcode, mn, ops, cmt, bt = disassemble_one(rom, pc)

        if bt:
            branch_targets.add(bt)
            if bt > max_target:
                max_target = bt

        if rts_delay:
            # Just executed delay slot after rts
            if pc >= max_target:
                remaining = [t for t in branch_targets if t > pc]
                if not remaining:
                    return pc  # end here
            rts_delay = False

        if rts_seen:
            rts_delay = True
            rts_seen = False

        if mn == "rts":
            rts_seen = True

        # Also handle bra (unconditional branch) as potential function end
        if mn == "bra" and bt and bt < start_addr:
            # Tail call to another function - this may be the end
            # Process delay slot then check
            pass

        pc += 2

    return pc


def disassemble_function(rom, stage_info):
    """Disassemble one function and return results."""
    name = stage_info["name"]
    start = stage_info["addr"]
    max_len = stage_info["max_len"]

    end_pc = find_function_end(rom, start, max_len)

    # First pass: collect branch targets and literal refs
    branch_targets = set()
    lit_addrs = set()
    bsr_targets = set()
    jsr_refs = set()
    ram_refs = set()
    cal_refs = set()

    pc = start
    while pc <= end_pc:
        opcode, mn, ops, cmt, bt = disassemble_one(rom, pc)
        if bt:
            branch_targets.add(bt)
        if mn == "bsr" and bt:
            bsr_targets.add(bt)
        if (opcode >> 12) == 0xD:
            disp = opcode & 0xFF
            la = (pc & ~3) + 4 + disp * 4
            if la + 3 < len(rom):
                lit_addrs.add(la)
                val = read_u32(rom, la)
                cls = classify_addr(val)
                if cls == "RAM":
                    ram_refs.add(val)
                elif cls == "CAL":
                    cal_refs.add(val)
                elif cls == "ROM" and val != 0:
                    jsr_refs.add(val)
        if (opcode >> 12) == 0x9:
            disp = opcode & 0xFF
            la = pc + 4 + disp * 2
            lit_addrs.add(la)
        pc += 2

    # Build labels
    labels = {}
    for t in sorted(branch_targets):
        if t >= start and t <= end_pc + 20:
            labels[t] = f"L_{t:05X}"

    results = {
        "name": name,
        "start": start,
        "end": end_pc,
        "branch_targets": branch_targets,
        "lit_addrs": lit_addrs,
        "bsr_targets": bsr_targets,
        "jsr_refs": jsr_refs,
        "ram_refs": ram_refs,
        "cal_refs": cal_refs,
        "labels": labels,
        "instructions": [],
    }

    # Second pass: full disassembly
    pc = start
    while pc <= end_pc:
        opcode, mn, ops, cmt, bt = disassemble_one(rom, pc)
        lbl = labels.get(pc, "")
        results["instructions"].append({
            "pc": pc, "opcode": opcode, "mn": mn, "ops": ops,
            "cmt": cmt, "bt": bt, "label": lbl,
        })
        pc += 2

    return results


def print_function(rom, result):
    """Pretty-print disassembly results for one function."""
    name = result["name"]
    start = result["start"]
    end = result["end"]
    size = end - start + 2

    print()
    print("=" * 110)
    print(f"  {name}")
    print(f"  Address: 0x{start:05X} - 0x{end:05X}  ({size} bytes, {size//2} instructions)")
    print("=" * 110)
    print()

    # Print instructions
    for inst in result["instructions"]:
        if inst["label"]:
            print(f"\n{inst['label']}:")
        line = f"  {inst['pc']:05X}: {inst['opcode']:04X}  {inst['mn']:12s} {inst['ops']:36s}"
        if inst["cmt"]:
            line += f"; {inst['cmt']}"
        print(line)

    # Literal pool
    if result["lit_addrs"]:
        print(f"\n  {'-'*80}")
        print(f"  LITERAL POOL")
        print(f"  {'─'*80}")
        for la in sorted(result["lit_addrs"]):
            if la + 3 < len(rom):
                val = read_u32(rom, la)
                cls = classify_addr(val)
                line = f"  0x{la:05X}: 0x{val:08X}  [{cls}]"
                if cls == "RAM":
                    label = KNOWN_LABELS.get(val, "")
                    line += f"  {label}"
                elif cls == "CAL":
                    try:
                        fv = read_float(rom, val)
                        line += f"  -> {fv}"
                    except:
                        pass
                elif cls == "ROM":
                    sub_label = KNOWN_SUBS.get(val, "")
                    line += f"  {sub_label}"
                print(line)

    # RAM addresses
    if result["ram_refs"]:
        print(f"\n  {'-'*80}")
        print(f"  RAM ADDRESSES REFERENCED")
        print(f"  {'─'*80}")
        for addr in sorted(result["ram_refs"]):
            label = KNOWN_LABELS.get(addr, "")
            print(f"  0x{addr:08X}  {label}")

    # Calibration values
    if result["cal_refs"]:
        print(f"\n  {'-'*80}")
        print(f"  CALIBRATION REFERENCES")
        print(f"  {'─'*80}")
        for addr in sorted(result["cal_refs"]):
            try:
                fv = read_float(rom, addr)
                raw = read_u32(rom, addr)
                print(f"  0x{addr:05X}: raw=0x{raw:08X}  float={fv:12.6f}")
            except:
                print(f"  0x{addr:05X}: (read error)")

    # Subroutine calls
    all_calls = result["bsr_targets"] | result["jsr_refs"]
    if all_calls:
        print(f"\n  {'-'*80}")
        print(f"  SUBROUTINE CALLS")
        print(f"  {'─'*80}")
        for addr in sorted(all_calls):
            sub_label = KNOWN_SUBS.get(addr, "")
            print(f"  0x{addr:05X}  {sub_label}")

    # GBR-relative accesses
    gbr_accesses = []
    for inst in result["instructions"]:
        if "GBR" in inst["ops"]:
            gbr_accesses.append(inst)
    if gbr_accesses:
        print(f"\n  {'-'*80}")
        print(f"  GBR-RELATIVE ACCESSES")
        print(f"  {'─'*80}")
        for inst in gbr_accesses:
            print(f"  0x{inst['pc']:05X}: {inst['mn']} {inst['ops']}")


def main():
    import sys
    # Fix stdout encoding for Windows cp1252 consoles
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    print(f"Loading ROM: {ROM_PATH}")
    with open(ROM_PATH, "rb") as f:
        rom = f.read()
    print(f"ROM size: {len(rom)} bytes ({len(rom)//1024} KB)")

    # ================================================================
    # INJECTOR_DATA write-site scan — runs standalone, no stage output
    # ================================================================
    if "--injdata" in sys.argv:
        # Scan for write sites of the INJECTOR_DATA struct at FFFF895C.
        # Strategy A: find pool entries loading any address in FFFF8940..FFFF89D0
        #             (struct base candidates), then look ±64 instructions for
        #             fmov.s FRm,@(R0,Rn)  (opcode 0xFnm7, nib3==7)
        #             or fmov.s FRm,@Rn    (opcode 0xFnmA, nib3==A)
        # Strategy B: brute-force scan all 0xFnm7 opcodes, filter by backward
        #             pool loads into FFFF8940..FFFF89D0 within a window.
        STRUCT_LO = 0xFFFF8940
        STRUCT_HI = 0xFFFF89D0
        TARGET    = 0xFFFF895C

        print()
        print("=" * 110)
        print("  INJECTOR_DATA (0xFFFF895C) WRITE-SITE SCAN")
        print("  Scanning for fmov.s indexed stores (0xFnm7) near struct-base pool loads")
        print("=" * 110)

        # Pass 1 — collect all pool entry offsets that load into struct range
        struct_pool_users = {}   # pool_offset -> (pool_value, [(code_offset, dest_rn)])
        for off in range(0, len(rom) - 3, 2):
            w = read_u16(rom, off)
            if (w >> 12) != 0xD:
                continue
            disp = w & 0xFF
            n    = (w >> 8) & 0xF
            la   = (off & ~3) + 4 + disp * 4
            if la + 3 >= len(rom):
                continue
            val = read_u32(rom, la)
            if STRUCT_LO <= val <= STRUCT_HI:
                if la not in struct_pool_users:
                    struct_pool_users[la] = (val, [])
                struct_pool_users[la][1].append((off, n))

        print(f"\n  Pool entries in FFFF895C+-0x80 struct range: {len(struct_pool_users)}")
        for la, (val, users) in sorted(struct_pool_users.items()):
            print(f"    Pool 0x{la:05X} -> 0x{val:08X}  used by {len(users)} mov.l refs")

        # Pass 2 — for each pool user, look +-80 bytes for fmov.s writes
        print()
        print("  Checking +-80 bytes around each pool-load site for fmov.s FR,@(R0,Rn):")
        WINDOW = 80
        found_writes = []
        seen_code = set()
        for la, (base_val, users) in sorted(struct_pool_users.items()):
            for (code_off, dest_rn) in users:
                lo = max(0, code_off - WINDOW)
                hi = min(len(rom) - 2, code_off + WINDOW)
                for scan in range(lo, hi, 2):
                    sw = read_u16(rom, scan)
                    if (sw >> 12) != 0xF:
                        continue
                    nib3 = sw & 0xF
                    if nib3 == 7:  # fmov.s FRm,@(R0,Rn)
                        fn = (sw >> 8) & 0xF
                        fm = (sw >> 4) & 0xF
                        key = (scan, code_off)
                        if key not in seen_code:
                            seen_code.add(key)
                            found_writes.append((scan, code_off, base_val, dest_rn, fm, fn, "fmov.s(idx)"))
                    elif nib3 == 0xA:  # fmov.s FRm,@Rn  direct
                        fn = (sw >> 8) & 0xF
                        fm = (sw >> 4) & 0xF
                        if fn == dest_rn:
                            key = (scan, code_off)
                            if key not in seen_code:
                                seen_code.add(key)
                                found_writes.append((scan, code_off, base_val, dest_rn, fm, fn, "fmov.s(dir)"))

        if not found_writes:
            print("  *** No indexed fmov.s writes found near struct-base pool loads ***")
        else:
            print(f"  Found {len(found_writes)} candidate write sites:")
            for (scan, pool_user, base_val, dest_rn, fm, fn, kind) in sorted(found_writes):
                sw = read_u16(rom, scan)
                dist = scan - pool_user
                print(f"    code@0x{scan:05X}: {sw:04X}  {kind} FR{fm}->@(R0,R{fn})  "
                      f"[base 0x{base_val:08X} loaded into R{dest_rn} @ 0x{pool_user:05X}, dist={dist:+d}]")

        # Pass 3 — brute-force: scan entire ROM for fmov.s indexed stores 0xFnm7,
        # then check if any register in the backward window was loaded with
        # a value in [STRUCT_LO, STRUCT_HI].
        print()
        print("  Pass 3 -- brute-force: all fmov.s FR,@(R0,Rn) in ROM filtered by nearby struct load:")
        WINDOW2 = 96
        brute_hits = []
        for off in range(0, len(rom) - 2, 2):
            w = read_u16(rom, off)
            if (w >> 12) != 0xF or (w & 0xF) != 7:
                continue
            fn = (w >> 8) & 0xF
            fm = (w >> 4) & 0xF
            # Look backward for any mov.l @pool,Rn that loads into struct range
            lo2 = max(0, off - WINDOW2)
            base_found = None
            for scan2 in range(lo2, off, 2):
                sw2 = read_u16(rom, scan2)
                if (sw2 >> 12) != 0xD:
                    continue
                disp2 = sw2 & 0xFF
                n2    = (sw2 >> 8) & 0xF
                la2   = (scan2 & ~3) + 4 + disp2 * 4
                if la2 + 3 >= len(rom):
                    continue
                val2 = read_u32(rom, la2)
                if STRUCT_LO <= val2 <= STRUCT_HI:
                    base_found = (scan2, n2, val2)
            if base_found:
                (bl, bn, bv) = base_found
                brute_hits.append((off, fn, fm, bl, bn, bv))

        if not brute_hits:
            print("  *** No brute-force hits ***")
        else:
            print(f"  {len(brute_hits)} brute-force candidate write sites:")
            prev_fn_addr = -999
            for (off, fn, fm, bl, bn, bv) in sorted(brute_hits):
                w = read_u16(rom, off)
                dist = off - bl
                if abs(off - prev_fn_addr) > 4:
                    print(f"    fmov.s@0x{off:05X}: {w:04X}  FR{fm}->@(R0,R{fn})  "
                          f"base 0x{bv:08X} in R{bn}@0x{bl:05X} (dist {dist})")
                prev_fn_addr = off
        return

    print()
    print("=" * 110)
    print("  AFC PIPELINE -- UNANALYZED STAGES DISASSEMBLY")
    print("  AE5L600L (2013 Subaru WRX MT) — SH7058 (SH-2)")
    print("=" * 110)
    print()
    print("  Pipeline order (from CL_fuel_dispatcher @ 0x33304):")
    print("    Stage 1: cl_fuel_target_B  @ 0x33D1C  [ALREADY ANALYZED]")
    print("    Stage 2: cl_fuel_target_A  @ 0x33CC0  [ALREADY ANALYZED]")
    print("    Stage 3: func_33658        @ 0x33658  <-- THIS SCRIPT")
    print("    Stage 4: func_33FCE        @ 0x33FCE  <-- THIS SCRIPT")
    print("    Stage 5: func_340A0        @ 0x340A0  <-- THIS SCRIPT")
    print("    Stage 6: AFC_PI_controller @ 0x342A8  [ALREADY ANALYZED]")
    print("    Stage 7: func_3439E        @ 0x3439E  <-- THIS SCRIPT")
    print("    Stage 8: func_343CE        @ 0x343CE  <-- THIS SCRIPT")
    print("    Tail:    fuel_aggregator   @ 0x33460  [ALREADY ANALYZED]")

    all_results = []
    for stage in STAGES:
        result = disassemble_function(rom, stage)
        all_results.append(result)
        print_function(rom, result)

    # ================================================================
    # MAIN IPW CALCULATOR
    # ================================================================
    if "--ipw" in __import__("sys").argv:
        for stage in STAGES_IPW:
            result = disassemble_function(rom, stage)
            print_function(rom, result)
        return

    if "--helpers" in __import__("sys").argv:
        for stage in STAGES_HELPERS:
            result = disassemble_function(rom, stage)
            print_function(rom, result)
        return

    if "--inject" in __import__("sys").argv:
        for stage in STAGES_INJECT:
            result = disassemble_function(rom, stage)
            print_function(rom, result)
        return

    if "--injdata2" in __import__("sys").argv:
        for stage in STAGES_INJDATA:
            result = disassemble_function(rom, stage)
            print_function(rom, result)
        return

    if "--tableb" in __import__("sys").argv:
        for stage in STAGES_TABLEB:
            result = disassemble_function(rom, stage)
            print_function(rom, result)
        return

    # ================================================================
    # CROSS-STAGE SUMMARY
    # ================================================================
    print()
    print("=" * 110)
    print("  CROSS-STAGE SUMMARY")
    print("=" * 110)

    # All RAM addresses across all stages
    all_ram = set()
    all_cal = set()
    all_subs = set()
    for r in all_results:
        all_ram |= r["ram_refs"]
        all_cal |= r["cal_refs"]
        all_subs |= r["bsr_targets"] | r["jsr_refs"]

    print(f"\n  All RAM addresses referenced across stages 3-5, 7-8:")
    for addr in sorted(all_ram):
        label = KNOWN_LABELS.get(addr, "")
        # Determine which stages reference this
        stages = []
        for r in all_results:
            if addr in r["ram_refs"]:
                stages.append(r["name"].split(":")[0].strip())
        print(f"    0x{addr:08X}  {label:40s}  [{', '.join(stages)}]")

    print(f"\n  All calibration addresses referenced:")
    for addr in sorted(all_cal):
        try:
            fv = read_float(rom, addr)
            print(f"    0x{addr:05X} = {fv:12.6f}")
        except:
            print(f"    0x{addr:05X} = (error)")

    print(f"\n  All subroutine calls:")
    for addr in sorted(all_subs):
        sub_label = KNOWN_SUBS.get(addr, "")
        stages = []
        for r in all_results:
            if addr in r["bsr_targets"] | r["jsr_refs"]:
                stages.append(r["name"].split(":")[0].strip())
        print(f"    0x{addr:05X}  {sub_label:40s}  [{', '.join(stages)}]")


if __name__ == "__main__":
    main()
