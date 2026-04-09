#!/usr/bin/env python3
"""
Build a call graph for each of the 59 scheduler tasks.

For each task function, traces:
1. BSR calls (direct) -> resolved target
2. JSR calls (indirect via literal pool) -> resolved target
3. RAM addresses loaded via literal pool (FFFF####)
4. ROM descriptor pointers loaded (0xAxxxx range)
5. Calibration table pointers loaded (0xCxxxx-0xDxxxx range)

Outputs a per-task dependency map.
"""
import os
import struct
import sys
from collections import defaultdict

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

def r_u16(rom, a): return struct.unpack_from(">H", rom, a)[0]
def r_u32(rom, a): return struct.unpack_from(">I", rom, a)[0]

def sign_extend_12(v):
    return v - 0x1000 if v & 0x800 else v

# Known labels
KNOWN_FUNCS = {
    0x0BE554: "uint16_add_sat", 0x0BE53C: "uint8_add_sat",
    0x0BDBCC: "desc_read_float_safe", 0x0BDCB6: "desc_read_int_safe",
    0x000317C: "interrupt_priority_set", 0x0003190: "interrupt_restore",
    0x0BE81C: "critical_section_enter", 0x0BE82C: "critical_section_exit",
    0x0BE56C: "float_clamp_range", 0x0BE5D8: "axis_frac_to_uint16",
    0x0BE5A8: "axis_frac_to_uint8", 0x0BE598: "fmac_interp_uint16",
    0x0BE588: "fmac_interp_uint8",
    0x0BE830: "table_desc_1d_float", 0x0BE8E4: "table_desc_2d_typed",
    0x0BE874: "LowPW_TableProcessor", 0x0BE8AC: "table_desc_1d_uint16",
    0x0BE960: "float_min", 0x0BE970: "float_max",
    0x0BE9A0: "uint8_pack", 0x0BE980: "uint8_unpack",
    0x0BE9B0: "uint16_pack", 0x0BE990: "uint16_unpack",
    0x0BE608: "float_deadband_check", 0x0BE628: "float_safe_div",
    0x0BEA40: "float_lerp", 0x0BEAB0: "float_abs_diff",
    0x022F92: "check_cl_active", 0x022CF4: "check_engine_running",
    0x02F8EA: "check_transient_flag", 0x03AB20: "check_engine_status",
    0x09EDEC: "dtc_set_code", 0x09ED90: "dtc_clear_code",
    0x0582D2: "diag_wrapper_set", 0x0582AC: "diag_check_status",
    0x0E6E4: "sched_event_post", 0x002B8C: "isr_context_save",
    0x06BC4: "io_write_word_atomic", 0x06BF0: "io_write_2word_atomic",
    0x0DCE4: "desc_table_walk", 0x06B5A: "calc_table_offset",
    0x0B9E0: "ram_word_update", 0x10800: "event_notify",
    0x0BE654: "int32_div_sat", 0x0BE9C0: "int32_fixmul",
    0x0BEA6C: "int_fixpoint_lerp",
    0x043750: "knock_wrapper", 0x043782: "knock_detector",
    0x043470: "LowPW_GateFunction",
}

KNOWN_RAM = {
    0xFFFF6624: "rpm_current", 0xFFFF6350: "ect_current",
    0xFFFF65FC: "engine_load", 0xFFFF67EC: "atm_pressure",
    0xFFFF65C0: "throttle_pos", 0xFFFF63F8: "iat_current",
    0xFFFF6254: "maf_current", 0xFFFF61CC: "vehicle_speed",
    0xFFFF6898: "manifold_pressure", 0xFFFF69F0: "boost_pressure",
    0xFFFF81BA: "KNOCK_FLAG", 0xFFFF81BB: "KNOCK_BANK_FLAG",
    0xFFFF3234: "IAM_value", 0xFFFF323C: "FLKC_BASE_STEP",
    0xFFFF7448: "clol_mode_flag", 0xFFFF7AB4: "afl_multiplier",
    0xFFFF8E98: "sensor_fault_flags", 0xFFFF65F6: "cl_active_flag",
    0xFFFF65C5: "engine_running_flag", 0xFFFF895C: "injector_data",
    0xFFFF85D7: "fuel_system_state", 0xFFFF7814: "afc_p_term",
    0xFFFF8EDC: "sched_disable_flag", 0xFFFF320C: "maf_correction",
}

# Task table
TASKS = [
    (0, 0x044188, "task00_timing_percyl"),
    (1, 0x045970, "task01_knock_timing_fb"),
    (2, 0x045098, "task02_knock_window"),
    (3, 0x045670, "task03_knock_thresh"),
    (4, 0x0455E6, "task04_knock_thresh"),
    (5, 0x04530A, "task05_knock_det"),
    (6, 0x045354, "task06_knock_det"),
    (7, 0x0450AE, "task07_knock_det"),
    (8, 0x044E04, "task08_knock_window"),
    (9, 0x044DB0, "task09_knock_det"),
    (10, 0x0448F4, "task10_knock_config"),
    (11, 0x04438C, "task11_knock_flag"),
    (12, 0x043D68, "task12_knock_post"),
    (13, 0x045A3E, "task13_rough_corr"),
    (14, 0x044834, "task14_knock_thresh_lu"),
    (15, 0x045A84, "task15_rough_corr"),
    (16, 0x045BBC, "task16_flkc_pre"),
    (17, 0x045B44, "task17_flkc_pre"),
    (18, 0x045BFE, "task18_flkc_J"),
    (19, 0x045E96, "task19_flkc_post"),
    (20, 0x0459F6, "task20_knock_win_upd"),
    (21, 0x0467AE, "task21_knock_win_upd"),
    (22, 0x0461D2, "task22_knock_percyl"),
    (23, 0x0467F4, "task23_knock_cyl_track"),
    (24, 0x0469A4, "task24_flkc_output"),
    (25, 0x0463BA, "task25_flkc_FG"),
    (26, 0x046978, "task26_flkc_output"),
    (27, 0x046296, "task27_knock_timing"),
    (28, 0x045DF8, "task28_flkc_recovery"),
    (29, 0x044296, "task29_timing_percyl"),
    (30, 0x03FCA2, "task30_base_timing"),
    (31, 0x03FFD6, "task31_timing_blend_ratio"),
    (32, 0x04004A, "task32_timing_blend_app"),
    (33, 0x040918, "task33_timing_ws_init"),
    (34, 0x040516, "task34_timing_throttle"),
    (35, 0x0418AC, "task35_timing_corr"),
    (36, 0x0415B8, "task36_timing_percond"),
    (37, 0x0419BA, "task37_timing_multiaxis"),
    (38, 0x042A78, "task38_ign_output"),
    (39, 0x042B90, "task39_ign_maf_corr"),
    (40, 0x042D20, "task40_ign_calc_a"),
    (41, 0x042D54, "task41_ign_calc_b"),
    (42, 0x042F48, "task42_timing_comp_b"),
    (43, 0x04322A, "task43_timing_out_load"),
    (44, 0x04317A, "task44_timing_lu_a"),
    (45, 0x0431B0, "task45_timing_lu_b"),
    (46, 0x043368, "task46_inj_mps_timing"),
    (47, 0x043464, "task47_mapswitch_lowpw"),
    (48, 0x04359C, "task48_final_timing"),
    (49, 0x03F00C, "task49_base_advance"),
    (50, 0x03F368, "task50_timing_blend_int"),
    (51, 0x054852, "task51_boost_wg_calc"),
    (52, 0x0549FA, "task52_boost_feedback"),
    (53, 0x0602DC, "task53_diag_monitor"),
    (54, 0x04BC20, "task54_idle_control"),
    (55, 0x0900B4, "task55_mps_diag"),
    (56, 0x066580, "task56_evap_purge"),
    (57, 0x0758CA, "task57_egr_emissions"),
    (58, 0x06F0B8, "task58_maf_diag"),
]


def trace_function(rom, start_addr, max_instrs=500):
    """Trace a function and collect its calls, RAM refs, and ROM refs."""
    rom_len = len(rom)
    calls = []      # BSR/JSR targets
    ram_refs = []    # FFFF#### addresses loaded
    rom_refs = []    # ROM pointers loaded (descriptors, calibration)
    gbr_bases = []   # GBR base addresses

    pc = start_addr
    for _ in range(max_instrs):
        if pc + 2 > rom_len:
            break
        word = r_u16(rom, pc)

        # BSR disp12
        if (word >> 12) == 0xB:
            disp = sign_extend_12(word & 0xFFF)
            target = (pc + 4) + (disp << 1)
            if 0 <= target < rom_len:
                calls.append(target)

        # JSR @Rn — resolve via literal pool
        if (word & 0xF0FF) == 0x400B:
            rn = (word >> 8) & 0xF
            for back in range(1, 12):
                prev_pc = pc - back * 2
                if prev_pc < start_addr - 20:
                    break
                prev_word = r_u16(rom, prev_pc)
                if (prev_word >> 12) == 0xD and ((prev_word >> 8) & 0xF) == rn:
                    disp = prev_word & 0xFF
                    lit_addr = (prev_pc & ~3) + 4 + disp * 4
                    if lit_addr + 4 <= rom_len:
                        target = r_u32(rom, lit_addr)
                        if 0x100 <= target < rom_len:
                            calls.append(target)
                    break

        # mov.l @(disp,PC),Rn — check loaded values
        if (word >> 12) == 0xD:
            disp = word & 0xFF
            lit_addr = (pc & ~3) + 4 + disp * 4
            if lit_addr + 4 <= rom_len:
                val = r_u32(rom, lit_addr)
                if 0xFFFF0000 <= val <= 0xFFFFFFFF:
                    ram_refs.append(val)
                elif 0xA0000 <= val < 0xB2000:  # Descriptor region
                    rom_refs.append(('desc', val))
                elif 0xC0000 <= val < 0xE0000:  # Calibration region
                    rom_refs.append(('cal', val))

        # ldc Rn,GBR
        if (word & 0xF0FF) == 0x401E:
            rn = (word >> 8) & 0xF
            for back in range(1, 10):
                prev_pc = pc - back * 2
                if prev_pc < start_addr - 20:
                    break
                prev_word = r_u16(rom, prev_pc)
                if (prev_word >> 12) == 0xD and ((prev_word >> 8) & 0xF) == rn:
                    disp = prev_word & 0xFF
                    lit_addr = (prev_pc & ~3) + 4 + disp * 4
                    if lit_addr + 4 <= rom_len:
                        val = r_u32(rom, lit_addr)
                        if 0xFFFF0000 <= val:
                            gbr_bases.append(val)
                    break

        # Stop at RTS (but continue past BSR)
        if word == 0x000B:
            break

        pc += 2

    return {
        'calls': list(dict.fromkeys(calls)),
        'ram': list(dict.fromkeys(ram_refs)),
        'rom_refs': list(dict.fromkeys(rom_refs)),
        'gbr': list(dict.fromkeys(gbr_bases)),
    }


def main():
    rom = load_rom()
    print(f"Loaded ROM: {len(rom)} bytes\n")

    print(f"{'='*90}")
    print(f"TASK CALL GRAPH — 59 Scheduler Tasks")
    print(f"{'='*90}")

    for idx, addr, name in TASKS:
        deps = trace_function(rom, addr)

        print(f"\n{'-'*70}")
        print(f"[{idx:>2}] {name}  @ 0x{addr:05X}")
        print(f"{'-'*70}")

        # Calls
        if deps['calls']:
            named = []
            unnamed = []
            for target in deps['calls']:
                label = KNOWN_FUNCS.get(target, "")
                if label:
                    named.append(f"{label}")
                else:
                    unnamed.append(f"0x{target:05X}")
            if named:
                print(f"  Calls:    {', '.join(named)}")
            if unnamed:
                print(f"  Unknown:  {', '.join(unnamed[:6])}"
                      + (f" (+{len(unnamed)-6})" if len(unnamed) > 6 else ""))

        # GBR bases
        if deps['gbr']:
            gbr_strs = []
            for g in deps['gbr']:
                label = KNOWN_RAM.get(g, "")
                gbr_strs.append(f"0x{g:08X}" + (f" ({label})" if label else ""))
            print(f"  GBR:      {', '.join(gbr_strs)}")

        # RAM refs
        if deps['ram']:
            named_ram = []
            unnamed_ram = []
            for r in deps['ram']:
                label = KNOWN_RAM.get(r, "")
                if label:
                    named_ram.append(label)
                else:
                    unnamed_ram.append(f"0x{r:08X}")
            if named_ram:
                print(f"  RAM (known): {', '.join(named_ram)}")
            if unnamed_ram:
                print(f"  RAM (new):   {', '.join(unnamed_ram[:8])}"
                      + (f" (+{len(unnamed_ram)-8})" if len(unnamed_ram) > 8 else ""))

        # ROM refs (descriptors and calibration)
        descs = [r for t, r in deps['rom_refs'] if t == 'desc']
        cals = [r for t, r in deps['rom_refs'] if t == 'cal']
        if descs:
            print(f"  Descriptors: {', '.join(f'0x{d:05X}' for d in descs[:6])}"
                  + (f" (+{len(descs)-6})" if len(descs) > 6 else ""))
        if cals:
            print(f"  Calibration: {', '.join(f'0x{d:05X}' for d in cals[:6])}"
                  + (f" (+{len(cals)-6})" if len(cals) > 6 else ""))

    # Summary stats
    print(f"\n\n{'='*90}")
    print(f"CROSS-TASK ANALYSIS")
    print(f"{'='*90}")

    all_calls = defaultdict(list)
    all_ram = defaultdict(list)
    for idx, addr, name in TASKS:
        deps = trace_function(rom, addr)
        for c in deps['calls']:
            all_calls[c].append(name)
        for r in deps['ram']:
            all_ram[r].append(name)

    print(f"\nMost-called subroutines from tasks:")
    for target, callers in sorted(all_calls.items(), key=lambda x: -len(x[1]))[:15]:
        label = KNOWN_FUNCS.get(target, f"0x{target:05X}")
        print(f"  {label:<30} called by {len(callers)} tasks")

    print(f"\nMost-referenced RAM from tasks:")
    for addr, callers in sorted(all_ram.items(), key=lambda x: -len(x[1]))[:15]:
        label = KNOWN_RAM.get(addr, f"0x{addr:08X}")
        print(f"  {label:<30} read by {len(callers)} tasks")


if __name__ == "__main__":
    main()
