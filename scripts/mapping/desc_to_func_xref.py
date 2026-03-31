#!/usr/bin/env python3
"""
Cross-reference calibration descriptors to their calling functions.

Scans for ROM pointers in the descriptor region (0xAA000-0xB0000) loaded
via literal pool, then maps them to the function context (which task or
named function loads them).
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
def r_f32(rom, a): return struct.unpack_from(">f", rom, a)[0]

# Function ranges for context
FUNC_RANGES = [
    (0x030674, 0x030A78, "PSE_code"),
    (0x033304, 0x033658, "afc_dispatcher"),
    (0x033658, 0x033DBD, "afc_sensor_prep"),
    (0x033DBE, 0x033FCE, "afc_cl_decision"),
    (0x033FCE, 0x0340A0, "afc_target_calc"),
    (0x0340A0, 0x0342A8, "afc_pi_output"),
    (0x0342A8, 0x034398, "afc_pi_controller"),
    (0x034488, 0x037B74, "afl_pipeline"),
    (0x036070, 0x036979, "clol_transition"),
    (0x03697A, 0x03AB1F, "clol_hysteresis+"),
    (0x03F00C, 0x03F368, "task49_base_advance"),
    (0x03F368, 0x03FCA2, "task50_timing_blend"),
    (0x03FCA2, 0x03FFD6, "task30_base_timing"),
    (0x03FFD6, 0x04004A, "task31_timing_blend_ratio"),
    (0x04004A, 0x040516, "task32_timing_blend_app"),
    (0x040516, 0x040918, "task34_timing_throttle"),
    (0x040918, 0x0415B8, "task33_timing_ws_init"),
    (0x0415B8, 0x0418AC, "task36_timing_percond"),
    (0x0418AC, 0x0419BA, "task35_timing_corr"),
    (0x0419BA, 0x042A78, "task37_timing_multiaxis"),
    (0x042A78, 0x042B90, "task38_ign_output"),
    (0x042B90, 0x042D20, "task39_ign_maf_corr"),
    (0x042D20, 0x042D54, "task40_ign_calc_a"),
    (0x042D54, 0x042F48, "task41_ign_calc_b"),
    (0x042F48, 0x04317A, "task42_timing_comp_b"),
    (0x04317A, 0x0431B0, "task44_timing_lu_a"),
    (0x0431B0, 0x04322A, "task45_timing_lu_b"),
    (0x04322A, 0x043368, "task43_timing_out_load"),
    (0x043368, 0x043464, "task46_inj_mps_timing"),
    (0x043464, 0x04359C, "task47_mapswitch_lowpw"),
    (0x04359C, 0x043750, "task48_final_timing"),
    (0x043750, 0x04438C, "knock_area"),
    (0x04438C, 0x046A00, "knock+flkc_tasks"),
    (0x04BC20, 0x04E100, "task54_idle_control"),
    (0x054852, 0x054A00, "task51_boost"),
    (0x0549FA, 0x054C00, "task52_boost_feedback"),
    (0x058000, 0x058A00, "diag_framework"),
    (0x05CC00, 0x05D000, "sensor_diag"),
    (0x0602DC, 0x060500, "task53_diag_monitor"),
    (0x066580, 0x066E00, "task56_evap_purge"),
    (0x06F0B8, 0x06F200, "task58_maf_diag"),
    (0x0758CA, 0x075C00, "task57_egr_emissions"),
    (0x0900B4, 0x090200, "task55_mps_diag"),
    (0x021A40, 0x022CF4, "frontO2_process"),
    (0x01FE54, 0x021A40, "frontO2_area"),
    (0x0301E4, 0x030674, "fuel_pw_calc"),
    (0x02E000, 0x0301E4, "fuel_area"),
]


def find_func(pc):
    """Find which named function a PC belongs to."""
    for start, end, name in FUNC_RANGES:
        if start <= pc < end:
            return name
    # Rough categorization by address range
    if pc < 0x10000: return "system_init"
    if 0x10000 <= pc < 0x20000: return "hw_drivers"
    if 0x20000 <= pc < 0x30000: return "sensor_processing"
    if 0x30000 <= pc < 0x40000: return "fuel_control"
    if 0x40000 <= pc < 0x50000: return "timing_knock"
    if 0x50000 <= pc < 0x60000: return "boost_idle_diag"
    if 0x60000 <= pc < 0x80000: return "emissions_diag"
    if 0x80000 <= pc < 0xA0000: return "comms_diag"
    return f"code_0x{pc:05X}"


def is_valid_axis(rom, ptr, size):
    if ptr + size * 4 > len(rom):
        return False
    vals = [r_f32(rom, ptr + i*4) for i in range(size)]
    for v in vals:
        if v != v or abs(v) > 1e8:
            return False
    increasing = sum(1 for i in range(len(vals)-1) if vals[i+1] >= vals[i])
    return increasing >= len(vals) * 0.7


def classify_desc(rom, addr):
    """Classify a descriptor by its axis content."""
    rom_len = len(rom)
    if addr + 12 > rom_len:
        return "unknown"

    b1 = rom[addr + 1]  # size or Y_size
    b3 = rom[addr + 3]  # 0=1D, >0=X_size

    if b3 == 0:
        # 1D
        size = b1
        axis_ptr = r_u32(rom, addr + 4)
        if not (0x1000 <= axis_ptr < rom_len):
            return "invalid"
        if size < 2 or size > 64:
            return "invalid"
        if not is_valid_axis(rom, axis_ptr, min(size, 3)):
            return "invalid"

        axis_vals = [r_f32(rom, axis_ptr + i*4) for i in range(min(size, 3))]
        first = axis_vals[0]
        last_full = r_f32(rom, axis_ptr + (size-1)*4)

        # Classify by axis range
        if -50 <= first <= -30 and 80 <= last_full <= 130:
            return "1D_vs_ECT"
        if 0 <= first <= 2 and 5000 <= last_full <= 8000:
            return "1D_vs_RPM"
        if 0 <= first <= 1 and 2 <= last_full <= 5:
            return "1D_vs_Load"
        if first >= 200 and last_full >= 1000:
            return "1D_vs_RPM_high"
        if -2 <= first <= 0 and 0.5 <= last_full <= 2:
            return "1D_vs_Ratio"
        return f"1D[{size}]_axis[{first:.0f}..{last_full:.0f}]"
    else:
        return f"2D[{b1}x{b3}]"


def main():
    rom = load_rom()
    rom_len = len(rom)
    print(f"Loaded ROM: {rom_len} bytes\n")

    # Scan all literal pool loads of descriptor-region pointers
    # Descriptor region: 0xAA000-0xB2000
    desc_refs = defaultdict(list)  # desc_addr -> [pc, ...]

    for pc in range(0, rom_len - 1, 2):
        word = r_u16(rom, pc)
        if (word >> 12) == 0xD:
            disp = word & 0xFF
            lit_addr = (pc & ~3) + 4 + disp * 4
            if lit_addr + 4 <= rom_len:
                val = r_u32(rom, lit_addr)
                if 0xAA000 <= val < 0xB2000:
                    desc_refs[val].append(pc)

    print(f"Descriptor pointers referenced: {len(desc_refs)}")

    # Map each to function context
    func_descs = defaultdict(list)  # func_name -> [(desc_addr, classification)]
    desc_funcs = defaultdict(list)  # desc_addr -> [func_name]

    for desc_addr, pcs in desc_refs.items():
        cls = classify_desc(rom, desc_addr)
        funcs_seen = set()
        for pc in pcs:
            func = find_func(pc)
            if func not in funcs_seen:
                funcs_seen.add(func)
                func_descs[func].append((desc_addr, cls))
                desc_funcs[desc_addr].append(func)

    # Output by function
    print(f"\n{'='*90}")
    print(f"DESCRIPTORS BY FUNCTION")
    print(f"{'='*90}")

    for func in sorted(func_descs.keys()):
        descs = func_descs[func]
        print(f"\n  {func} ({len(descs)} descriptors):")
        for desc_addr, cls in sorted(descs):
            print(f"    0x{desc_addr:05X}  {cls}")

    # Summary: functions with most descriptors
    print(f"\n{'='*90}")
    print(f"FUNCTIONS BY DESCRIPTOR COUNT")
    print(f"{'='*90}")
    for func, descs in sorted(func_descs.items(), key=lambda x: -len(x[1])):
        types = defaultdict(int)
        for _, cls in descs:
            types[cls.split('_')[0] if '_' in cls else cls] += 1
        type_str = ", ".join(f"{k}:{v}" for k, v in sorted(types.items(), key=lambda x: -x[1]))
        print(f"  {func:<35} {len(descs):>3} descs  ({type_str})")

    # Descriptors referenced from multiple functions (shared tables)
    print(f"\n{'='*90}")
    print(f"SHARED DESCRIPTORS (referenced from multiple functions)")
    print(f"{'='*90}")
    for desc_addr in sorted(desc_funcs.keys()):
        funcs = desc_funcs[desc_addr]
        if len(funcs) >= 2:
            cls = classify_desc(rom, desc_addr)
            print(f"  0x{desc_addr:05X} {cls:<30} <- {', '.join(funcs)}")


if __name__ == "__main__":
    main()
