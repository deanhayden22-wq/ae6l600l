#!/usr/bin/env python3
"""
Dump the 59-entry periodic task table from the AE5L600L ROM.
Table starts at 0x4AD40, each entry is 4 bytes (pointer to function).
Terminator value: 0xFFFF8322

For each task, peek at the first ~32 instructions to identify:
- GBR context (ldc rN,GBR)
- RAM addresses referenced (mov.l literal pool loads of 0xFFFFxxxx)
- ROM table references (literal pool loads of 0x000Cxxxx calibration region)
- Subroutine calls (bsr/jsr)
- Float operations
"""
import struct
import sys

ROM_PATH = "/home/user/ae6l600l/AE5L600L 20g rev 20.3 tiny wrex.bin"

# Known function labels
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

# Known RAM addresses
KNOWN_RAM = {
    0xFFFF80FC: "knock_det_GBR",
    0xFFFF81BA: "KNOCK_FLAG",
    0xFFFF81BB: "KNOCK_BANK_FLAG",
    0xFFFF81D9: "task12_output",
    0xFFFF323C: "FLKC_BASE_STEP",
    0xFFFF8290: "flkc_fg_GBR",
    0xFFFF6350: "RPM",
    0xFFFF6624: "MAF",
    0xFFFF63CC: "ECT",
    0xFFFF5E94: "GEAR",
    0xFFFF3234: "IAM",
    0xFFFF7D18: "sched_status",
    0xFFFF8EDC: "sched_disable",
    0xFFFF3360: "flkc_output_table",
}

# Calibration region labels (partial)
CAL_LABELS = {
    0x0C009E: "WG_duty_freq",
    0x0C0BC8: "boost_disable_fuelcut",
}


def read_rom():
    with open(ROM_PATH, 'rb') as f:
        return f.read()


def read_u32(rom, off):
    return struct.unpack_from('>I', rom, off)[0]


def read_u16(rom, off):
    return struct.unpack_from('>H', rom, off)[0]


def sign_extend_8(val):
    return val - 0x100 if val & 0x80 else val


def sign_extend_12(val):
    return val - 0x1000 if val & 0x800 else val


def analyze_function(rom, func_addr, max_insns=64):
    """Analyze the first N instructions of a function.
    Returns dict with: gbr_values, ram_refs, cal_refs, calls, has_fpu, rom_refs
    """
    info = {
        'gbr_values': [],
        'ram_refs': {},       # addr -> context
        'cal_refs': {},       # addr -> context
        'calls_bsr': [],      # BSR targets
        'calls_jsr': False,   # has JSR (indirect)
        'has_fpu': False,
        'rom_refs': {},       # other ROM references
        'gbr_offsets': [],    # GBR-relative accesses
    }

    pc = func_addr
    for _ in range(max_insns):
        if pc + 1 >= len(rom):
            break
        code = read_u16(rom, pc)

        # Check for RTS (end of function, though may have delay slot)
        if code == 0x000B:
            # Process delay slot too
            pass

        top4 = (code >> 12) & 0xF
        n = (code >> 8) & 0xF
        m = (code >> 4) & 0xF

        # LDC Rn,GBR  (0x4n1E)
        if (code & 0xF0FF) == 0x401E:
            # Look backward for the mov.l that loaded this register
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

        # mov.w @(disp,PC),Rn - 16-bit literal pool load
        if top4 == 0x9:
            pass  # less useful for categorization

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
            # First instruction is BRA = thunk/trampoline
            disp = sign_extend_12(code & 0xFFF)
            jump_target = pc + 4 + disp * 2
            info['rom_refs'][jump_target] = KNOWN_FUNCS.get(jump_target, "thunk_target")

        pc += 2

    return info


def categorize(info, func_addr):
    """Try to categorize based on references."""
    categories = []

    # Check known functions
    if func_addr in KNOWN_FUNCS:
        return [KNOWN_FUNCS[func_addr]]

    ram = set(info['ram_refs'].keys())
    cal = set(info['cal_refs'].keys())

    # Knock-related
    knock_ram = {0xFFFF81BA, 0xFFFF81BB, 0xFFFF80FC}
    if ram & knock_ram:
        categories.append("knock")

    # FLKC-related
    flkc_ram = {0xFFFF8290, 0xFFFF323C, 0xFFFF3360}
    if ram & flkc_ram:
        categories.append("FLKC")

    # RPM reference
    if 0xFFFF6350 in ram:
        categories.append("uses_RPM")

    # ECT reference
    if 0xFFFF63CC in ram:
        categories.append("uses_ECT")

    # MAF reference
    if 0xFFFF6624 in ram:
        categories.append("uses_MAF")

    # FPU
    if info['has_fpu']:
        categories.append("FPU")

    # GBR usage
    if info['gbr_values']:
        categories.append("sets_GBR")

    if not categories:
        categories.append("unknown")

    return categories


def main():
    rom = read_rom()

    TABLE_START = 0x4AD40
    TERMINATOR = 0xFFFF8322

    print(f"; AE5L600L Periodic Task Table Dump")
    print(f"; Table base: 0x{TABLE_START:05X}")
    print(f"; ROM: {ROM_PATH}")
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
        if idx > 80:  # safety
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

    # Now print detailed analysis for each task
    print()
    print(f"; {'='*76}")
    print(f"; DETAILED ANALYSIS")
    print(f"; {'='*76}")

    for idx, tbl_off, func_addr in tasks:
        info = analyze_function(rom, func_addr)
        label = KNOWN_FUNCS.get(func_addr, f"task_{idx:02d}")

        print(f"\n; ─── Task [{idx:2d}]: 0x{func_addr:08X} ({label}) ───")

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


if __name__ == '__main__':
    main()
