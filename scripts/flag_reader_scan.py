#!/usr/bin/env python3
"""
Scan the ROM for flag reader template functions in the 0x020000-0x02FFFF region.
Generates Ghidra label statements for ImportAE5L600L.java.

Templates detected:
  T1: Standard flag reader (10 bytes) - D6xx 6060 8801 000B 0029
  T1v: Variant with R5 (10 bytes) - D5xx 6050 8801 ...
  T1w: Word variant (10 bytes) - D6xx 6061 8801 000B 0029
  T2: DTC flag reader (16 bytes) - D6xx 6260 2228 8F01 E002 E000 000B 0009
  T3: Bit-test reader (12 bytes) - D5xx 6050 8801 8B01 000B E001
  T4: Inverted flag reader - D6xx 6060 8800 000B 0029

Also detects variants with different registers and comparison values.
"""

import struct
import os
import re
from pathlib import Path

base = Path(__file__).resolve().parent.parent
with open(base / 'rom' / 'ae5l600l.bin', 'rb') as f:
    rom = f.read()


def read_u16(addr):
    return struct.unpack('>H', rom[addr:addr+2])[0]

def read_u32(addr):
    return struct.unpack('>I', rom[addr:addr+4])[0]

def resolve_movl_pc(addr, op):
    """Resolve mov.l @(disp,PC),Rn literal pool reference."""
    disp = op & 0xFF
    pool_addr = (addr & ~3) + 4 + disp * 4
    if pool_addr + 4 <= len(rom):
        return read_u32(pool_addr)
    return None


# Known labels to avoid duplicates
def get_existing_labels(java_path):
    existing = set()
    with open(java_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            for m in re.finditer(r'(?:label|labelComment)\(0x([0-9A-Fa-f]+)L?', line):
                existing.add(int(m.group(1), 16))
    return existing


# RAM address -> semantic name mapping
RAM_NAMES = {
    # Engine state flags (FFFF64xx-66xx)
    0xFFFF6350: "ect_valid",
    0xFFFF6364: "map_valid",
    0xFFFF6430: "iat_valid",
    0xFFFF6455: "fuel_state_A",
    0xFFFF6456: "fuel_state_B",
    0xFFFF6458: "throttle_valid",
    0xFFFF64D8: "throttle_raw_valid",
    0xFFFF653C: "o2_valid",
    0xFFFF6540: "o2_state_B",
    0xFFFF6552: "sensor_valid",
    0xFFFF655C: "sensor_state_B",
    0xFFFF65A8: "vss_valid",
    0xFFFF65A9: "vss_state",
    0xFFFF65AA: "gear_state",
    0xFFFF65AE: "engine_state_byte",
    0xFFFF65B1: "accel_pedal_idle",
    0xFFFF65BD: "cruise_state",
    0xFFFF65BF: "cruise_active",
    0xFFFF65C0: "engine_cranking",
    0xFFFF65C4: "engine_start_state",
    0xFFFF65C5: "engine_running",
    0xFFFF65E8: "warmup_state",
    0xFFFF65F6: "cl_active",
    0xFFFF65FC: "engine_load_state",
    0xFFFF6624: "rpm_valid",
    0xFFFF67EC: "fuel_system_state_A",
    0xFFFF67FC: "afl_ready",
    0xFFFF6810: "injection_state",
    0xFFFF6811: "injection_mode",
    0xFFFF683C: "ign_state",
    0xFFFF68A4: "boost_state",
    0xFFFF68C8: "maf_state_A",
    0xFFFF68EF: "maf_state_B",
    0xFFFF6948: "sensor_range_A",
    0xFFFF69AC: "boost_pressure_state",
    0xFFFF69F0: "boost_pressure_valid",
    0xFFFF69F8: "atm_pressure_state",
    0xFFFF69FC: "atm_pressure_valid",
    0xFFFF6A18: "maf_conditioning_state",
    0xFFFF6A29: "maf_valid",
    0xFFFF6A64: "maf_range_state",
    0xFFFF6A74: "tps_state_A",
    0xFFFF6A84: "tps_state_B",
    0xFFFF6AC0: "batt_voltage_state",
    0xFFFF6AC4: "batt_valid",
    0xFFFF6AD1: "can_state_A",
    0xFFFF6ACD: "can_state_B",
    0xFFFF6AD8: "vehicle_state_A",
    0xFFFF6B20: "idle_state_A",
    0xFFFF6B30: "idle_target_state",
    0xFFFF6BB8: "ac_state",
    0xFFFF6BBC: "ac_request",
    0xFFFF6BD0: "fan_state",
    0xFFFF6BDC: "elec_load_state",
    0xFFFF6C48: "can_data_valid",

    # Fuel timing (FFFF7xxx)
    0xFFFF71E0: "fuel_state_C",
    0xFFFF71E2: "fuel_state_D",
    0xFFFF71E6: "fuel_enrichment_state",
    0xFFFF71EA: "fuel_enrichment_active",
    0xFFFF7244: "fuel_trim_state",
    0xFFFF7278: "fuel_correction_state",
    0xFFFF726C: "fuel_system_ready",
    0xFFFF726D: "transient_state_flag_B",
    0xFFFF72A0: "fuel_pump_state",
    0xFFFF72B4: "fuel_cut_state",
    0xFFFF7354: "ol_state_A",
    0xFFFF7374: "ol_state_B",
    0xFFFF73B0: "enrichment_calc_state",
    0xFFFF73E0: "enrichment_output_state",
    0xFFFF7710: "fuel_pipeline_state",
    0xFFFF7828: "aggregator_state",
    0xFFFF7830: "aggregator_state_B",
    0xFFFF7858: "ipw_state",
    0xFFFF7874: "injector_state",
    0xFFFF787E: "afl_range_state",
    0xFFFF787F: "afl_airflow_range_idx",
    0xFFFF7888: "afl_workspace_state",
    0xFFFF78AC: "afl_state_C",
    0xFFFF7950: "ol_enrichment_state",
    0xFFFF79C0: "timing_control_state",
    0xFFFF79CC: "timing_state_B",
    0xFFFF7A2C: "ol_transition_state",
    0xFFFF7AA0: "afl_output_state",
    0xFFFF7A78: "fuel_trim_state_B",
    0xFFFF7AB8: "afl_final_state",
    0xFFFF7AF8: "ipw_correction_state",
    0xFFFF7B7C: "fuel_state_E",
    0xFFFF7B8C: "fuel_state_F",
    0xFFFF7BE4: "fuel_blend_state",
    0xFFFF7C30: "timing_comp_state",
    0xFFFF7C34: "timing_comp_state_B",
    0xFFFF7C6C: "timing_mode_state",
    0xFFFF7C80: "timing_final_state",
    0xFFFF7C82: "timing_final_state_B",
    0xFFFF7C92: "timing_output_state",
    0xFFFF7CCA: "timing_knock_state",
    0xFFFF7D04: "timing_advance_state",
    0xFFFF7D08: "timing_advance_state_B",
    0xFFFF7D11: "timing_mode_byte",
    0xFFFF7D28: "timing_workspace_state",
    0xFFFF7D2A: "timing_workspace_state_B",

    # Scheduler / knock-FLKC
    0xFFFF8020: "knock_workspace_state",
    0xFFFF8080: "knock_detection_state",
    0xFFFF8318: "idle_state_B",
    0xFFFF8330: "idle_state_C",
    0xFFFF8366: "idle_dispatch_state",
    0xFFFF8378: "idle_dispatch_state_B",
    0xFFFF837C: "idle_dispatch_state_C",
    0xFFFF8389: "idle_flag_A",
    0xFFFF83A5: "idle_workspace_state",
    0xFFFF83AA: "idle_workspace_state_B",
    0xFFFF8391: "idle_mode_state",
    0xFFFF8570: "knock_state_A",
    0xFFFF8584: "knock_state_B",
    0xFFFF85D4: "knock_threshold_state",
    0xFFFF8634: "engine_ctrl_state",
    0xFFFF8694: "engine_ctrl_state_B",
    0xFFFF8680: "engine_ctrl_state_C",
    0xFFFF8A84: "sensor_struct_state",
    0xFFFF8B1C: "boost_workspace_state",
    0xFFFF8C98: "timing_ext_state",
    0xFFFF8E38: "scheduler_state_A",
    0xFFFF8E44: "scheduler_state_B",
    0xFFFF8E64: "scheduler_state_C",
    0xFFFF8E65: "scheduler_state_D",

    # Scheduler (FFFF9xxx)
    0xFFFF90B2: "sched_dispatch_state",
    0xFFFF9358: "evap_state_A",
    0xFFFF95FC: "learn_state_A",
    0xFFFF96A8: "diag_mode_active",
    0xFFFF96BC: "learn_state_B",
    0xFFFF96F0: "learn_convergence_state",
    0xFFFF972B: "learn_flag_A",
    0xFFFF972C: "learn_flag_B",
    0xFFFF9735: "learn_flag_C",
    0xFFFF972A: "learn_flag_D",
    0xFFFF9740: "learn_flag_E",

    # Diagnostic state (FFFFAxxx)
    0xFFFFA156: "diag_state_B_start",
    0xFFFFA161: "diag_monitor_byte_A",
    0xFFFFA163: "diag_monitor_byte_B",
    0xFFFFA166: "diag_monitor_byte_C",
    0xFFFFA168: "diag_monitor_byte_D",
    0xFFFFA16B: "diag_monitor_byte_E",
    0xFFFFA176: "diag_maturation_counter",
    0xFFFFA19C: "diag_state_extended",
    0xFFFFA450: "diag_fault_state_A",
    0xFFFFA714: "diag_maturation_state_A",
    0xFFFFA716: "diag_maturation_state_B",
    0xFFFFA72A: "diag_maturation_state_C",
    0xFFFFA72B: "diag_maturation_state_D",
    0xFFFFA734: "diag_maturation_state_E",
    0xFFFFA735: "diag_maturation_state_F",
    0xFFFFA736: "diag_maturation_state_G",
    0xFFFFA738: "diag_maturation_state_H",
    0xFFFFA739: "diag_maturation_state_I",
}

# DTC flag addresses -> P-code mapping (FFFF9704-FFFF9742)
DTC_CODES = {
    0xFFFF9704: "P0031", 0xFFFF9705: "P0032", 0xFFFF9706: "P0037",
    0xFFFF9707: "P0038", 0xFFFF9708: "P0068", 0xFFFF9709: "P0101",
    0xFFFF970A: "P0102", 0xFFFF970B: "P0103", 0xFFFF970C: "P0107",
    0xFFFF970D: "P0108", 0xFFFF970E: "P0111", 0xFFFF970F: "P0112",
    0xFFFF9710: "P0113", 0xFFFF9711: "P0117", 0xFFFF9712: "P0118",
    0xFFFF9713: "P0122", 0xFFFF9714: "P0123", 0xFFFF9715: "P0125",
    0xFFFF9716: "P0128", 0xFFFF9717: "P0131", 0xFFFF9718: "P0132",
    0xFFFF9719: "P0134", 0xFFFF971A: "P0137", 0xFFFF971B: "P0138",
    0xFFFF971C: "P0140", 0xFFFF971D: "P0141", 0xFFFF971E: "P0171",
    0xFFFF971F: "P0172", 0xFFFF9720: "P0222", 0xFFFF9721: "P0223",
    0xFFFF9722: "P0244", 0xFFFF9723: "P0245", 0xFFFF9724: "P0246",
    0xFFFF9725: "P0301", 0xFFFF9726: "P0302", 0xFFFF9727: "P0303",
    0xFFFF9728: "P0304", 0xFFFF9729: "P0327", 0xFFFF972A: "P0328",
    0xFFFF972B: "P0336", 0xFFFF972C: "P0340", 0xFFFF972D: "P0345",
    0xFFFF972E: "P0420", 0xFFFF972F: "P0461", 0xFFFF9730: "P0462",
    0xFFFF9731: "P0463", 0xFFFF9732: "P0500", 0xFFFF9733: "P0506",
    0xFFFF9734: "P0507", 0xFFFF9735: "P0604", 0xFFFF9736: "P2096",
    0xFFFF9737: "P2097", 0xFFFF9738: "P2101", 0xFFFF9739: "P2102",
    0xFFFF973A: "P2103", 0xFFFF973B: "P2109", 0xFFFF973C: "P2122",
    0xFFFF973D: "P2123", 0xFFFF973E: "P2127", 0xFFFF973F: "P2128",
    0xFFFF9740: "P2135", 0xFFFF9741: "P2138", 0xFFFF9742: "P1443",
}


def scan_region(start, end):
    """Scan ROM region for flag reader templates."""
    results = []
    addr = start

    while addr < end - 10:
        op0 = read_u16(addr)
        op1 = read_u16(addr + 2)
        op2 = read_u16(addr + 4)
        op3 = read_u16(addr + 6)
        op4 = read_u16(addr + 8)

        # Template 1: Standard flag reader (10 bytes)
        # Dnxx 60n0 88yy 000B 0029  where n=register, yy=compare value
        if ((op0 >> 12) == 0xD and
            op1 in (0x6060, 0x6050, 0x6040, 0x6020) and
            (op2 >> 8) == 0x88 and
            op3 == 0x000B and
            op4 == 0x0029):

            src_reg = (op0 >> 8) & 0xF
            read_reg = (op1 >> 8) & 0xF
            cmp_val = op2 & 0xFF
            ram_addr = resolve_movl_pc(addr, op0)

            if ram_addr and 0xFFFF0000 <= ram_addr <= 0xFFFFFFFF:
                results.append({
                    'addr': addr,
                    'template': 'T1',
                    'size': 10,
                    'ram': ram_addr,
                    'cmp_val': cmp_val,
                })
                addr += 10
                continue

        # Template 1w: Word read variant
        # Dnxx 60n1 88yy 000B 0029
        if ((op0 >> 12) == 0xD and
            op1 in (0x6061, 0x6051, 0x6041) and
            (op2 >> 8) == 0x88 and
            op3 == 0x000B and
            op4 == 0x0029):

            ram_addr = resolve_movl_pc(addr, op0)
            if ram_addr and 0xFFFF0000 <= ram_addr <= 0xFFFFFFFF:
                results.append({
                    'addr': addr,
                    'template': 'T1w',
                    'size': 10,
                    'ram': ram_addr,
                    'cmp_val': op2 & 0xFF,
                })
                addr += 10
                continue

        # Template 2: DTC flag reader (16 bytes)
        # Dnxx 6260 2228 8F01 E002 E000 000B 0009
        # Note: register for mov.b is always R6->R2 in this pattern
        if (addr < end - 16 and
            (op0 >> 12) == 0xD and
            op1 == 0x6260 and
            op2 == 0x2228 and
            op3 == 0x8F01 and
            op4 == 0xE002 and
            read_u16(addr + 10) == 0xE000 and
            read_u16(addr + 12) == 0x000B and
            read_u16(addr + 14) == 0x0009):

            ram_addr = resolve_movl_pc(addr, op0)
            if ram_addr and 0xFFFF0000 <= ram_addr <= 0xFFFFFFFF:
                results.append({
                    'addr': addr,
                    'template': 'T2',
                    'size': 16,
                    'ram': ram_addr,
                    'cmp_val': 2,
                })
                addr += 16
                continue

        # Template 2b: DTC flag reader with R5 register variant
        if (addr < end - 16 and
            (op0 >> 12) == 0xD and
            op1 == 0x6250 and
            op2 == 0x2228 and
            op3 == 0x8F01 and
            op4 == 0xE002 and
            read_u16(addr + 10) == 0xE000 and
            read_u16(addr + 12) == 0x000B and
            read_u16(addr + 14) == 0x0009):

            ram_addr = resolve_movl_pc(addr, op0)
            if ram_addr and 0xFFFF0000 <= ram_addr <= 0xFFFFFFFF:
                results.append({
                    'addr': addr,
                    'template': 'T2',
                    'size': 16,
                    'ram': ram_addr,
                    'cmp_val': 2,
                })
                addr += 16
                continue

        # Template 5: Tiny return stub (4 bytes)
        # 000B E0xx  (rts; mov #imm, R0)
        # Only match if this looks like a standalone function start
        # (not inside a T2 pattern - check previous instruction)
        if (op0 == 0x000B and
            (op1 >> 8) == 0xE0):
            prev = read_u16(addr - 2) if addr > start else 0
            # Skip if this is the tail of a T2 (after E000)
            if prev != 0xE000 and prev != 0x8F01:
                ret_val = op1 & 0xFF
                results.append({
                    'addr': addr,
                    'template': 'T5',
                    'size': 4,
                    'ram': None,
                    'cmp_val': ret_val,
                })
                addr += 4
                continue

        # Template 3: Bit-test / inverted compare (12 bytes)
        # Dnxx 60n0 88yy 8B01 000B E0zz
        if ((op0 >> 12) == 0xD and
            op1 in (0x6060, 0x6050, 0x6040) and
            (op2 >> 8) == 0x88 and
            op3 == 0x8B01 and  # bf +2
            op4 == 0x000B):    # rts

            ram_addr = resolve_movl_pc(addr, op0)
            if ram_addr and 0xFFFF0000 <= ram_addr <= 0xFFFFFFFF:
                results.append({
                    'addr': addr,
                    'template': 'T3',
                    'size': 12,
                    'ram': ram_addr,
                    'cmp_val': op2 & 0xFF,
                })
                addr += 12
                continue

        # Template 4: tst + movt pattern (10 bytes)
        # Dnxx 60n0 C801 000B 0029
        if ((op0 >> 12) == 0xD and
            op1 in (0x6060, 0x6050) and
            (op2 & 0xFF00) == 0xC800 and  # tst #imm,R0
            op3 == 0x000B and
            op4 == 0x0029):

            ram_addr = resolve_movl_pc(addr, op0)
            if ram_addr and 0xFFFF0000 <= ram_addr <= 0xFFFFFFFF:
                results.append({
                    'addr': addr,
                    'template': 'T4',
                    'size': 10,
                    'ram': ram_addr,
                    'cmp_val': op2 & 0xFF,
                })
                addr += 10
                continue

        addr += 2  # Advance by instruction size

    return results


def generate_label(entry):
    """Generate a label name from the scan result."""
    ram = entry['ram']
    addr = entry['addr']
    template = entry['template']

    # Tiny return stubs (no RAM read)
    if template == 'T5':
        ret_val = entry['cmp_val']
        return f"return_{ret_val}_stub_{addr & 0xFFFF:04X}", \
               f"Tiny return stub: always returns {ret_val}."

    if ram is None:
        return f"flag_stub_{addr & 0xFFFF:04X}", f"Flag stub at 0x{addr:06X}."

    # DTC flag readers get P-code names
    if ram in DTC_CODES:
        code = DTC_CODES[ram]
        return f"diag_check_{code}", f"DTC flag reader: returns 2 if {code} (0x{ram:08X}) is set."

    # Known RAM names
    if ram in RAM_NAMES:
        name = RAM_NAMES[ram]
        if template == 'T4':
            return f"check_{name}_bit", f"Bit-test reader: tests 0x{ram:08X} ({name})."
        return f"check_{name}", f"Flag reader: reads 0x{ram:08X} ({name})."

    # Generic based on RAM region
    short = ram & 0xFFFF
    if 0x6000 <= short < 0x7000:
        prefix = "check_adc"
    elif 0x7000 <= short < 0x8000:
        prefix = "check_fuel"
    elif 0x8000 <= short < 0x9000:
        prefix = "check_eng"
    elif 0x9000 <= short < 0xA000:
        prefix = "check_sched"
    elif 0xA000 <= short < 0xB000:
        prefix = "check_diag"
    else:
        prefix = "check_flag"

    return f"{prefix}_{short:04X}", f"Flag reader ({template}): reads 0x{ram:08X}."


def main():
    java_path = base / 'disassembly' / 'ghidra' / 'ImportAE5L600L.java'
    existing = get_existing_labels(java_path)

    # Scan the 0x020000-0x030000 region
    results = scan_region(0x020000, 0x030000)

    print(f"Found {len(results)} flag reader functions in 0x020000-0x02FFFF")
    print(f"Existing labels: {len(existing)}")

    # Also scan 0x05D000-0x05EA00 for diag monitor stubs
    results2 = scan_region(0x05D000, 0x05EA00)
    print(f"Found {len(results2)} flag reader stubs in 0x05D000-0x05EA00")

    all_results = results + results2

    # Filter out already-labeled
    new_labels = []
    skipped = 0
    for entry in all_results:
        if entry['addr'] in existing:
            skipped += 1
            continue
        name, comment = generate_label(entry)
        new_labels.append((entry['addr'], name, comment, entry))

    print(f"Skipped (already labeled): {skipped}")
    print(f"New labels to generate: {len(new_labels)}")

    # Sort by address
    new_labels.sort(key=lambda x: x[0])

    # Template distribution
    templates = {}
    for _, _, _, e in new_labels:
        t = e['template']
        templates[t] = templates.get(t, 0) + 1
    print(f"\nBy template: {templates}")

    # Write output
    output_path = base / 'disassembly' / 'ghidra' / 'flag_reader_labels_generated.txt'
    with open(output_path, 'w') as f:
        f.write("        // =====================================================================\n")
        f.write("        // FLAG READER LABELS (auto-generated from ROM byte pattern scan)\n")
        f.write(f"        // {len(new_labels)} flag/DTC reader functions in 0x020000-0x02FFFF\n")
        f.write("        // =====================================================================\n\n")

        current_template = None
        for addr, name, comment, entry in new_labels:
            t = entry['template']
            if t != current_template:
                current_template = t
                tname = {'T1': 'Standard flag readers (cmp/eq #1)',
                         'T1w': 'Word flag readers',
                         'T2': 'DTC flag readers (returns 2/0)',
                         'T3': 'Inverted compare readers',
                         'T4': 'Bit-test readers'}
                f.write(f"\n        // --- {tname.get(t, t)} ---\n")

            safe_comment = comment.replace('"', '\\"')
            f.write(f'        count += labelComment(0x{addr:08X}L, "{name}",\n')
            f.write(f'            "{safe_comment}");\n')

    print(f"\nWrote {len(new_labels)} labels to: {output_path}")


if __name__ == '__main__':
    main()
