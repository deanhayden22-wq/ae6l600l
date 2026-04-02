#!/usr/bin/env python3
"""
Map GBR-relative data structures for top GBR bases.

For each GBR base, finds all GBR-relative accesses (mov.b/mov.w/mov.l @(disp,GBR))
within the function that sets GBR, revealing the complete struct layout.

SH-2 GBR-relative instructions:
  mov.b @(disp,GBR),R0: 11000100 dddddddd  (C4dd) - byte read
  mov.w @(disp,GBR),R0: 11000101 dddddddd  (C5dd) - word read (disp*2)
  mov.l @(disp,GBR),R0: 11000110 dddddddd  (C6dd) - long read (disp*4)
  mov.b R0,@(disp,GBR): 11000000 dddddddd  (C0dd) - byte write
  mov.w R0,@(disp,GBR): 11000001 dddddddd  (C1dd) - word write (disp*2)
  mov.l R0,@(disp,GBR): 11000010 dddddddd  (C2dd) - long write (disp*4)
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

KNOWN_RAM = {
    # Hardware / peripheral
    0xFFFF4024: "adc_raw_workspace",
    0xFFFF6155: "adc_channel_status",
    # Calibration mirror / descriptor
    0xFFFF2398: "desc_table_copy_2398",
    0xFFFF24A8: "desc_partial_copy_24A8",
    0xFFFF2D88: "desc_partial_copy_2D88",
    0xFFFF2F84: "desc_table_copy_2F84",
    0xFFFF30E4: "desc_partial_copy_30E4",
    0xFFFF3480: "cal_mirror_base",
    0xFFFF34EC: "desc_table_copy_34EC",
    0xFFFF35E4: "cal_mirror_lookup",
    0xFFFF3682: "cal_output_buffer",
    0xFFFF3718: "cal_descriptor_queue",
    # Sensor / boost
    0xFFFF5C98: "ssm_diagnostic_GBR",
    0xFFFF69F0: "boost_pressure",
    # Fuel / CL-OL
    0xFFFF726C: "transient_flag",
    0xFFFF7448: "clol_mode_flag",
    0xFFFF77BC: "fuel_pipeline_base",
    0xFFFF798C: "timing_state_var",
    0xFFFF7AB4: "afl_multiplier_output",
    0xFFFF7AF4: "fuel_ipw_state_B",
    # Timing
    0xFFFF7E90: "warmup_blend_state",
    0xFFFF7EC0: "base_advance_state",
    0xFFFF7F0C: "timing_blend_app",
    0xFFFF7F10: "base_timing_state",
    0xFFFF7FBC: "timing_final_advance",
    0xFFFF7FD4: "timing_ws_init",
    0xFFFF8000: "timing_percond_state",
    0xFFFF8C9C: "timing_workspace_A",
    # Knock / FLKC
    0xFFFF80FC: "knock_det_GBR_base",
    0xFFFF81BA: "KNOCK_FLAG",
    0xFFFF81BB: "KNOCK_BANK_FLAG",
    0xFFFF81F0: "knock_state_base",
    0xFFFF81F8: "knock_thresh_config",
    0xFFFF8210: "knock_window_state",
    0xFFFF821C: "knock_thresh_calc",
    0xFFFF8258: "roughness_correction",
    0xFFFF8277: "roughness_detection",
    0xFFFF8290: "flkc_fg_GBR_base",
    0xFFFF8298: "knock_percyl_state",
    0xFFFF829E: "knock_window_update",
    # Idle control
    0xFFFF837B: "idle_dispatch_workspace",
    0xFFFF837E: "idle_control_GBR",
    0xFFFF8387: "knock_flkc_workspace",
    0xFFFF83AC: "idle_workspace_GBR",
    # Ignition / boost ext
    0xFFFF8B50: "boost_wastegate_calc",
    # Scheduler
    0xFFFF8EA8: "sched_control_GBR",
    0xFFFF8EC7: "sched_control_secondary",
    0xFFFF8F08: "cl_readiness_A_input",
    0xFFFF9094: "sched_task_GBR",
    0xFFFF91C4: "sched_queue_base",
    0xFFFF980C: "sched_periodic_GBR",
    0xFFFF9FA8: "sched_timer_B",
    0xFFFF9FC6: "sched_timer_base",
    # Diagnostics
    0xFFFFA156: "diag_state_B_start",
    0xFFFFA160: "diag_monitor_GBR",
    0xFFFFA198: "egr_diag_state",
    0xFFFFAC6C: "diag_protocol_GBR",
    0xFFFFAF70: "diag_state_A_start",
    # Sensor structs
    0xFFFF8998: "sensor_struct_8998",
}


def find_gbr_accesses_near(rom, ldc_pc, search_range=400):
    """Find all GBR-relative accesses near a ldc Rn,GBR instruction."""
    accesses = []  # (offset, size, rw, pc)

    start = max(0, ldc_pc - 20)
    end = min(len(rom) - 1, ldc_pc + search_range)

    for pc in range(start, end, 2):
        if pc + 2 > len(rom):
            break
        word = r_u16(rom, pc)
        hi_byte = (word >> 8) & 0xFF
        disp = word & 0xFF

        if hi_byte == 0xC4:  # mov.b @(disp,GBR),R0
            accesses.append((disp, 1, 'R', pc))
        elif hi_byte == 0xC5:  # mov.w @(disp*2,GBR),R0
            accesses.append((disp * 2, 2, 'R', pc))
        elif hi_byte == 0xC6:  # mov.l @(disp*4,GBR),R0
            accesses.append((disp * 4, 4, 'R', pc))
        elif hi_byte == 0xC0:  # mov.b R0,@(disp,GBR)
            accesses.append((disp, 1, 'W', pc))
        elif hi_byte == 0xC1:  # mov.w R0,@(disp*2,GBR)
            accesses.append((disp * 2, 2, 'W', pc))
        elif hi_byte == 0xC2:  # mov.l R0,@(disp*4,GBR)
            accesses.append((disp * 4, 4, 'W', pc))

        # Stop at RTS
        if word == 0x000B:
            break

    return accesses


def main():
    rom = load_rom()
    rom_len = len(rom)

    # Find all GBR base sets and their access patterns
    gbr_structures = defaultdict(lambda: defaultdict(lambda: {'size': 0, 'rw': set(), 'pcs': []}))

    for pc in range(0, rom_len - 1, 2):
        word = r_u16(rom, pc)
        # ldc Rn,GBR: 0100nnnn00011110
        if (word & 0xF0FF) == 0x401E:
            rn = (word >> 8) & 0xF
            # Find the mov.l that loaded Rn
            for back in range(1, 10):
                prev_pc = pc - back * 2
                if prev_pc < 0:
                    break
                prev_word = r_u16(rom, prev_pc)
                if (prev_word >> 12) == 0xD and ((prev_word >> 8) & 0xF) == rn:
                    disp = prev_word & 0xFF
                    lit_addr = (prev_pc & ~3) + 4 + disp * 4
                    if lit_addr + 4 <= rom_len:
                        gbr_val = r_u32(rom, lit_addr)
                        if 0xFFFF0000 <= gbr_val <= 0xFFFFFFFF:
                            accesses = find_gbr_accesses_near(rom, pc)
                            for offset, size, rw, apc in accesses:
                                entry = gbr_structures[gbr_val][offset]
                                entry['size'] = max(entry['size'], size)
                                entry['rw'].add(rw)
                                entry['pcs'].append(apc)
                    break

    # Output structures for top GBR bases
    # Sort by number of unique offsets (struct complexity)
    ranked = sorted(gbr_structures.items(),
                    key=lambda x: len(x[1]), reverse=True)

    print(f"GBR Structure Analysis: {len(gbr_structures)} unique GBR bases\n")

    for gbr_addr, offsets in ranked[:25]:
        label = KNOWN_RAM.get(gbr_addr, "")
        max_offset = max(offsets.keys()) if offsets else 0
        total_accesses = sum(len(e['pcs']) for e in offsets.values())

        print(f"\n{'='*80}")
        print(f"GBR = 0x{gbr_addr:08X}  {label}")
        print(f"  Struct size: >= {max_offset + 4} bytes  |  "
              f"{len(offsets)} unique fields  |  {total_accesses} total accesses")
        print(f"{'='*80}")

        SIZE_NAMES = {1: 'byte', 2: 'word', 4: 'long'}
        for offset in sorted(offsets.keys()):
            entry = offsets[offset]
            size_name = SIZE_NAMES.get(entry['size'], f"{entry['size']}B")
            rw = '/'.join(sorted(entry['rw']))
            abs_addr = gbr_addr + offset
            known = KNOWN_RAM.get(abs_addr, "")
            ref_count = len(entry['pcs'])
            sample_pcs = ', '.join(f"0x{p:05X}" for p in sorted(set(entry['pcs']))[:3])

            print(f"  +0x{offset:03X} (0x{abs_addr:08X}): {size_name:>4} {rw:>3} "
                  f"[{ref_count:>3}x] {known:>20}  from: {sample_pcs}")


if __name__ == "__main__":
    main()
