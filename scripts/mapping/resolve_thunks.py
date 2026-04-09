#!/usr/bin/env python3
"""
Resolve thunk functions in the AE5L600L ROM.

Thunks are small trampolines: typically just a mov.l + jmp @Rn pattern.
Ghidra identified 101 thunks but left them as thunk_FUN_*.
This script resolves each thunk to its actual target and maps it
to known labels where possible.
"""
import os
import struct
import sys

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

KNOWN_FUNCS = {
    0x0BE554: "uint16_add_sat", 0x0BE53C: "uint8_add_sat",
    0x0BDBCC: "desc_read_float_safe", 0x0BDCB6: "desc_read_int_safe",
    0x000317C: "interrupt_priority_set", 0x0003190: "interrupt_restore",
    0x0BE81C: "critical_section_enter", 0x0BE82C: "critical_section_exit",
    0x0BE56C: "float_clamp_range",
    0x0BE830: "table_desc_1d_float", 0x0BE8E4: "table_desc_2d_typed",
    0x0BE960: "float_min", 0x0BE970: "float_max",
    0x0BE9A0: "uint8_pack", 0x0BE980: "uint8_unpack",
    0x0BE9B0: "uint16_pack", 0x0BE990: "uint16_unpack",
    0x0BE608: "float_deadband_check", 0x0BE628: "float_safe_div",
    0x0BEA40: "float_lerp", 0x0BEAB0: "float_abs_diff",
    0x022F92: "check_cl_active", 0x022CF4: "check_engine_running",
    0x02F8EA: "check_transient_flag", 0x03AB20: "check_engine_status",
    0x09EDEC: "dtc_set_code", 0x09ED90: "dtc_clear_code",
    0x033304: "afc_dispatcher", 0x0342A8: "afc_pi_controller",
    0x036070: "clol_main_transition",
    0x021A40: "frontO2_process", 0x01FE54: "frontO2_comp_atm",
    0x033CC4: "cl_fuel_target_calc",
    0x043750: "knock_wrapper", 0x043782: "knock_detector",
    0x045BFE: "flkc_path_J", 0x0463BA: "flkc_paths_FG",
    0x030674: "PSE_code_entry", 0x0320AE: "fuel_correction_final",
    0x04A94C: "sched_periodic_dispatch",
    0x00000C0C: "Entry", 0x00000BAC: "NMI_Handler",
    0x058902: "frontO2_scaling_lookup", 0x004A2C: "frontO2_scaling_init",
}


def resolve_thunk(rom, addr, max_instrs=6):
    """Try to resolve a thunk at addr to its target.

    Common patterns:
    1. mov.l @(disp,PC),Rn + jmp @Rn (+ delay slot nop)
    2. bra target (unconditional branch)
    """
    rom_len = len(rom)

    for i in range(max_instrs):
        pc = addr + i * 2
        if pc + 2 > rom_len:
            return None
        word = r_u16(rom, pc)

        # BRA disp12 (unconditional branch = simplest thunk)
        if (word >> 12) == 0xA:
            disp = sign_extend_12(word & 0xFFF)
            target = (pc + 4) + (disp << 1)
            if 0 <= target < rom_len:
                return target

        # JMP @Rn: 0100nnnn00101011
        if (word & 0xF0FF) == 0x402B:
            rn = (word >> 8) & 0xF
            # Look back for mov.l @(disp,PC),Rn
            for back in range(1, i + 2):
                prev_pc = addr + (i - back) * 2
                prev_word = r_u16(rom, prev_pc)
                if (prev_word >> 12) == 0xD and ((prev_word >> 8) & 0xF) == rn:
                    disp = prev_word & 0xFF
                    lit_addr = (prev_pc & ~3) + 4 + disp * 4
                    if lit_addr + 4 <= rom_len:
                        target = r_u32(rom, lit_addr)
                        if 0x100 <= target < rom_len:
                            return target
                    break

    return None


def find_thunks(rom):
    """Find thunk-like patterns: very short functions (2-4 instructions) ending in JMP or BRA."""
    rom_len = len(rom)
    thunks = []

    # Strategy: look for mov.l + jmp patterns at aligned addresses
    # These are typically in code regions (before 0xA0000)
    for addr in range(0x100, min(rom_len, 0xA0000), 2):
        word = r_u16(rom, addr)

        # Pattern 1: mov.l @(disp,PC),Rn followed immediately by JMP @Rn
        if (word >> 12) == 0xD:
            rn = (word >> 8) & 0xF
            if addr + 4 <= rom_len:
                next_word = r_u16(rom, addr + 2)
                # JMP @Rn
                if next_word == (0x402B | (rn << 8)):
                    target = resolve_thunk(rom, addr)
                    if target:
                        thunks.append((addr, target, "mov.l+jmp"))
                        continue

        # Pattern 2: BRA target (1 instruction thunk)
        if (word >> 12) == 0xA:
            disp = sign_extend_12(word & 0xFFF)
            target = (addr + 4) + (disp << 1)
            # Only count as thunk if next instruction is nop (delay slot filler)
            if addr + 2 < rom_len:
                next_word = r_u16(rom, addr + 2)
                if next_word == 0x0009 and 0x100 <= target < rom_len:
                    # Check if this address is actually called (not just any BRA)
                    # Skip — too many false positives with bare BRA+nop
                    pass

    return thunks


def main():
    rom = load_rom()
    print(f"Loaded ROM: {len(rom)} bytes\n")

    # Find all thunk-like patterns
    thunks = find_thunks(rom)

    # Deduplicate and filter: only keep thunks whose targets are known or significant
    print(f"Found {len(thunks)} potential mov.l+jmp thunks\n")

    # Check which thunks point to known functions
    known_thunks = []
    unknown_thunks = []
    for thunk_addr, target, pattern in thunks:
        label = KNOWN_FUNCS.get(target, "")
        if label:
            known_thunks.append((thunk_addr, target, label, pattern))
        else:
            unknown_thunks.append((thunk_addr, target, pattern))

    print(f"Thunks to known functions: {len(known_thunks)}")
    print(f"Thunks to unknown functions: {len(unknown_thunks)}")

    print(f"\n{'='*80}")
    print(f"THUNKS TO KNOWN FUNCTIONS")
    print(f"{'='*80}")
    for thunk_addr, target, label, pattern in sorted(known_thunks):
        print(f"  0x{thunk_addr:05X} -> 0x{target:05X} ({label})  [{pattern}]")

    print(f"\n{'='*80}")
    print(f"THUNKS TO UNKNOWN FUNCTIONS (top 50 by target)")
    print(f"{'='*80}")

    # Group by target
    target_groups = {}
    for thunk_addr, target, pattern in unknown_thunks:
        if target not in target_groups:
            target_groups[target] = []
        target_groups[target].append(thunk_addr)

    for target in sorted(target_groups.keys()):
        thunk_addrs = target_groups[target]
        thunk_str = ", ".join(f"0x{a:05X}" for a in sorted(thunk_addrs)[:4])
        if len(thunk_addrs) > 4:
            thunk_str += f" (+{len(thunk_addrs)-4})"
        print(f"  0x{target:05X} <- {len(thunk_addrs)} thunk(s): {thunk_str}")

    # Also find thunks that are called frequently (by scanning BSR/JSR to thunk addresses)
    print(f"\n{'='*80}")
    print(f"THUNK CALL FREQUENCY (thunks that are actually called)")
    print(f"{'='*80}")

    all_thunk_addrs = set(t[0] for t in thunks)

    # Quick scan for calls to thunk addresses
    thunk_call_counts = {}
    for pc in range(0, len(rom) - 1, 2):
        word = r_u16(rom, pc)
        if (word >> 12) == 0xB:  # BSR
            disp = sign_extend_12(word & 0xFFF)
            target = (pc + 4) + (disp << 1)
            if target in all_thunk_addrs:
                thunk_call_counts[target] = thunk_call_counts.get(target, 0) + 1

    for thunk_addr, count in sorted(thunk_call_counts.items(), key=lambda x: -x[1])[:30]:
        # Find what this thunk resolves to
        resolved = resolve_thunk(rom, thunk_addr)
        label = KNOWN_FUNCS.get(resolved, f"0x{resolved:05X}") if resolved else "???"
        print(f"  0x{thunk_addr:05X} ({count:>3} calls) -> {label}")


if __name__ == "__main__":
    main()
