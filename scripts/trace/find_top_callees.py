#!/usr/bin/env python3
"""
Find the most-called subroutines in the AE5L600L ROM.

Scans for:
  1. BSR disp12  — 12-bit signed displacement calls (opcode 1011xxxx)
  2. JSR @Rn     — indirect calls preceded by mov.l @(disp,PC),Rn literal pool loads
  3. JSR/N @Rn   — SH-2 no-delay-slot variant (4n4B)

Outputs top N call targets ranked by cross-reference count, with caller addresses.
"""
import os
import struct
import sys
from collections import defaultdict

# ─── ROM loading ────────────────────────────────────────────────────────────

ROM_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rom")

def load_rom():
    for fn in ["ae5l600l.bin"]:
        p = os.path.join(ROM_DIR, fn)
        if os.path.isfile(p):
            with open(p, "rb") as f:
                return f.read(), p
    # fallback: first .bin
    for fn in sorted(os.listdir(ROM_DIR)):
        if fn.lower().endswith(".bin"):
            p = os.path.join(ROM_DIR, fn)
            with open(p, "rb") as f:
                return f.read(), p
    print("ERROR: no ROM found", file=sys.stderr)
    sys.exit(1)

# ─── SH-2 instruction helpers ──────────────────────────────────────────────

def sign_extend_12(val):
    """Sign-extend 12-bit value."""
    if val & 0x800:
        return val - 0x1000
    return val

def sign_extend_8(val):
    """Sign-extend 8-bit value."""
    if val & 0x80:
        return val - 0x100
    return val

# ─── Known labels (from ImportAE5L600L.java) ────────────────────────────────

KNOWN_LABELS = {
    0x000BE608: "float_deadband_check",
    0x000BE628: "float_safe_div",
    0x000BE654: "int32_div_sat",
    0x000BE800: "float_clamp_with_step",
    0x000BE830: "table_desc_1d_float",
    0x000BE874: "LowPW_TableProcessor",
    0x000BE88C: "table_desc_2d_uint8",
    0x000BE8AC: "table_desc_1d_uint16",
    0x000BE8C4: "table_desc_2d_uint16",
    0x000BE8E4: "table_desc_2d_typed",
    0x000BE928: "table_desc_2d_uint8_int",
    0x000BE944: "table_desc_2d_uint16_int",
    0x000BE960: "float_max",
    0x000BE970: "float_min",
    0x000BE980: "uint8_unpack",
    0x000BE990: "uint16_unpack",
    0x000BE9A0: "uint8_pack",
    0x000BE9B0: "uint16_pack",
    0x000BE9C0: "int32_fixmul",
    0x000BEA40: "float_lerp",
    0x000BEA6C: "int_fixpoint_lerp",
    0x000BEA98: "int_sat_sub",
    0x000BEAB0: "float_abs_diff",
    0x000BEAB8: "int_count_shifts",
    0x000BEACC: "interp_1d_float32",
    0x000BEAE4: "interp_1d_int8",
    0x000BEB00: "interp_1d_int16",
    0x000BEB20: "interp_1d_uint8",
    0x000BEB40: "interp_1d_uint8_int",
    0x000BEB6C: "interp_1d_uint16",
    0x000BEB90: "interp_1d_uint16_int",
    0x000BEBC0: "interp_2d_float32",
    0x000BEBF0: "interp_2d_int8",
    0x000BEC1C: "interp_2d_int16",
    0x000BEC4C: "interp_2d_uint8",
    0x000BEC78: "interp_2d_uint16",
    0x000BECA8: "LowPW_AxisLookup",
    0x000BECDC: "axis_lookup_2d",
    0x000BED98: "axis_lookup_2d_typed",
    0x00043750: "knock_wrapper",
    0x00043782: "knock_detector",
    0x00045BFE: "flkc_path_J",
    0x000463BA: "flkc_paths_FG",
    0x00030674: "PSE_code_entry",
    0x00033304: "afc_dispatcher",
    0x000342A8: "afc_pi_controller",
    0x000340A0: "afc_pi_output",
    0x000320AE: "fuel_correction_final",
    0x00036070: "clol_main_transition",
    0x0003697A: "clol_hysteresis_sub",
    0x00021A40: "frontO2_process",
    0x0001FE54: "frontO2_comp_atm",
    0x00058902: "frontO2_scaling_lookup",
    0x00004A2C: "frontO2_scaling_init",
    0x0000E628: "sched_table_main",
    0x0004A94C: "sched_periodic_dispatch",
    0x0004AD40: "task_table",
    0x00000BAC: "NMI_Handler",
    0x00000C0C: "Entry",
    0x00033CC4: "cl_fuel_target_calc",
    0x00033D1C: "cl_fuel_target_B",
    0x00033CC0: "cl_fuel_target_A",
    0x00033658: "afc_sensor_prep",
    0x00033FCE: "afc_target_calc",
    0x00033DBE: "afc_cl_decision",
    0x0003439E: "afc_enable_gate",
    0x000343CE: "afc_output_clamp",
    0x00043470: "LowPW_GateFunction",
}

# Add task labels
TASK_ADDRS = {
    0x044188: "task00", 0x045970: "task01", 0x045098: "task02",
    0x045670: "task03", 0x0455E6: "task04", 0x04530A: "task05",
    0x045354: "task06", 0x0450AE: "task07", 0x044E04: "task08",
    0x044DB0: "task09", 0x0448F4: "task10", 0x04438C: "task11",
    0x043D68: "task12", 0x045A3E: "task13", 0x044834: "task14",
    0x045A84: "task15", 0x045BBC: "task16", 0x045B44: "task17",
    0x045BFE: "task18", 0x045E96: "task19", 0x0459F6: "task20",
    0x0467AE: "task21", 0x0461D2: "task22", 0x0467F4: "task23",
    0x0469A4: "task24", 0x0463BA: "task25", 0x046978: "task26",
    0x046296: "task27", 0x045DF8: "task28", 0x044296: "task29",
    0x03FCA2: "task30", 0x03FFD6: "task31", 0x04004A: "task32",
    0x040918: "task33", 0x040516: "task34", 0x0418AC: "task35",
    0x0415B8: "task36", 0x0419BA: "task37", 0x042A78: "task38",
    0x042B90: "task39", 0x042D20: "task40", 0x042D54: "task41",
    0x042F48: "task42", 0x04322A: "task43", 0x04317A: "task44",
    0x0431B0: "task45", 0x043368: "task46", 0x043464: "task47",
    0x04359C: "task48", 0x03F00C: "task49", 0x03F368: "task50",
    0x054852: "task51", 0x0549FA: "task52", 0x0602DC: "task53",
    0x04BC20: "task54", 0x0900B4: "task55", 0x066580: "task56",
    0x0758CA: "task57", 0x06F0B8: "task58",
}
KNOWN_LABELS.update(TASK_ADDRS)


def scan_rom(rom):
    """Scan ROM for BSR and JSR call targets."""
    call_targets = defaultdict(list)  # target_addr -> [caller_addr, ...]
    rom_len = len(rom)

    # Pass 1: BSR disp12 — opcode 1011 dddd dddd dddd
    for pc in range(0, rom_len - 1, 2):
        word = struct.unpack_from(">H", rom, pc)[0]
        if (word >> 12) == 0xB:  # BSR
            disp = sign_extend_12(word & 0xFFF)
            target = (pc + 4) + (disp << 1)
            if 0 <= target < rom_len:
                call_targets[target].append(pc)

    # Pass 2: JSR @Rn — opcode 0100 nnnn 0000 1011
    # Look for pattern: mov.l @(disp,PC),Rn ... JSR @Rn
    # mov.l @(disp,PC),Rn = 1101 nnnn dddd dddd
    for pc in range(0, rom_len - 1, 2):
        word = struct.unpack_from(">H", rom, pc)[0]
        # JSR @Rn: 0100nnnn00001011
        if (word & 0xF0FF) == 0x400B:
            rn = (word >> 8) & 0xF
            # Search backwards up to 10 instructions for mov.l @(disp,PC),Rn
            for back in range(1, 12):
                prev_pc = pc - back * 2
                if prev_pc < 0:
                    break
                prev_word = struct.unpack_from(">H", rom, prev_pc)[0]
                # mov.l @(disp,PC),Rn: 1101nnnndddddddd
                if (prev_word >> 12) == 0xD and ((prev_word >> 8) & 0xF) == rn:
                    disp = prev_word & 0xFF
                    # Literal pool address: (PC & ~3) + 4 + disp*4
                    lit_addr = (prev_pc & ~3) + 4 + disp * 4
                    if lit_addr + 4 <= rom_len:
                        target = struct.unpack_from(">I", rom, lit_addr)[0]
                        # Only count targets that look like code addresses
                        if 0x100 <= target < rom_len and (target & 1) == 0:
                            call_targets[target].append(pc)
                    break
                # If we hit another write to the same register, stop
                if (prev_word >> 12) == 0xD and ((prev_word >> 8) & 0xF) == rn:
                    break
                # Also check if register is overwritten by other instructions
                # mov Rm,Rn: 0110nnnnmmmm0011
                if (prev_word & 0xF00F) == 0x6003 and ((prev_word >> 8) & 0xF) == rn:
                    break

        # JSR/N @Rn (SH-2): 0100nnnn01001011
        if (word & 0xF0FF) == 0x404B:
            rn = (word >> 8) & 0xF
            for back in range(1, 12):
                prev_pc = pc - back * 2
                if prev_pc < 0:
                    break
                prev_word = struct.unpack_from(">H", rom, prev_pc)[0]
                if (prev_word >> 12) == 0xD and ((prev_word >> 8) & 0xF) == rn:
                    disp = prev_word & 0xFF
                    lit_addr = (prev_pc & ~3) + 4 + disp * 4
                    if lit_addr + 4 <= rom_len:
                        target = struct.unpack_from(">I", rom, lit_addr)[0]
                        if 0x100 <= target < rom_len and (target & 1) == 0:
                            call_targets[target].append(pc)
                    break
                if (prev_word >> 12) == 0xD and ((prev_word >> 8) & 0xF) == rn:
                    break
                if (prev_word & 0xF00F) == 0x6003 and ((prev_word >> 8) & 0xF) == rn:
                    break

    return call_targets


def classify_target(rom, addr):
    """Try to classify a function by its first few instructions."""
    if addr + 16 > len(rom):
        return "?"

    hints = []
    # Read first 8 instructions
    instrs = []
    for i in range(8):
        if addr + i*2 + 2 <= len(rom):
            instrs.append(struct.unpack_from(">H", rom, addr + i*2)[0])

    for w in instrs[:6]:
        # STS.L FPUL,@-Rn (FPU save): 0100nnnn01010010 = 4n52
        if (w & 0xF0FF) == 0x4052:
            hints.append("FPU")
            break
        # FMOV (float load/store): 1111xxxx
        if (w >> 12) == 0xF:
            hints.append("FPU")
            break
        # FLDS FRn,FPUL: 1111nnnn00011101
        if (w & 0xF0FF) == 0xF01D:
            hints.append("FPU")
            break
        # FLOAT FPUL,FRn: 1111nnnn00101101
        if (w & 0xF0FF) == 0xF02D:
            hints.append("FPU")
            break

    for w in instrs[:4]:
        # LDC Rn,GBR: 0100nnnn00011110
        if (w & 0xF0FF) == 0x401E:
            hints.append("GBR")
            break

    for w in instrs[:4]:
        # STS.L PR,@-R15: 4F22
        if w == 0x4F22:
            hints.append("saves_PR")
            break

    # Check for RTS as very short function
    for w in instrs[:3]:
        if w == 0x000B:  # RTS
            hints.append("leaf/short")
            break

    return "+".join(hints) if hints else "generic"


def main():
    rom, rom_path = load_rom()
    print(f"Loaded: {rom_path} ({len(rom)} bytes)")
    print(f"Scanning for BSR/JSR call targets...\n")

    call_targets = scan_rom(rom)

    # Sort by call count (descending)
    ranked = sorted(call_targets.items(), key=lambda x: len(x[1]), reverse=True)

    # Count already-labeled vs unlabeled
    labeled_count = 0
    unlabeled_count = 0
    for addr, callers in ranked[:200]:
        if addr in KNOWN_LABELS:
            labeled_count += 1
        else:
            unlabeled_count += 1

    print(f"Total unique call targets: {len(call_targets)}")
    print(f"Top 200: {labeled_count} already labeled, {unlabeled_count} unlabeled\n")

    # Show top 100 UNLABELED targets
    print("=" * 90)
    print(f"{'Rank':>4}  {'Address':>10}  {'Calls':>5}  {'Type':>20}  {'Status':<12}  Sample Callers")
    print("=" * 90)

    unlabeled_rank = 0
    for addr, callers in ranked:
        if unlabeled_rank >= 100:
            break
        label = KNOWN_LABELS.get(addr, None)
        if label:
            continue  # skip already-labeled
        unlabeled_rank += 1
        cls = classify_target(rom, addr)
        sample = ", ".join(f"0x{c:05X}" for c in sorted(callers)[:5])
        if len(callers) > 5:
            sample += f" (+{len(callers)-5} more)"
        print(f"{unlabeled_rank:>4}  0x{addr:08X}  {len(callers):>5}  {cls:>20}  {'UNLABELED':<12}  {sample}")

    # Also show top 30 already-labeled for reference
    print("\n" + "=" * 90)
    print("TOP 30 ALREADY-LABELED (for reference)")
    print("=" * 90)
    labeled_rank = 0
    for addr, callers in ranked:
        if labeled_rank >= 30:
            break
        label = KNOWN_LABELS.get(addr, None)
        if not label:
            continue
        labeled_rank += 1
        print(f"{labeled_rank:>4}  0x{addr:08X}  {len(callers):>5}  {label}")

    # Summary stats
    print(f"\n{'=' * 90}")
    print("CALL COUNT DISTRIBUTION (all targets)")
    brackets = [(100, "100+"), (50, "50-99"), (20, "20-49"), (10, "10-19"), (5, "5-9"), (2, "2-4"), (1, "1")]
    for threshold, label in brackets:
        count = sum(1 for _, callers in call_targets.items() if len(callers) >= threshold)
        unlabeled = sum(1 for addr, callers in call_targets.items()
                       if len(callers) >= threshold and addr not in KNOWN_LABELS)
        print(f"  {label:>8} calls: {count:>5} targets ({unlabeled} unlabeled)")


if __name__ == "__main__":
    main()
