#!/usr/bin/env python3
"""
Trace descriptor format by:
1. Disassembling desc_read_float_safe (0xBDBCC) and desc_read_int_safe (0xBDCB6) in detail
2. Dumping known descriptor headers to find the common structure
3. Scanning for descriptor-like patterns in the ROM

Known descriptors (from ImportAE5L600L.java and PORTING_NOTES):
  - AVCS Intake Duty Corr:   0xAD620 (28 bytes, 2D, uint8,  10x9)
  - AVCS Exhaust Duty Corr:  0xAD848 (28 bytes, 2D, uint16, 10x9)
  - PSE descriptors:          0xAC948-0xACB3F (multiple, 1D, various sizes)
  - AFL descriptors:          Referenced in CL/OL analysis
  - AFC PI gain descriptors:  Referenced in afc_pi_output
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

def read_u8(rom, addr):
    return rom[addr]

def read_u16(rom, addr):
    return struct.unpack_from(">H", rom, addr)[0]

def read_u32(rom, addr):
    return struct.unpack_from(">I", rom, addr)[0]

def read_f32(rom, addr):
    return struct.unpack_from(">f", rom, addr)[0]

def is_rom_ptr(val, rom_len):
    return 0x1000 <= val < rom_len

def is_ram_ptr(val):
    return 0xFFFF0000 <= val <= 0xFFFFFFFF

def dump_hex(rom, addr, length):
    """Hex dump of ROM region."""
    result = []
    for i in range(0, length, 16):
        offset = addr + i
        if offset + 16 > len(rom):
            break
        hexb = " ".join(f"{rom[offset+j]:02X}" for j in range(min(16, length - i)))
        result.append(f"  0x{offset:06X}: {hexb}")
    return "\n".join(result)


def analyze_descriptor(rom, addr, label=""):
    """Analyze a descriptor at the given address."""
    rom_len = len(rom)
    print(f"\n{'='*70}")
    print(f"Descriptor at 0x{addr:06X}  {label}")
    print(f"{'='*70}")

    # Raw hex dump (first 32 bytes)
    print(f"\nRaw bytes (32):")
    print(dump_hex(rom, addr, 32))

    # Try to interpret as standard descriptor fields
    print(f"\nField interpretation:")

    # Common Subaru descriptor patterns:
    # Offset 0x00: bias (float) or flags
    # Offset 0x04: dimensions or type
    # Offset 0x08+: axis pointers, data pointer, sizes

    # Try reading as series of 32-bit words
    for i in range(8):
        val = read_u32(rom, addr + i*4)
        fval = read_f32(rom, addr + i*4)
        desc = ""
        if is_rom_ptr(val, rom_len):
            desc = f"  <- ROM pointer"
            # Check if target looks like float array (axis)
            if val + 4 < rom_len:
                target_f = read_f32(rom, val)
                if -1000 < target_f < 100000 and target_f != 0:
                    desc += f" (first value: {target_f:.4f})"
        elif is_ram_ptr(val):
            desc = f"  <- RAM address"
        elif abs(fval) < 1e6 and fval != 0 and not (val == 0):
            desc = f"  (as float: {fval:.6f})"
        elif val < 256:
            desc = f"  (small int: {val})"

        print(f"  +0x{i*4:02X}: 0x{val:08X}{desc}")

    # Also try byte-level interpretation for first 8 bytes
    print(f"\nByte-level (first 12):")
    for i in range(12):
        b = rom[addr + i]
        print(f"  +0x{i:02X}: 0x{b:02X} ({b:>3d})")


# Known descriptors to analyze
KNOWN_DESCRIPTORS = [
    # (addr, label, expected_type)
    (0x0AD620, "AVCS_IntakeDutyCorr_Desc (28B, 2D, uint8, 10x9)", "2D"),
    (0x0AD848, "AVCS_ExhaustDutyCorr_Desc (28B, 2D, uint16, 10x9)", "2D"),
    (0x0AC948, "PSE_Desc_LSD_Initial_1A", "1D"),
    (0x0AC95C, "PSE_Desc_LSD_Initial_1B", "1D"),
    (0x0AC998, "PSE_Desc_LSD_Delay_1", "1D"),
    (0x0AC9A4, "PSE_Desc_HSD_InitStart_1A", "1D"),
    (0x0ACA78, "PSE_Desc_HSD_StepValue_1", "1D"),
    (0x0ACAF0, "PSE_Desc_LSD_DelayMult", "1D"),
    # AFC PI gain descriptors
    (0x0ACEA0, "AFC P-gain (load axis)", "1D"),
    (0x0ACEB4, "AFC P-gain (RPM axis)", "1D"),
    (0x0ACEC8, "AFC I-gain (load axis)", "1D"),
    (0x0ACEDC, "AFC I-gain (RPM axis)", "1D"),
    # AFL descriptors (from CL/OL analysis - check around 0xACE8C)
    (0x0ACE8C, "AFC Active Correction", "?"),
    # Low PW descriptors
    (0x0ADFC0, "LowPW Desc (Tasks 44/45)", "?"),
]

# Also try to find where desc_read_float_safe callers pass their r4 values
# by tracing literal pool loads before the JSR

def find_desc_ptrs_for_callee(rom, callee_addr, max_results=50):
    """Find ROM pointers loaded into r4 before calling callee_addr.
    Pattern: mov.l @(disp,PC),r4 ... mov.l @(disp,PC),r2 (=callee) ... jsr @r2
    """
    rom_len = len(rom)
    results = []

    for pc in range(0, rom_len - 1, 2):
        word = struct.unpack_from(">H", rom, pc)[0]

        # Look for JSR @Rn where Rn was loaded with callee_addr
        if (word & 0xF0FF) == 0x400B:
            rn = (word >> 8) & 0xF
            # Find the mov.l that loaded Rn with callee_addr
            callee_found = False
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
                        if target == callee_addr:
                            callee_found = True
                    break

            if callee_found:
                # Now find what was in r4 — look for mov.l @(disp,PC),r4
                for back2 in range(1, 20):
                    prev_pc2 = pc - back2 * 2
                    if prev_pc2 < 0:
                        break
                    prev_word2 = struct.unpack_from(">H", rom, prev_pc2)[0]
                    if (prev_word2 >> 12) == 0xD and ((prev_word2 >> 8) & 0xF) == 4:
                        disp2 = prev_word2 & 0xFF
                        lit_addr2 = (prev_pc2 & ~3) + 4 + disp2 * 4
                        if lit_addr2 + 4 <= rom_len:
                            r4_val = struct.unpack_from(">I", rom, lit_addr2)[0]
                            if is_rom_ptr(r4_val, rom_len):
                                results.append((r4_val, pc))
                        break

        if len(results) >= max_results:
            break

    return results


def main():
    rom = load_rom()
    print(f"Loaded ROM: {len(rom)} bytes\n")

    # Part 1: Analyze known descriptors
    print("=" * 70)
    print("PART 1: KNOWN DESCRIPTOR ANALYSIS")
    print("=" * 70)

    for addr, label, dtype in KNOWN_DESCRIPTORS:
        analyze_descriptor(rom, addr, label)

    # Part 2: Find descriptor pointers passed to desc_read_float_safe
    print(f"\n\n{'='*70}")
    print("PART 2: DESCRIPTOR POINTERS PASSED TO desc_read_float_safe (0xBDBCC)")
    print(f"{'='*70}")

    desc_ptrs = find_desc_ptrs_for_callee(rom, 0x0BDBCC, max_results=80)
    # Deduplicate by pointer value
    unique_ptrs = {}
    for ptr, caller in desc_ptrs:
        if ptr not in unique_ptrs:
            unique_ptrs[ptr] = []
        unique_ptrs[ptr].append(caller)

    print(f"\nFound {len(unique_ptrs)} unique descriptor pointers:")
    for ptr in sorted(unique_ptrs.keys()):
        callers = unique_ptrs[ptr]
        first_bytes = " ".join(f"{rom[ptr+i]:02X}" for i in range(min(20, len(rom)-ptr)))
        print(f"  0x{ptr:06X}: {first_bytes}  ({len(callers)} refs)")

    # Part 3: Try to find common structure
    print(f"\n\n{'='*70}")
    print("PART 3: DESCRIPTOR STRUCTURE PATTERN ANALYSIS")
    print(f"{'='*70}")

    # Collect first bytes of all found descriptors
    all_desc_addrs = [addr for addr, _, _ in KNOWN_DESCRIPTORS] + list(unique_ptrs.keys())
    all_desc_addrs = sorted(set(all_desc_addrs))

    # Analyze common patterns in first few bytes
    print(f"\nAnalyzing {len(all_desc_addrs)} descriptor addresses for common patterns:")

    # Check byte 0 (often a type/flag byte)
    byte0_values = {}
    for addr in all_desc_addrs:
        if addr + 20 < len(rom):
            b0 = rom[addr]
            byte0_values[b0] = byte0_values.get(b0, 0) + 1

    print(f"\n  Byte +0x00 distribution:")
    for val, count in sorted(byte0_values.items(), key=lambda x: -x[1])[:10]:
        print(f"    0x{val:02X} ({val:>3d}): {count} descriptors")

    # Check word at offset 0 (might be a bias float or dimension info)
    word0_patterns = {}
    for addr in all_desc_addrs:
        if addr + 4 < len(rom):
            w = read_u32(rom, addr)
            if w == 0:
                word0_patterns["zero"] = word0_patterns.get("zero", 0) + 1
            elif is_rom_ptr(w, len(rom)):
                word0_patterns["ROM_ptr"] = word0_patterns.get("ROM_ptr", 0) + 1
            elif is_ram_ptr(w):
                word0_patterns["RAM_ptr"] = word0_patterns.get("RAM_ptr", 0) + 1
            else:
                f = read_f32(rom, addr)
                if abs(f) < 1e6 and f != 0:
                    word0_patterns[f"float({f:.2f})"] = word0_patterns.get(f"float({f:.2f})", 0) + 1
                else:
                    word0_patterns[f"0x{w:08X}"] = word0_patterns.get(f"0x{w:08X}", 0) + 1

    print(f"\n  Word +0x00 patterns:")
    for pat, count in sorted(word0_patterns.items(), key=lambda x: -x[1])[:10]:
        print(f"    {pat}: {count} descriptors")


if __name__ == "__main__":
    main()
