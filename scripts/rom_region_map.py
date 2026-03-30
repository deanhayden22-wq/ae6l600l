#!/usr/bin/env python3
"""
ROM Region Map for AE5L600L.

Classifies every byte of the 1MB ROM into regions:
- Code (instructions)
- Calibration data (lookup tables)
- Descriptor headers
- Literal pools
- Vector table
- ROM holes (0xFF filled, available for patches)
- ECU ID / strings
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


def find_ff_regions(rom, min_size=32):
    """Find contiguous regions of 0xFF bytes (ROM holes)."""
    regions = []
    start = None
    for i in range(len(rom)):
        if rom[i] == 0xFF:
            if start is None:
                start = i
        else:
            if start is not None:
                length = i - start
                if length >= min_size:
                    regions.append((start, length))
                start = None
    if start is not None:
        length = len(rom) - start
        if length >= min_size:
            regions.append((start, length))
    return regions


def find_zero_regions(rom, min_size=64):
    """Find contiguous regions of 0x00 bytes."""
    regions = []
    start = None
    for i in range(len(rom)):
        if rom[i] == 0x00:
            if start is None:
                start = i
        else:
            if start is not None:
                length = i - start
                if length >= min_size:
                    regions.append((start, length))
                start = None
    return regions


def find_strings(rom, min_length=4):
    """Find ASCII strings in the ROM."""
    strings = []
    start = None
    current = []
    for i in range(len(rom)):
        b = rom[i]
        if 0x20 <= b <= 0x7E:  # printable ASCII
            if start is None:
                start = i
            current.append(chr(b))
        else:
            if start is not None and len(current) >= min_length:
                strings.append((start, ''.join(current)))
            start = None
            current = []
    return strings


def classify_region(rom, start, size=256):
    """Classify a 256-byte block by its content pattern."""
    end = min(start + size, len(rom))
    block = rom[start:end]
    n = len(block)
    if n == 0:
        return "empty"

    # Check for all 0xFF (ROM hole)
    ff_count = sum(1 for b in block if b == 0xFF)
    if ff_count > n * 0.95:
        return "rom_hole"

    # Check for all 0x00 (zero-fill)
    zero_count = sum(1 for b in block if b == 0x00)
    if zero_count > n * 0.95:
        return "zero_fill"

    # Check for float32 patterns (calibration axes: sequences of 4-byte aligned floats)
    float_count = 0
    for i in range(0, n - 3, 4):
        val = struct.unpack_from(">f", block, i)[0]
        if val == val and abs(val) < 1e8 and val != 0:
            float_count += 1
    if float_count > n / 8:
        return "float_data"

    # Check for code-like patterns (SH-2 instructions)
    # Look for common instruction patterns
    code_indicators = 0
    for i in range(0, n - 1, 2):
        word = struct.unpack_from(">H", block, i)[0]
        hi = (word >> 12) & 0xF
        # Common code opcodes
        if hi in (0x4, 0x6, 0xE, 0x2, 0x3, 0x8, 0x9, 0xD):
            code_indicators += 1
        if word in (0x000B, 0x0009, 0x4F22, 0x4F26):
            code_indicators += 3
    if code_indicators > n / 6:
        return "code"

    # Check for uint8 data (values 0-255, no clear float pattern)
    small_count = sum(1 for b in block if b < 200)
    if small_count > n * 0.8:
        return "uint8_data"

    return "mixed_data"


def main():
    rom = load_rom()
    rom_len = len(rom)
    print(f"ROM Size: {rom_len} bytes ({rom_len // 1024} KB)\n")

    # 1. Find ROM holes (0xFF regions)
    ff_regions = find_ff_regions(rom, min_size=32)
    total_ff = sum(length for _, length in ff_regions)

    print(f"{'='*80}")
    print(f"ROM HOLES (0xFF regions >= 32 bytes)")
    print(f"{'='*80}")
    print(f"Total free space: {total_ff:,} bytes ({total_ff/1024:.1f} KB)\n")

    for start, length in sorted(ff_regions, key=lambda x: -x[1]):
        end = start + length
        print(f"  0x{start:06X}-0x{end:06X}  {length:>6} bytes ({length/1024:.1f} KB)")

    # 2. Region classification (256-byte blocks)
    print(f"\n{'='*80}")
    print(f"ROM REGION MAP (256-byte block classification)")
    print(f"{'='*80}")

    region_stats = {}
    block_size = 256
    regions = []
    prev_type = None
    region_start = 0

    for addr in range(0, rom_len, block_size):
        rtype = classify_region(rom, addr, block_size)
        if rtype != prev_type:
            if prev_type is not None:
                regions.append((region_start, addr, prev_type))
            region_start = addr
            prev_type = rtype
        region_stats[rtype] = region_stats.get(rtype, 0) + block_size
    if prev_type:
        regions.append((region_start, rom_len, prev_type))

    print(f"\nRegion type distribution:")
    for rtype, size in sorted(region_stats.items(), key=lambda x: -x[1]):
        pct = size * 100 / rom_len
        bar = '#' * int(pct / 2)
        print(f"  {rtype:<15} {size:>8} bytes ({pct:>5.1f}%)  {bar}")

    print(f"\nRegion boundaries:")
    for start, end, rtype in regions:
        size = end - start
        if size >= 512:  # Only show significant regions
            print(f"  0x{start:06X}-0x{end:06X}  {size:>6} bytes  {rtype}")

    # 3. Known region annotations
    print(f"\n{'='*80}")
    print(f"ANNOTATED ROM MAP")
    print(f"{'='*80}")

    KNOWN_REGIONS = [
        (0x000000, 0x000034, "Exception Vector Table"),
        (0x000034, 0x000BAC, "System startup data/tables"),
        (0x000BAC, 0x000C0C, "NMI Handler"),
        (0x000C0C, 0x0A0000, "Main code region"),
        (0x0A0000, 0x0B2000, "Descriptor headers (760 descriptors)"),
        (0x0B2000, 0x0BF000, "Table processor library + utilities"),
        (0x0BF000, 0x0C0000, "Transition / padding"),
        (0x0C0000, 0x0DB000, "Calibration data tables"),
        (0x0DB000, 0x0F8900, "ROM hole (available for patches)"),
        (0x09A770, 0x09A7CD, "DTC enable flags (93 bytes)"),
        (0x09A834, 0x09AF78, "DTC definition structs (93 x 20B)"),
        (0x0D97F0, 0x0D9800, "ECU ID region"),
        (0x0F8900, 0x100000, "Extended calibration / data"),
    ]

    for start, end, desc in KNOWN_REGIONS:
        size = end - start
        print(f"  0x{start:06X}-0x{end:06X}  {size:>7} bytes  {desc}")

    # 4. Strings in ROM
    print(f"\n{'='*80}")
    print(f"ASCII STRINGS (>= 6 chars)")
    print(f"{'='*80}")

    strings = find_strings(rom, min_length=6)
    # Filter out likely false positives (strings in code region that are just instruction patterns)
    for addr, s in strings:
        # Only show strings that look meaningful
        if any(c.isalpha() for c in s) and len(s) >= 6:
            print(f"  0x{addr:06X}: \"{s}\"")
        if len(s) >= 20:
            print(f"  0x{addr:06X}: \"{s[:60]}\"{'...' if len(s) > 60 else ''}")

    # 5. Largest ROM holes summary
    print(f"\n{'='*80}")
    print(f"PATCH-AVAILABLE ROM HOLES (largest first)")
    print(f"{'='*80}")
    print(f"Total: {total_ff:,} bytes ({total_ff/1024:.1f} KB) in {len(ff_regions)} regions\n")

    for start, length in sorted(ff_regions, key=lambda x: -x[1])[:10]:
        end = start + length
        print(f"  0x{start:06X}-0x{end:06X}  {length:>6} bytes ({length/1024:.1f} KB)"
              f"  {'<-- PRIMARY PATCH AREA' if length > 10000 else ''}")


if __name__ == "__main__":
    main()
