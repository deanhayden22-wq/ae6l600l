#!/usr/bin/env python3
"""
Reconstruct the FLKC grid CELL INDEX per log sample, and classify every FLKC
step as CELL TRAVERSAL or IN-CELL CHANGE (i.e. actual learning).

Why this matters
----------------
The FLKC grid is BUCKETED, not interpolated (docs/corrections.md item 41).
Axis values at 0xD2F0C (RPM) and 0xD2F28 (load) are band BOUNDARIES, so
6 + 4 boundaries give 7 x 5 = 35 cells, and every lookup reads exactly ONE cell.

Consequence: a uniform 0.25 step between consecutive samples is NOT evidence of
traversing a pre-learned map. 0.25 is exactly the Fine Correction Advance Value
(0xD2F48). Under a piecewise-constant map, traversal produces jumps of whatever
separates two adjacent cells -- arbitrary, not uniformly 0.25.

The discriminator is therefore: did the CELL INDEX change across the step?
  index changed  -> traversal (you moved to a different cell)
  index constant -> the cell's own stored value moved = LEARNING

Band selection replicates the ECU exactly (selector 0x0461D2):
  band = number of boundaries <= input
  and a DOWNWARD band change requires the input to fall a further `hyst` below
  the boundary (50 rpm at 0xD2F24, 0.02 load at 0xD2F38). Upward changes are
  immediate. cell = rpm_band * 5 + load_band.

Usage:
    python scripts/analysis/flkc_cell_trace.py "logs/8-14 weekend 20.19c/8-14 weekend 20.19c.csv"
    python scripts/analysis/flkc_cell_trace.py <csv> --rom "rom/AE5L600L 20g rev 20.19d.bin"
"""
import csv
import os
import struct
import sys

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
DEFAULT_ROM = os.path.join(REPO, "rom", "AE5L600L 20g rev 20.19c.bin")

RPM_AXIS_ADDR, RPM_N = 0xD2F0C, 6
LOAD_AXIS_ADDR, LOAD_N = 0xD2F28, 4
RPM_HYST_ADDR = 0xD2F24
LOAD_HYST_ADDR = 0xD2F38


def read_cal(rom_path):
    with open(rom_path, "rb") as f:
        rom = f.read()
    g = lambda a: struct.unpack_from(">f", rom, a)[0]  # noqa: E731
    return {
        "rpm": [g(RPM_AXIS_ADDR + 4 * i) for i in range(RPM_N)],
        "load": [g(LOAD_AXIS_ADDR + 4 * i) for i in range(LOAD_N)],
        "rpm_hyst": g(RPM_HYST_ADDR),
        "load_hyst": g(LOAD_HYST_ADDR),
    }


def band(value, bounds, prev, hyst):
    """Replicate the ECU band selector, including downward-only hysteresis."""
    b = 0
    while b < len(bounds) and bounds[b] <= value:
        b += 1
    if prev is not None and b < prev:
        # falling: require value to be `hyst` below the boundary of the new band
        if not (b < len(bounds) and value < bounds[b] - hyst):
            b = min(b + 1, prev)
    return b


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        sys.exit(__doc__)
    csv_path = args[0]
    rom_path = DEFAULT_ROM
    if "--rom" in sys.argv:
        rom_path = sys.argv[sys.argv.index("--rom") + 1]
    cal = read_cal(rom_path)
    print(f"ROM : {os.path.basename(rom_path)}")
    print(f"  RPM  boundaries {cal['rpm']}   hyst {cal['rpm_hyst']}")
    print(f"  LOAD boundaries {cal['load']}  hyst {cal['load_hyst']}")
    print(f"LOG : {os.path.basename(csv_path)}\n")

    prpm = pload = None
    prev_cell = prev_flkc = None
    traversal = incell = 0
    incell_steps, traversal_steps = [], []
    n = 0
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            try:
                rpm = float(row["RPM"]); load = float(row["load"]); flkc = float(row["FLKC"])
            except (ValueError, KeyError, TypeError):
                continue
            n += 1
            rb = band(rpm, cal["rpm"], prpm, cal["rpm_hyst"])
            lb = band(load, cal["load"], pload, cal["load_hyst"])
            prpm, pload = rb, lb
            cell = rb * 5 + lb
            if prev_cell is not None and flkc != prev_flkc:
                d = round(flkc - prev_flkc, 4)
                if cell != prev_cell:
                    traversal += 1; traversal_steps.append(d)
                else:
                    incell += 1
                    incell_steps.append((row.get("time", "?"), rpm, load, cell, prev_flkc, flkc, d))
            prev_cell, prev_flkc = cell, flkc

    print(f"samples parsed        : {n}")
    print(f"FLKC changes total    : {traversal + incell}")
    print(f"  CELL TRAVERSAL      : {traversal}   (index moved -- a different cell was read)")
    print(f"  IN-CELL CHANGE      : {incell}   (index held -- the stored value itself moved = LEARNING)\n")
    if incell_steps:
        from collections import Counter
        c = Counter(round(s[6], 2) for s in incell_steps)
        print("in-cell step sizes:", dict(sorted(c.items())))
        print("\nfirst 15 in-cell changes (time, rpm, load, cell, from -> to, delta):")
        for s in incell_steps[:15]:
            print(f"  {s[0]:>10s}  {s[1]:6.0f} {s[2]:5.2f}  cell {s[3]:2d}   {s[4]:+.2f} -> {s[5]:+.2f}  ({s[6]:+.2f})")
    if traversal_steps:
        from collections import Counter
        c = Counter(round(d, 2) for d in traversal_steps)
        print("\ntraversal step sizes (top 10):",
              dict(sorted(c.items(), key=lambda kv: -kv[1])[:10]))


if __name__ == "__main__":
    main()
