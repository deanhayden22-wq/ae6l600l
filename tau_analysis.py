#!/usr/bin/env python3
"""
Tau Adjustment Analysis: Rev 20.1 vs Rev 20.2

Compares the Alpha Transient Fueling (Tau) calibration changes between
ROM revisions and analyzes datalog evidence for over/under-enrichment.

Usage:
    python3 tau_analysis.py
"""

import csv
import io
import struct
import sys
from pathlib import Path

ROM_20_1 = "AE5L600L 20g rev 20.1 tiny wrex.bin"
ROM_20_2 = "AE5L600L 20g rev 20.2 tiny wrex.bin"


def read_rom(path):
    with open(path, "rb") as f:
        return f.read()


def read_float(rom, addr):
    return struct.unpack(">f", rom[addr : addr + 4])[0]


def read_uint16(rom, addr):
    return struct.unpack(">H", rom[addr : addr + 2])[0]


def tau_scaling(raw_uint16):
    """Convert raw uint16 to Tau enrichment adder multiplier."""
    return raw_uint16 * 0.00048828125


def print_section(title):
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


def compare_tau_tables(rom1, rom2):
    """Compare all tau-related calibration data between two ROMs."""

    print_section("TAU CALIBRATION CHANGES: Rev 20.1 -> Rev 20.2")

    # ---------------------------------------------------------------
    # 1. Engine Load axis for Tau Rising Load Activation (at 0xCCDCC)
    # ---------------------------------------------------------------
    print("\n--- Engine Load Axis (Tau Rising Load breakpoints) @ 0xCCDCC ---")
    print("  These define the load thresholds where tau enrichment activates.")
    for offset in range(0, 12, 4):
        addr = 0xCCDCC + offset
        v1 = read_float(rom1, addr)
        v2 = read_float(rom2, addr)
        changed = " <-- CHANGED" if v1 != v2 else ""
        print(f"  0x{addr:06X}: {v1:8.2f} -> {v2:8.2f}{changed}")

    # ---------------------------------------------------------------
    # 2. Tau Input A Rising Load Activation values (near 0xCD6FE)
    #    These are uint16 values with tau scaling
    # ---------------------------------------------------------------
    print("\n--- Tau Input A Rising Load Activation Data @ 0xCD6FE ---")
    print("  Enrichment multiplier values (higher = more fuel during tip-in)")
    for addr in range(0xCD6FE, 0xCD706, 2):
        v1 = read_uint16(rom1, addr)
        v2 = read_uint16(rom2, addr)
        if v1 != v2:
            t1 = tau_scaling(v1)
            t2 = tau_scaling(v2)
            pct = ((t2 - t1) / t1 * 100) if t1 != 0 else float("inf")
            print(f"  0x{addr:06X}: {t1:.4f} -> {t2:.4f}  ({pct:+.0f}%)")

    # ---------------------------------------------------------------
    # 3. Tau-related float constants in 0xCC region
    # ---------------------------------------------------------------
    print("\n--- Tau / Transient Fueling Constants (0xCC region) ---")
    float_addrs = [
        (0xCC078, "Transient threshold A"),
        (0xCC07C, "Transient threshold B"),
        (0xCC174, "Transient gain/limit A"),
        (0xCC178, "Transient gain/limit B"),
        (0xCC1D8, "Transient decay constant"),
        (0xCC204, "Transient scale factor A"),
        (0xCC208, "Transient scale factor B"),
    ]
    for addr, label in float_addrs:
        v1 = read_float(rom1, addr)
        v2 = read_float(rom2, addr)
        if v1 != v2:
            pct = ((v2 - v1) / abs(v1) * 100) if v1 != 0 else float("inf")
            print(f"  0x{addr:06X} [{label}]: {v1:.4f} -> {v2:.4f}  ({pct:+.1f}%)")

    # ---------------------------------------------------------------
    # 4. RPM thresholds (0xCC180-0xCC1A4) - seem to be RPM breakpoints
    #    lowered by ~500 RPM each in 20.2
    # ---------------------------------------------------------------
    print("\n--- RPM Breakpoints (transient activation) @ 0xCC180 ---")
    print("  Lower RPM thresholds = tau activates at lower engine speeds")
    for offset in range(0, 0x28, 4):
        addr = 0xCC180 + offset
        v1 = read_float(rom1, addr)
        v2 = read_float(rom2, addr)
        if v1 != v2:
            print(f"  0x{addr:06X}: {v1:.0f} RPM -> {v2:.0f} RPM  ({v2 - v1:+.0f})")

    # ---------------------------------------------------------------
    # 5. Repeated ECT-based tau tables (0xD47xx, 0xD48xx, 0xD4Axx, 0xD4Cxx)
    #    4 copies = 4 cylinders or 4 ECT ranges
    # ---------------------------------------------------------------
    print("\n--- ECT-Based Rising Load Tau Tables (4 copies) ---")
    print("  Values generally reduced by 1-3 counts per cell in 20.2")
    table_starts = [0xD473A, 0xD48FA, 0xD4ABA, 0xD4C7A]
    for ti, base in enumerate(table_starts):
        changed = 0
        total_delta = 0
        for offset in range(0, 0x60):
            addr = base + offset
            if addr < len(rom1) and addr < len(rom2):
                if rom1[addr] != rom2[addr]:
                    changed += 1
                    total_delta += rom2[addr] - rom1[addr]
        if changed:
            print(f"  Table {ti + 1} @ 0x{base:06X}: {changed} bytes changed, net delta = {total_delta:+d} counts")

    # ---------------------------------------------------------------
    # 6. CL fuel target changes (0xD8D10-0xD8D2F)
    # ---------------------------------------------------------------
    print("\n--- CL Fuel Target / Compensation Table @ 0xD8D10 ---")
    print("  These affect the closed-loop AFR target")
    for offset in range(0, 0x24, 4):
        addr = 0xD8D10 + offset
        v1 = read_float(rom1, addr)
        v2 = read_float(rom2, addr)
        if v1 != v2:
            print(f"  0x{addr:06X}: {v1:.3f} -> {v2:.3f}  ({v2 - v1:+.3f})")


def analyze_log(filename, label=""):
    """Analyze a datalog CSV for signs of tau over/under-enrichment."""

    path = Path(filename)
    if not path.exists():
        print(f"  Log file not found: {filename}")
        return None

    with open(filename, "r", newline="") as f:
        content = f.read().replace("\r\n", "\n").replace("\r", "\n")

    reader = csv.DictReader(io.StringIO(content))
    data = []
    for r in reader:
        try:
            d = {}
            for key in ["wbo2", "FFB", "AFC", "AFL", "correction", "RPM", "load", "CL/OL"]:
                val = r.get(key, "").strip()
                d[key] = float(val) if val else 0.0
            data.append(d)
        except (ValueError, TypeError):
            continue

    if not data:
        print(f"  No data parsed from {filename}")
        return None

    print(f"\n  File: {filename} {label}")
    print(f"  Samples: {len(data)}")

    # Overall AFR stats
    wbo2 = [d["wbo2"] for d in data if d["wbo2"] > 5]
    if wbo2:
        print(f"\n  WBO2 (Measured AFR):")
        print(f"    Mean: {sum(wbo2) / len(wbo2):.2f}")
        lean = sum(1 for v in wbo2 if v > 15.0)
        rich = sum(1 for v in wbo2 if v < 14.2)
        print(f"    Lean (>15.0): {lean} ({100 * lean / len(wbo2):.1f}%)")
        print(f"    Rich (<14.2): {rich} ({100 * rich / len(wbo2):.1f}%)")

    # AFC (short-term fuel trim)
    afc = [d["AFC"] for d in data]
    pos = sum(1 for v in afc if v > 0)
    neg = sum(1 for v in afc if v < 0)
    mean_afc = sum(afc) / len(afc)
    print(f"\n  AFC (Short-Term Fuel Trim):")
    print(f"    Mean: {mean_afc:+.3f}%")
    print(f"    Adding fuel (lean): {pos} ({100 * pos / len(afc):.1f}%)")
    print(f"    Pulling fuel (rich): {neg} ({100 * neg / len(afc):.1f}%)")

    # AFL (long-term learning)
    afl = [d["AFL"] for d in data]
    mean_afl = sum(afl) / len(afl)
    print(f"\n  AFL (Long-Term Learning):")
    print(f"    Mean: {mean_afl:+.3f}%")

    # CL vs OL split
    cl = [d for d in data if d["CL/OL"] == 8]
    ol = [d for d in data if d["CL/OL"] != 8]
    print(f"\n  CL/OL Split:")
    print(f"    CL: {len(cl)} ({100 * len(cl) / len(data):.1f}%)")
    print(f"    OL: {len(ol)} ({100 * len(ol) / len(data):.1f}%)")
    if cl:
        cl_afc = sum(d["AFC"] for d in cl) / len(cl)
        print(f"    CL avg AFC: {cl_afc:+.3f}%")

    # AFR vs Target error
    errs = [(d["wbo2"] - d["FFB"]) for d in data if d["FFB"] > 5]
    if errs:
        mean_err = sum(errs) / len(errs)
        print(f"\n  AFR Error (measured - target):")
        print(f"    Mean: {mean_err:+.3f} AFR (positive = lean of target)")

    return {
        "mean_afc": mean_afc,
        "mean_afl": mean_afl,
        "mean_afr_err": sum(errs) / len(errs) if errs else 0,
        "pct_pulling": 100 * neg / len(afc),
    }


def diagnosis(stats_9, stats_10):
    """Provide diagnostic interpretation."""
    print_section("DIAGNOSIS: Did You Bump Tau Too Much?")

    print("""
  WHAT TAU DOES:
    Tau (Alpha Transient Fueling) adds extra fuel during load transients
    (tip-in/tip-out) to compensate for the wall-wetting effect -- fuel
    that condenses on intake port walls instead of reaching the cylinder.
    Higher tau = more enrichment during throttle changes.

  WHAT CHANGED (20.1 -> 20.2):
    1. Tau rising load multiplier values DOUBLED (~0.25 -> ~0.50)
    2. Engine load axis breakpoints LOWERED (2.0->1.5, 4.0->3.0)
       -> Tau now activates at LOWER loads than before
    3. RPM thresholds LOWERED by ~400-500 RPM across the board
       -> Tau now activates at LOWER RPMs too
    4. Transient thresholds reduced (29->23, 60->40)
    5. Transient scale factors reduced (1.15->0.95, 1.25->1.10)
    6. Some CL fuel target values shifted richer

  NET EFFECT: Significantly MORE transient enrichment, activating
  in a WIDER operating range (lower RPM, lower load).
""")

    print("  EVIDENCE FROM DATALOGS:")

    if stats_9 and stats_10:
        print(f"""
    Log 3-9 (earlier):
      AFC mean:      {stats_9['mean_afc']:+.3f}%  (ECU pulling fuel {stats_9['pct_pulling']:.0f}% of time)
      AFL mean:      {stats_9['mean_afl']:+.3f}%
      AFR error:     {stats_9['mean_afr_err']:+.3f} AFR lean of target

    Log 3-10 (later):
      AFC mean:      {stats_10['mean_afc']:+.3f}%  (ECU pulling fuel {stats_10['pct_pulling']:.0f}% of time)
      AFL mean:      {stats_10['mean_afl']:+.3f}%
      AFR error:     {stats_10['mean_afr_err']:+.3f} AFR lean of target
""")

    print("""  INTERPRETATION:
    - AFC is consistently NEGATIVE in both logs, meaning the ECU is
      PULLING FUEL most of the time -> mixture is running RICH
    - The 3-10 log shows AFC pulling even harder (-2.6% vs -1.2%)
    - This is consistent with tau over-enrichment: the extra transient
      fuel is making the overall mixture too rich, and the closed-loop
      AFC is fighting to pull it back

  HOWEVER - IMPORTANT NUANCE:
    - You said the original problem was LEAN conditions
    - The tau increase was meant to add fuel during transients to fix lean spikes
    - If the lean spikes were happening during tip-in, the tau increase may be
      doing its job during those specific moments, but OVER-correcting on average
    - The AFR error in 3-10 (+1.118 vs +0.243) also shows more scatter,
      suggesting the tau might be causing oscillation

  HOW TO TELL IF TAU IS TOO MUCH:

    1. LOOK AT AFC DURING TIP-IN EVENTS SPECIFICALLY
       If AFC goes strongly negative right after a load increase,
       tau is adding too much fuel during the transient.

    2. CHECK FOR AFR OSCILLATION
       Over-aggressive tau causes rich-lean-rich oscillation as the
       ECU's closed-loop correction fights the transient enrichment.

    3. COMPARE STEADY-STATE vs TRANSIENT AFC
       If steady-state AFC is near zero but goes very negative during
       load changes, tau is overshooting.

    4. WATCH THE WIDEBAND DURING PULLS
       On a steady pull (WOT), AFR should track target smoothly.
       If it goes rich on initial tip-in then settles, tau is too high.

  RECOMMENDATION:
    The tau multiplier values were roughly DOUBLED (100% increase).
    Try splitting the difference -- increase by ~50% from the 20.1
    baseline instead of 100%. Specifically:
      - At 0xCD6FE-0xCD704: try ~0.375 instead of 0.50 (was 0.25)
      - Consider restoring the load axis breakpoints (2.0 and 4.0)
        or only lowering them partway (1.75 and 3.5)
      - The RPM threshold reductions seem reasonable, those can stay
""")


def main():
    print("=" * 70)
    print("  Tau Adjustment Analysis: AE5L600L Rev 20.1 vs Rev 20.2")
    print("  2013 USDM Subaru Impreza WRX MT")
    print("=" * 70)

    rom1 = read_rom(ROM_20_1)
    rom2 = read_rom(ROM_20_2)

    compare_tau_tables(rom1, rom2)

    print_section("DATALOG ANALYSIS")

    stats_9 = analyze_log("3-9.csv", "(earlier log)")
    stats_10 = analyze_log("3-10.csv", "(later log)")

    diagnosis(stats_9, stats_10)


if __name__ == "__main__":
    main()
