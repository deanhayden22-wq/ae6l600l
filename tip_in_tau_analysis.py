#!/usr/bin/env python3
"""
Tip-in Enrichment vs Tau (Alpha Transient Fueling) Relationship Analysis
=========================================================================
ROM: AE5L600L 20g rev 20.3 (2013 USDM Subaru WRX MT)

This script extracts and analyzes the relationship between the Throttle
Tip-in Enrichment system and the Tau (Alpha Transient Fueling) system
from the ECU ROM binary.
"""

import struct

ROM_PATH = "AE5L600L 20g rev 20.3 tiny wrex.bin"


def read_rom():
    with open(ROM_PATH, "rb") as f:
        return f.read()


def read_floats(rom, addr, count):
    return [struct.unpack('>f', rom[addr+i*4:addr+i*4+4])[0] for i in range(count)]


def read_uint16s(rom, addr, count):
    return [struct.unpack('>H', rom[addr+i*2:addr+i*2+2])[0] for i in range(count)]


def read_uint8s(rom, addr, count):
    return list(rom[addr:addr+count])


def main():
    rom = read_rom()

    # Shared ECT axis (16 elements, float, Celsius in ROM, converted to F)
    ect_axis_c = read_floats(rom, 0xCC624, 16)
    ect_axis_f = [(x * 1.8) + 32 for x in ect_axis_c]

    print("=" * 78)
    print("TIP-IN ENRICHMENT vs TAU: RELATIONSHIP ANALYSIS")
    print("ROM: AE5L600L 20g rev 20.3 (2013 WRX)")
    print("=" * 78)

    # ─── SECTION 1: TIP-IN ENRICHMENT TABLES ────────────────────────────────
    print("\n" + "─" * 78)
    print("SECTION 1: THROTTLE TIP-IN ENRICHMENT (Throttle-Rate Based)")
    print("─" * 78)
    print("""
The Tip-in Enrichment system adds fuel based on THROTTLE ANGLE RATE OF CHANGE.
It is a direct, throttle-position-derivative system that fires when the driver
stabs the throttle.

  Trigger:  delta(throttle_angle) per cycle
  Output:   Additional Injector Pulse Width (ms) added to base IPW
  Purpose:  Compensate for intake manifold fuel film lag on sudden throttle
            opening — prevents lean stumble during tip-in transients.
""")

    tip_a_axis = read_floats(rom, 0xCED08, 18)
    tip_a_data = read_uint16s(rom, 0xCED50, 18)
    tip_a_ms = [x * 0.004 for x in tip_a_data]

    print("  Throttle Tip-in Enrichment A (addr 0xCED50):")
    print(f"  {'Throttle Δ (%)':>15s}  {'Added IPW (ms)':>15s}")
    for i in range(len(tip_a_axis)):
        print(f"  {tip_a_axis[i]:>15.1f}  {tip_a_ms[i]:>15.3f}")

    print(f"\n  Activation Requirements:")
    min_thr = read_floats(rom, 0xCC4A0, 1)[0]
    min_ipw_raw = read_floats(rom, 0xCC4A4, 1)[0]
    min_ipw = min_ipw_raw * 0.004
    print(f"    Min Throttle Angle Change:  {min_thr:.1f}%")
    print(f"    Min Calculated IPW Adder:   {min_ipw:.3f} ms (after compensations)")
    print(f"    Applied Counter Reset:      {rom[0xCBC08]} cycles")
    print(f"    Throttle Cumulative Reset:  {rom[0xCBC09]} cycles")

    # ─── Tip-in Compensations ───
    print("\n  Tip-in Enrichment Compensations (multiply the base tip-in IPW):")

    print("\n  RPM Compensation (addr 0xCD118):")
    rpm_axis = read_floats(rom, 0xCD0D8, 16)
    tip_comp_rpm = read_uint8s(rom, 0xCD118, 16)
    tip_comp_rpm_pct = [(x * 0.78125) - 100 for x in tip_comp_rpm]
    print(f"    {'RPM':>6s}  {'Comp (%)':>10s}")
    for i in range(len(rpm_axis)):
        print(f"    {rpm_axis[i]:>6.0f}  {tip_comp_rpm_pct[i]:>10.1f}")
    print("    NOTE: At low RPM (<2000), tip-in enrichment is heavily reduced.")
    print("          Full enrichment only at ~4800+ RPM.")

    print("\n  ECT Compensation B (addr 0xCEDE0) — cold engine boost:")
    tip_comp_b = read_uint16s(rom, 0xCEDE0, 16)
    tip_comp_b_pct = [(x * 0.01220703125) - 100 for x in tip_comp_b]
    print(f"    {'ECT (°F)':>10s}  {'Comp (%)':>10s}")
    for i in range(len(ect_axis_f)):
        if tip_comp_b_pct[i] != 0:
            print(f"    {ect_axis_f[i]:>10.0f}  {tip_comp_b_pct[i]:>10.1f}")
    print("    Cold engines get up to 350% total tip-in enrichment (250% + base).")
    print("    At 140°F+, no additional ECT compensation.")

    # ─── SECTION 2: TAU TABLES ──────────────────────────────────────────────
    print("\n" + "─" * 78)
    print("SECTION 2: TAU — ALPHA TRANSIENT FUELING (Load-Rate Based)")
    print("─" * 78)
    print("""
The Tau system adds fuel based on ENGINE LOAD RATE OF CHANGE. It is a
load-derivative system that responds to changes in volumetric efficiency
and manifold filling — a fundamentally different trigger than tip-in.

  Trigger:  delta(engine_load) per cycle (g/rev change rate)
  Output:   Enrichment Adder Multiplier (dimensionless, multiplies a base adder)
  Purpose:  Compensate for fuel film dynamics during load transients that
            may NOT correspond to throttle changes (e.g., boost spool,
            gear changes, altitude changes).

The Tau value is an "Enrichment Adder Multiplier" — it scales how much
additional fuel is added during transient load conditions.
""")

    print("  Tau Input A Rising Load Activation (addr 0xCD6E6):")
    print("  (When engine load is INCREASING)")
    eload_axis = read_floats(rom, 0xCCDCC, 3)
    tau_rising = read_uint16s(rom, 0xCD6E6, 48)
    tau_rising_val = [x * 0.00048828125 for x in tau_rising]
    print(f"\n    {'':>10s}", end="")
    for t in ect_axis_f:
        print(f"  {t:>6.0f}°F", end="")
    print()
    for row in range(3):
        print(f"    {eload_axis[row]:>6.2f}g/r", end="")
        for col in range(16):
            print(f"  {tau_rising_val[row*16+col]:>7.3f}", end="")
        print()

    print("\n  Tau Input A Falling Load Activation (addr 0xCD746):")
    print("  (When engine load is DECREASING — fuel cut / decel)")
    tau_falling = read_uint16s(rom, 0xCD746, 16)
    tau_falling_val = [x * 0.00048828125 for x in tau_falling]
    print(f"    {'ECT (°F)':>10s}  {'Tau Multiplier':>15s}")
    for i in range(len(ect_axis_f)):
        print(f"    {ect_axis_f[i]:>10.0f}  {tau_falling_val[i]:>15.4f}")

    print("\n  Tau Falling Load Variants:")
    for label, addr in [("A", 0xCD766), ("B", 0xCD848), ("C", 0xCD868)]:
        vals = [x * 0.00048828125 for x in read_uint16s(rom, addr, 16)]
        cold = vals[0]
        warm = vals[10]
        hot = vals[15]
        print(f"    Variant {label} (addr 0x{addr:X}): cold={cold:.4f}  warm(140°F)={warm:.4f}  hot={hot:.4f}")

    # ─── SECTION 3: THE RELATIONSHIP ────────────────────────────────────────
    print("\n" + "─" * 78)
    print("SECTION 3: THE RELATIONSHIP BETWEEN TIP-IN AND TAU")
    print("─" * 78)
    print("""
  SUMMARY: Tip-in and Tau are TWO INDEPENDENT transient fueling systems
  that operate on DIFFERENT input signals but combine additively in the
  final fuel correction accumulator.

  ┌─────────────────────────────────────────────────────────────────────┐
  │                    TRANSIENT FUELING PIPELINE                      │
  │                                                                    │
  │  THROTTLE POSITION ──► delta(throttle)/dt ──► Tip-in Enrichment   │
  │                                                    │               │
  │                                                    ▼               │
  │                                              Additional IPW (ms)   │
  │                                              × RPM Comp            │
  │                                              × ECT Comp            │
  │                                              × Boost Error Comp    │
  │                                                    │               │
  │                                                    │  (if > min    │
  │                                                    │   threshold)  │
  │                                                    ▼               │
  │  ENGINE LOAD ────────► delta(load)/dt ──────► Tau Multiplier       │
  │                                                    │               │
  │                                                    ▼               │
  │                                              Tau × Base Adder      │
  │                                                    │               │
  │                                                    ▼               │
  │              ┌──────────────────────────────────────┘               │
  │              │                                                     │
  │              ▼                                                     │
  │     Final Fuel Correction Accumulator (0x320AE)                    │
  │     Final IPW = Base IPW × (1 + AFC) × (1 + LTFT) × corrections   │
  │                          + Tip-in Adder + Tau Adder                │
  └─────────────────────────────────────────────────────────────────────┘

  KEY DIFFERENCES:
  ───────────────────────────────────────────────────────────────────────
  Property              Tip-in Enrichment           Tau (Alpha Transient)
  ───────────────────────────────────────────────────────────────────────
  Trigger               Throttle angle change       Engine load change
  Units                 IPW adder (ms)              Enrichment multiplier
  Sensitivity           Throttle rate               Load rate (g/rev/cycle)
  Direction             Rising throttle only        Rising AND falling load
  Cold compensation     Yes (ECT B/C: up to +250%)  Yes (built into tables)
  RPM compensation      Yes (0-100% by RPM)         No (load-indexed)
  Boost compensation    Yes (reduces with boost)    Via manifold pressure axis
  Disable mechanism     Counter + cumulative        Separate variants (A-C)
  ───────────────────────────────────────────────────────────────────────

  HOW THEY INTERACT DURING A TYPICAL TIP-IN EVENT:
  ─────────────────────────────────────────────────

  1. Driver stabs throttle → large delta(throttle)
     → Tip-in system activates immediately with IPW adder (0.4-1.5 ms)
     → Compensations applied (RPM, ECT, boost error)
     → Result must exceed 1.32 ms minimum to actually fire

  2. As turbo spools and manifold fills → engine load rises
     → Tau system detects rising load rate
     → Tau multiplier applied (1.5-3.4× at cold, 0.25-1.5× at warm)
     → Adds enrichment proportional to load change rate

  3. The two systems overlap in time but trigger on different signals:
     - Tip-in fires FIRST (throttle moves before load changes)
     - Tau fires SECOND (load follows throttle with turbo lag)
     - Together they "bridge the gap" from throttle movement to full boost

  4. During tip-OUT (throttle closing):
     - Tip-in system: INACTIVE (only responds to rising throttle)
     - Tau falling load: ACTIVE (handles the fuel film evaporation
       during falling load — prevents rich spike on decel)

  TEMPERATURE RELATIONSHIP:
  ─────────────────────────
  Both systems provide MORE enrichment when the engine is COLD:
    - Tip-in ECT Comp B:  +250% at -40°F, tapering to 0% at 140°F
    - Tau Rising (1.75 g/r): 3.40× at -40°F, tapering to 0.32× at 176°F+

  This makes physical sense: cold intake ports have more fuel film
  condensation, requiring more aggressive transient compensation.

  LOAD/BOOST RELATIONSHIP:
  ────────────────────────
  - Tip-in reduces enrichment WITH boost error (up to -90.6% at 0 psi error)
    meaning when boost is ON TARGET, tip-in enrichment is nearly eliminated
  - Tau INCREASES enrichment at higher loads (3.40× vs 0.32× multiplier
    comparing 1.75 g/rev to 8.0 g/rev at hot temps)

  This is complementary: as boost builds and tip-in fades, tau picks up
  the transient fuel compensation role.
""")


if __name__ == "__main__":
    main()
