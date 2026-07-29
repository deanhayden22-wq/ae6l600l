#!/usr/bin/env python3
"""
injector_rescale.py -- compute every ROM value that must change when the
injectors are swapped, for AE5L600L.

WHY A TOOL AND NOT A CHECKLIST
------------------------------
The injector swap touches two disjoint sets of values and it is easy to
confuse them:

  (1) Values that are an ABSOLUTE TIME (ms of injector on-time, or an ms
      threshold that a computed pulse width is compared against).  These all
      scale by the SAME factor k = old_flow / new_flow, because the ECU turns
      a fuel mass demand into a time by multiplying by one constant.

  (2) Values that are a PERCENTAGE, a ratio, an RPM, a temperature or an AFR.
      These do NOT change.  Rescaling them is the classic way to break a tune
      while believing you did the swap correctly.

Everything in group (1) is enumerated below with ROM evidence.  The tool reads
the current values out of a bin and prints the rescaled ones in BOTH display
units (what ECUFlash shows) and raw stored units.

THE ONE CONSTANT THAT SETS EVERYTHING
-------------------------------------
`Injector Flow Scaling` @0xCBE0C, float, raw 4916.0 in every rev of this ROM.

  ECUFlash display  = 2707090 / raw  = 550.669 cc/min  ("ESTIMATED Flow Rate -
                      Gas Only", i.e. referenced to the stock fuel pressure)

  Verified from ROM bytes -- 0x000CBE0C has exactly ONE literal reference in
  the whole 1 MB image (pool @0x0303B0), consumed by the function at 0x030378:

      030378  sts.l pr,@-r15
      03037A  mov.l @(0x3038,pc),r2   ; = 0xFFFF63F8  (engine load, g/rev)
      03037C  fmov.s @r2,fr4
      030384  mov.l @(0x30B0,pc),r2   ; = 0x000CBE0C  (flow scaling)
      030388  fmov.s @r2,fr8          ; fr8 = 4916.0
      03038A  fmul   fr8,fr4          ; fr4 = load * 4916.0
      03039C  jsr    @r2              ; = 0xBE56C float clamp, lo=0.0 hi=131072.0
      0303A6  fmov.s fr0,@r2          ; -> 0xFFFF7348

  So injector on-time is directly proportional to this constant.  Bigger
  injector -> larger cc/min -> SMALLER raw constant -> shorter pulse width for
  the same air mass.  Every ms-domain calibration therefore scales by

      k = 550.669 / new_cc_min   ( == new_raw / 4916.0 )

WHAT THIS TOOL DELIBERATELY DOES NOT DO
---------------------------------------
  * It does not write the ROM.  ECUFlash owns the bin and recomputes the
    Subaru checksum on save; edits are made in the ECUFlash UI.
  * It does not touch `Injector Latency_` @0xD106C.  Dead time is a property
    of the new injector and its driver, not of a flow ratio -- it comes off
    the new injector's data sheet.  The tool prints the current curve so you
    have something to compare the new numbers against.
  * It does not touch the definition XMLs (see CLAUDE.md).

Usage:
    python scripts/injector_rescale.py --new-cc 1050
    python scripts/injector_rescale.py --new-cc 1050 --rom "rom/AE5L600L 20g rev 20.19c.bin"
    python scripts/injector_rescale.py --list          # inventory only, no maths
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import defs  # noqa: E402

FLOW_ADDR = 0xCBE0C
FLOW_NUMERATOR = 2707090.0          # ECUFlash 'ESTIMATED Flow Rate - Gas Only'
DEFAULT_ROM = "rom/AE5L600L 20g rev 20.19c.bin"

# ---------------------------------------------------------------------------
# GROUP 1 -- absolute ms.  Scale the DATA by k.
# ---------------------------------------------------------------------------
SCALE_DATA = [
    # (table name, note)
    ("Cranking Fuel Injector Pulse Width A (ECT)", "cold-start IPW vs ECT"),
    ("Cranking Fuel Injector Pulse Width B (ECT)", "cold-start IPW vs ECT"),
    ("Cranking Fuel Injector Pulse Width C (ECT)", "cold-start IPW vs ECT"),
    ("Cranking Fuel Injector Pulse Width D (ECT)", "cold-start IPW vs ECT"),
    ("Cranking Fuel Injector Pulse Width E (ECT)", "cold-start IPW vs ECT"),
    ("Cranking Fuel Injector Pulse Width F (ECT)", "cold-start IPW vs ECT"),
    ("Throttle Tip-in Enrichment A", "additive ms fired on tip-in"),
    ("Throttle Tip-in Enrichment B", "additive ms fired on tip-in"),
    ("Minimum Tip-in Enrichment Activation", "min additive ms before tip-in arms"),
    ("Overrun initial injector enrichment (pulsewidth)", "additive ms on fuel-cut resume"),
    ("CL to OL Transition with Delay (Base Pulse Width)",
     "BPW threshold vs RPM -- INERT while 'CL to OL Delay_' == 0"),
    ("CL to OL Transition with Delay BPW Hysteresis",
     "INERT while 'CL to OL Delay_' == 0"),
]

# ---------------------------------------------------------------------------
# GROUP 2 -- data is a percentage, but the AXIS is absolute ms.
# Scale the AXIS by k; leave the data alone.
# ---------------------------------------------------------------------------
SCALE_AXIS = [
    ("Per Injector Pulse Width Compensation A", "X"),
    ("Per Injector Pulse Width Compensation B", "X"),
    ("Per Injector Pulse Width Compensation C", "X"),
    ("Per Injector Pulse Width Compensation D", "X"),
]

# ---------------------------------------------------------------------------
# GROUP 3 -- looks injector-related by name, is NOT.  Do not touch.
# ---------------------------------------------------------------------------
DO_NOT_TOUCH = [
    ("0xD39A8", "Low Pulse Width Fuel Injector Compensation",
     "MISIDENTIFIED. Axis @0xD3988 is RPM (700..4500), not ms -- the only "
     "consumer is 0x0434C2, which passes fr4 = [0xFFFF6624] (RPM) to the "
     "lookup at 0xBE874. Result byte is stored to 0xFFFF80EC "
     "(timing_comp_lowpw_state). Gates are the map-switch constants."),
    ("0xD2D28", "Low pulse width fuel injector compensation maximum RPM",
     "Lower bound of an RPM window (continue if RPM >= this). Raw 10000.0."),
    ("0xD2D2C", "Low pulse width fuel injector compensation maximum IPW",
     "MISIDENTIFIED as ms. Upper bound of the same RPM window, compared "
     "against fr4 = RPM at 0x0434B6. Raw 10000.0 = 10000 RPM, not 10.0 ms. "
     "Window is empty (10000..10000) so the whole branch is dead."),
    ("0xCF704 / 0xCF6B0 / 0xCC868 / 0xCC89C / 0xCC8BC",
     "Cranking Fuel IPW Compensation (RPM/MAP/Accel/IAT)",
     "Percentage multipliers on the cranking IPW. Dimensionless -- no rescale."),
    ("0xCD118 / 0xCD14C / 0xCD155 / 0xCEDE0 / 0xCEE00 / 0xCEE40",
     "Tip-in Enrichment Compensation (RPM / Boost Error / ECT A-D)",
     "Percentage multipliers on the tip-in adder. No rescale."),
    ("0xD8C9C", "MAF Sensor Scaling",
     "Airflow, upstream of fuelling. Unaffected by injector size."),
    ("0xD0244 / 0xD0404 / 0xCFD30 / ...", "Primary Open Loop Fueling (all)",
     "Target AFR. Unaffected by injector size."),
    ("0xCC830 / 0xCF8B8 / 0xCF95C", "Min Primary Base Enrichment 1",
     "Lambda-offset additive (raw*0.00390625, currently 0.5). Not ms."),
]


def fmt(vals, nd=4):
    if isinstance(vals, (int, float)):
        return "%.*g" % (nd + 2, vals)
    return "[" + ", ".join("%.*g" % (nd + 2, v) for v in vals) + "]"


def fmt_raw(vals, scaling):
    """Raw values print as integers unless the storage type is float."""
    if (scaling.storagetype or "").startswith("float"):
        return fmt(vals)
    return "[" + ", ".join("%d" % v for v in vals) + "]"


def flatten(v):
    if isinstance(v, (int, float)):
        return [v]
    out = []
    for e in v:
        out.extend(flatten(e))
    return out


def requantise(scaling, raw_new):
    """Round a rescaled raw value back onto the storage type's grid."""
    st = scaling.storagetype or ""
    if st.startswith("float"):
        return raw_new
    lim = {"uint8": 255, "int8": 127, "uint16": 65535, "int16": 32767}.get(st)
    v = int(round(raw_new))
    if lim is not None:
        v = max(-lim - 1 if st.startswith("int") else 0, min(lim, v))
    return v


def report_table(t, k, buf, which="data"):
    raw = flatten(t.read_raw(buf))
    disp = flatten(t.read(buf))
    new_raw = [requantise(t.scaling, r * k) for r in raw]
    new_disp = [t.scaling.to_display(r) for r in new_raw]
    lost = [i for i, (a, b) in enumerate(zip(raw, new_raw))
            if a != 0 and abs(b - a * k) / abs(a * k) > 0.02]
    print("  now  (display): %s" % fmt(disp))
    print("  NEW  (display): %s" % fmt(new_disp))
    print("  NEW  (raw)    : %s" % fmt_raw(new_raw, t.scaling))
    if lost:
        print("  !! %d cell(s) off by >2%% after rounding to %s: index %s"
              % (len(lost), t.scaling.storagetype, lost))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--new-cc", type=float,
                    help="new injector flow in cc/min, on the SAME reference "
                         "pressure ECUFlash's 'ESTIMATED Flow Rate - Gas Only' uses")
    ap.add_argument("--new-raw", type=float,
                    help="alternative: set the raw 0xCBE0C constant directly")
    ap.add_argument("--rom", default=DEFAULT_ROM)
    ap.add_argument("--list", action="store_true",
                    help="print the inventory and exit (no rescale)")
    ap.add_argument("--skip-percyl", action="store_true",
                    help="omit the Per Injector PW Compensation ms axes (group 2). "
                         "Use when those four tables are being left at stock for "
                         "now -- the axes are only worth moving if you are also "
                         "deciding what to do with the %%-data they index.")
    a = ap.parse_args()

    d = defs.load()
    buf = open(a.rom, "rb").read()

    flow = d.get("Injector Flow Scaling")
    cur_raw = flow.read_raw(buf)
    cur_cc = flow.read(buf)[0] if isinstance(flow.read(buf), list) else flow.read(buf)
    if isinstance(cur_raw, list):
        cur_raw = cur_raw[0]

    print("=" * 78)
    print("INJECTOR RESCALE -- %s" % a.rom)
    print("=" * 78)
    print("current Injector Flow Scaling @0x%05X : raw %.6g  =  %.3f cc/min"
          % (FLOW_ADDR, cur_raw, cur_cc))

    if a.list or (a.new_cc is None and a.new_raw is None):
        print("\n(no --new-cc given; inventory only)\n")
        print("-- GROUP 1: scale the DATA by k --")
        for name, note in SCALE_DATA:
            t = d.get(name)
            print("  0x%05X  %-52s  %s" % (t.address, name, note))
        print("\n-- GROUP 2: scale the ms AXIS by k, leave data alone --")
        for name, ax in SCALE_AXIS:
            t = d.get(name)
            axis = t.x_axis if ax == "X" else t.y_axis
            print("  0x%05X  %-52s  axis @0x%05X '%s'"
                  % (t.address, name, axis.address, axis.name))
        print("\n-- REPLACE FROM THE NEW INJECTOR'S DATA SHEET (not a flow ratio) --")
        lat = d.get("Injector Latency_")
        print("  0x%05X  %-52s  %s" % (lat.address, "Injector Latency_",
                                       "dead time vs battery volts"))
        print("\n-- DO NOT TOUCH --")
        for addr, name, why in DO_NOT_TOUCH:
            print("  %-42s %s" % (addr, name))
            print("      %s" % why)
        return 0

    if a.new_raw is not None:
        new_raw = a.new_raw
        new_cc = FLOW_NUMERATOR / new_raw
    else:
        new_cc = a.new_cc
        new_raw = FLOW_NUMERATOR / new_cc

    k = new_raw / cur_raw
    print("target  Injector Flow Scaling @0x%05X : raw %.6g  =  %.3f cc/min"
          % (FLOW_ADDR, new_raw, new_cc))
    print("scale factor k = %.6f   (all ms-domain values multiply by this)" % k)
    print()

    print("=" * 78)
    print("GROUP 1 -- scale the DATA")
    print("=" * 78)
    for name, note in SCALE_DATA:
        t = d.get(name)
        print("\n0x%05X  %s" % (t.address, name))
        print("  (%s)" % note)
        report_table(t, k, buf)

    print()
    print("=" * 78)
    if a.skip_percyl:
        print("GROUP 2 -- SKIPPED (--skip-percyl)")
        print("=" * 78)
        print("Per Injector Pulse Width Compensation A-D and their ms axes are")
        print("left at stock. Their %-data characterises the OEM injector, so it")
        print("is wrong for the new one either way; moving the axis alone does not")
        print("fix that. Revisit after the first drive -- docs/injector-rescale.md")
        print("section 3 has the three options.")
        SCALE_AXIS_RUN = []
    else:
        print("GROUP 2 -- scale the ms AXIS only; the %-data stays as it is")
        print("=" * 78)
        SCALE_AXIS_RUN = SCALE_AXIS
    for name, ax in SCALE_AXIS_RUN:
        t = d.get(name)
        axis = t.x_axis if ax == "X" else t.y_axis
        raw = axis.read_raw(buf) if hasattr(axis, "read_raw") else None
        cur = axis.read(buf)
        new = [v * k for v in cur]
        print("\n0x%05X  %s" % (axis.address, name))
        print("  axis '%s' @0x%05X" % (axis.name, axis.address))
        print("  now : %s" % fmt(cur))
        print("  NEW : %s" % fmt(new))
        _ = raw

    print()
    print("=" * 78)
    print("DEAD TIME -- replace from the injector's data sheet, do NOT scale by k")
    print("=" * 78)
    lat = d.get("Injector Latency_")
    print("0x%05X  Injector Latency_   %d x %d" % ((lat.address,) + lat.shape))
    print("  battery axis (V) @0x%05X : %s" % (lat.x_axis.address, fmt(lat.x_axis.read(buf))))
    print("  current dead time (ms), all %d MAP rows identical:" % lat.shape[0])
    print("    %s" % fmt(lat.read(buf)[0]))
    print("  storage uint16, display = raw * 0.00025 ms  (raw 4000 = 1.000 ms)")

    print()
    print("=" * 78)
    print("DO NOT TOUCH")
    print("=" * 78)
    for addr, name, why in DO_NOT_TOUCH:
        print("%-42s %s" % (addr, name))
        print("    %s" % why)
    return 0


if __name__ == "__main__":
    sys.exit(main())
