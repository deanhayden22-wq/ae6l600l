"""
Compare Tip-in Enrichment tables across stock / garn / current 20.14.

Highlights differences in the activation gates, base tables, AND all
the comps (RPM / Boost Error / ECT A-D / counters / cumulative).
"""
import struct
from pathlib import Path

ROMS = {
    "stock":  Path("rom/ae5l600l.bin"),
    "garn":   Path("rom/13 20g Base rev 25 e garn.hex"),
    "20.14":  Path("rom/AE5L600L 20g rev 20.14.bin"),
}
DATA = {k: v.read_bytes() for k, v in ROMS.items()}

def f(rom, a):     return struct.unpack(">f", DATA[rom][a:a+4])[0]
def u8(rom, a):    return DATA[rom][a]
def u16(rom, a):   return struct.unpack(">H", DATA[rom][a:a+2])[0]
def fs(rom, a, n): return [struct.unpack(">f", DATA[rom][a+4*i:a+4*i+4])[0] for i in range(n)]
def u8s(rom, a, n): return list(DATA[rom][a:a+n])
def u16s(rom, a, n):return [struct.unpack(">H", DATA[rom][a+2*i:a+2*i+2])[0] for i in range(n)]

# scalings
def sc_ipw(x):    return x * 0.004
def sc_comp_u8(x): return (x * 0.78125) - 100
def sc_comp_u16_2(x): return (x * 0.01220703125) - 100
def sc_comp_u16_1(x): return (x * 0.04882812) - 99.99998976
def sc_degF(c):   return (c * 1.8) + 32
def sc_cumthr(x): return x * 0.001907349
def sc_psi(x):    return x * 0.01933677

def cmp_table(name, addr, axis_addr, axis_n, axis_to_disp, dat_reader, dat_scaler, data_n, units, fmt="{:7.3f}"):
    print(f"\n## {name}")
    print(f"   data @ 0x{addr:05X}, axis @ 0x{axis_addr:05X}")
    print(f"   units: {units}")
    axes_raw = {rom: fs(rom, axis_addr, axis_n) for rom in DATA}
    axes_disp = {rom: ([axis_to_disp(a) for a in axes_raw[rom]] if axis_to_disp else axes_raw[rom]) for rom in DATA}
    axes_match = all(axes_raw["stock"] == axes_raw[r] for r in ["garn", "20.14"])
    if not axes_match:
        print(f"   !!! AXES DIFFER across ROMs (showing each ROM's own breakpoint) !!!")
    data = {rom: dat_reader(rom, addr, data_n) for rom in DATA}
    scaled = {rom: [dat_scaler(x) for x in data[rom]] for rom in DATA}

    # show two columns per ROM: axis breakpoint, data value
    print(f"   {'idx':>3} | " + " | ".join(f"{rom+' axis':>11} {rom+' val':>10}" for rom in DATA))
    print("   " + "-" * (4 + 26 * len(DATA)))
    for i in range(data_n):
        row = f"   {i:>3} |"
        diff_flag = False
        vals = []
        for rom in DATA:
            row += f" {axes_disp[rom][i]:>11.2f} {fmt.format(scaled[rom][i]):>10} |"
            vals.append(scaled[rom][i])
        if max(vals) - min(vals) > 0.01:
            row += " <-- VAL DIFF"
        print(row)

def cmp_scalar(name, addr, reader, scaler, units, fmt="{:.4f}"):
    vals = {rom: scaler(reader(rom, addr)) for rom in DATA}
    raws = {rom: reader(rom, addr) for rom in DATA}
    print(f"\n## {name}  @ 0x{addr:05X}")
    print(f"   units: {units}")
    for rom in DATA:
        diff = ""
        if rom != "stock" and abs(vals[rom] - vals["stock"]) > 0.001:
            diff = "   <-- DIFF vs stock"
        print(f"   {rom:>6}: {fmt.format(vals[rom])}  (raw {raws[rom]}){diff}")

# ============ ACTIVATION GATES ============
print("="*80)
print("ACTIVATION GATES")
print("="*80)

cmp_scalar("Minimum Tip-in Enrichment Activation (IPW)", 0xCC4A4, f, sc_ipw, "ms")
cmp_scalar("Minimum Tip-in Enrichment Activation (Throttle)", 0xCC4A0, f, lambda x: x, "%")
cmp_scalar("Tip-in Enrichment Compensation D Activation (Throttle)", 0xCC4A8, f, lambda x: x, "%")

# ============ BASE TABLES ============
print()
print("="*80)
print("BASE TIP-IN A / B (Throttle Change -> Additional IPW)")
print("="*80)

cmp_table("Throttle Tip-in Enrichment A", 0xCED50, 0xCED08, 18, None,
          u16s, sc_ipw, 18, "Additional IPW (ms)")
cmp_table("Throttle Tip-in Enrichment B", 0xCEDBC, 0xCED74, 18, None,
          u16s, sc_ipw, 18, "Additional IPW (ms)")

# ============ COMPS ============
print()
print("="*80)
print("COMPENSATIONS")
print("="*80)

cmp_table("Tip-in Compensation (RPM)", 0xCD118, 0xCD0D8, 9, None,
          u8s, sc_comp_u8, 9, "Comp (%)")

cmp_table("Tip-in Compensation (Boost Error)", 0xCD14C, 0xCD128, 9, sc_psi,
          u8s, sc_comp_u8, 9, "Comp (%)")

cmp_table("Tip-in Compensation A (ECT)", 0xCD155, 0xCC624, 16, sc_degF,
          u8s, sc_comp_u8, 16, "Comp (%)")

cmp_table("Tip-in Compensation B (ECT)", 0xCEDE0, 0xCC624, 16, sc_degF,
          u16s, sc_comp_u16_2, 16, "Comp (%)")

cmp_table("Tip-in Compensation C (ECT)", 0xCEE00, 0xCC624, 16, sc_degF,
          u16s, sc_comp_u16_2, 16, "Comp (%)")

cmp_table("Tip-in Compensation D (ECT)", 0xCEE40, 0xCC664, 16, sc_degF,
          u16s, sc_comp_u16_1, 16, "Comp (%)")

# ============ DISABLE COUNTERS ============
print()
print("="*80)
print("DISABLE COUNTERS")
print("="*80)

cmp_table("Disable Applied Counter Threshold A (ECT)", 0xCD165, 0xCC624, 16, sc_degF,
          u8s, lambda x: x, 16, "applied-counter limit (raw uint8)", fmt="{:7.0f}")

cmp_table("Disable Applied Counter Threshold B (ECT)", 0xCD175, 0xCC624, 16, sc_degF,
          u8s, lambda x: x, 16, "applied-counter limit (raw uint8)", fmt="{:7.0f}")

cmp_table("Disable Throttle Cumulative Threshold A (ECT)", 0xCEE60, 0xCC624, 16, sc_degF,
          u16s, sc_cumthr, 16, "cumulative %", fmt="{:7.2f}")

cmp_table("Disable Throttle Cumulative Threshold B (ECT)", 0xCEE80, 0xCC624, 16, sc_degF,
          u16s, sc_cumthr, 16, "cumulative %", fmt="{:7.2f}")

cmp_scalar("Tip-in Enrichment Applied Counter Reset", 0xCBC08, u8, lambda x: x, "period (raw uint8)", fmt="{:d}")
cmp_scalar("Tip-in Throttle Cumulative Reset", 0xCBC09, u8, lambda x: x, "period (raw uint8)", fmt="{:d}")
