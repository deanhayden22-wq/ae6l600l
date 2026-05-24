"""
Read the current 20.14 ROM's Tip-in Enrichment tables and print scaled values.

All ECT axes show in BOTH C (storage) and F (display) since memory note says
this ROM stores ECT in Celsius and the RomRaider DegreesF scaling converts.
"""
import struct
from pathlib import Path

ROM = Path("rom/AE5L600L 20g rev 20.14.bin").read_bytes()

def read_float(addr): return struct.unpack(">f", ROM[addr:addr+4])[0]
def read_u8(addr):    return ROM[addr]
def read_u16(addr):   return struct.unpack(">H", ROM[addr:addr+2])[0]

def read_floats(addr, n): return [struct.unpack(">f", ROM[addr+4*i:addr+4*i+4])[0] for i in range(n)]
def read_u8s(addr, n):    return list(ROM[addr:addr+n])
def read_u16s(addr, n):   return [struct.unpack(">H", ROM[addr+2*i:addr+2*i+2])[0] for i in range(n)]

# Scaling functions
def sc_ipw(x):    return x * 0.004                      # additional IPW (ms)
def sc_app(x):    return x                              # throttle angle change (%) -- raw is %
def sc_comp_u8(x): return (x * 0.78125) - 100           # tip-in comp uint8: -100..+99.2
def sc_comp_u16_2(x): return (x * 0.01220703125) - 100  # tip-in comp uint16 variant 2
def sc_comp_u16_1(x): return (x * 0.04882812) - 99.99998976  # tip-in comp uint16 variant 1
def sc_degF_from_C(c): return (c * 1.8) + 32
def sc_cumthrottle(x): return x * 0.001907349
def sc_psi(x):    return x * 0.01933677

def print_2d(name, ax_label, ax_values_raw, ax_to_display, data_raw, data_to_scaled, units, fmt="%.3f"):
    print(f"\n## {name}")
    print(f"  axis: {ax_label}")
    print(f"  data units: {units}")
    if ax_to_display:
        ax_disp = [ax_to_display(a) for a in ax_values_raw]
    else:
        ax_disp = list(ax_values_raw)
    data_scaled = [data_to_scaled(d) for d in data_raw]
    lines = []
    for axv, dv in zip(ax_disp, data_scaled):
        lines.append(f"    {axv:>10.2f}  ->  " + (fmt % dv))
    print("\n".join(lines))

def print_scalar(name, value, units=""):
    print(f"\n## {name}")
    print(f"  value: {value}{(' ' + units) if units else ''}")

# 1. Throttle Tip-in Enrichment A (18 elements, uint16, ms)
ax_a = read_floats(0xCED08, 18)   # Throttle Angle Change axis (float %)
dat_a = read_u16s(0xCED50, 18)    # data uint16
print_2d("Throttle Tip-in Enrichment A  @ 0xCED50  (axis @ 0xCED08)",
         "Throttle Angle Change (%)", ax_a, None,
         dat_a, sc_ipw, "Additional IPW (ms)")

# 2. Throttle Tip-in Enrichment B (18 elements, uint16, ms)
ax_b = read_floats(0xCED74, 18)
dat_b = read_u16s(0xCEDBC, 18)
print_2d("Throttle Tip-in Enrichment B  @ 0xCEDBC  (axis @ 0xCED74)",
         "Throttle Angle Change (%)", ax_b, None,
         dat_b, sc_ipw, "Additional IPW (ms)")

# 3. Activation thresholds (scalars)
v = read_float(0xCC4A4)
print_scalar("Minimum Tip-in Enrichment Activation @ 0xCC4A4",
             f"{sc_ipw(v):.4f}", "ms (raw float {:.3f})".format(v))

v = read_float(0xCC4A0)
print_scalar("Minimum Tip-in Enrichment Activation (Throttle) @ 0xCC4A0",
             f"{v:.3f}", "% throttle change (raw float)")

# 4. RPM compensation (9 elements, uint8)
ax_rpm = read_floats(0xCD0D8, 9)
dat_rpm = read_u8s(0xCD118, 9)
print_2d("Tip-in Enrichment Compensation (RPM)  @ 0xCD118  (axis @ 0xCD0D8)",
         "Engine Speed (RPM)", ax_rpm, None,
         dat_rpm, sc_comp_u8, "Comp (%)  [-100..+99.2]")

# 5. Boost Error compensation (9 elements, uint8)
ax_be = read_floats(0xCD128, 9)
dat_be = read_u8s(0xCD14C, 9)
print_2d("Tip-in Enrichment Compensation (Boost Error)  @ 0xCD14C  (axis @ 0xCD128)",
         "Boost Error (psi)", ax_be, sc_psi,
         dat_be, sc_comp_u8, "Comp (%)  [-100..+99.2]")

# 6. ECT compensation A (16 elements, uint8) — Celsius axis presented as F
ax_ect = read_floats(0xCC624, 16)
dat_ect_a = read_u8s(0xCD155, 16)
print_2d("Tip-in Enrichment Compensation A (ECT)  @ 0xCD155  (axis @ 0xCC624)",
         "ECT (degF, raw is degC)", ax_ect, sc_degF_from_C,
         dat_ect_a, sc_comp_u8, "Comp (%)")

# 7. ECT compensation B (16 elements, uint16, comp2 scaling)
dat_ect_b = read_u16s(0xCEDE0, 16)
print_2d("Tip-in Enrichment Compensation B (ECT)  @ 0xCEDE0  (axis @ 0xCC624)",
         "ECT (degF)", ax_ect, sc_degF_from_C,
         dat_ect_b, sc_comp_u16_2, "Comp (%)")

# 8. ECT compensation C (16 elements, uint16, comp2 scaling)
dat_ect_c = read_u16s(0xCEE00, 16)
print_2d("Tip-in Enrichment Compensation C (ECT)  @ 0xCEE00  (axis @ 0xCC624)",
         "ECT (degF)", ax_ect, sc_degF_from_C,
         dat_ect_c, sc_comp_u16_2, "Comp (%)")

# 9. ECT compensation D (16 elements, uint16, comp1 scaling) — axis is different (cc664)
ax_ect_d = read_floats(0xCC664, 16)
dat_ect_d = read_u16s(0xCEE40, 16)
print_2d("Tip-in Enrichment Compensation D (ECT)  @ 0xCEE40  (axis @ 0xCC664)",
         "ECT (degF)", ax_ect_d, sc_degF_from_C,
         dat_ect_d, sc_comp_u16_1, "Comp (%)")

# 10. D activation threshold (scalar, throttle change %)
v = read_float(0xCC4A8)
print_scalar("Tip-in Enrichment Compensation D (ECT) Activation @ 0xCC4A8",
             f"{v:.3f}", "% throttle change above which D-comp activates")

# 11. Disable Applied Counter Thresholds A & B (16 ECT entries, uint8)
dat = read_u8s(0xCD165, 16)
print_2d("Tip-in Enrichment Disable Applied Counter Threshold A (ECT) @ 0xCD165",
         "ECT (degF)", ax_ect, sc_degF_from_C, dat, lambda x: x,
         "applied-counter limit (raw uint8)", fmt="%d")
dat = read_u8s(0xCD175, 16)
print_2d("Tip-in Enrichment Disable Applied Counter Threshold B (ECT) @ 0xCD175",
         "ECT (degF)", ax_ect, sc_degF_from_C, dat, lambda x: x,
         "applied-counter limit (raw uint8)", fmt="%d")

# 12. Disable Throttle Cumulative Thresholds A & B (16 ECT entries, uint16, scaled)
dat = read_u16s(0xCEE60, 16)
print_2d("Tip-in Enrichment Disable Throttle Cumulative Threshold A (ECT) @ 0xCEE60",
         "ECT (degF)", ax_ect, sc_degF_from_C, dat, sc_cumthrottle, "cumulative %")
dat = read_u16s(0xCEE80, 16)
print_2d("Tip-in Enrichment Disable Throttle Cumulative Threshold B (ECT) @ 0xCEE80",
         "ECT (degF)", ax_ect, sc_degF_from_C, dat, sc_cumthrottle, "cumulative %")

# 13. Counter resets (scalars, uint8)
v = read_u8(0xCBC08)
print_scalar("Tip-in Enrichment Applied Counter Reset @ 0xCBC08",
             f"{v}", "raw uint8 (period units)")
v = read_u8(0xCBC09)
print_scalar("Tip-in Throttle Cumulative Reset @ 0xCBC09",
             f"{v}", "raw uint8 (period units)")
