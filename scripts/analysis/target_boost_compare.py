"""
Compare Target Boost map across stock / garn / 20.14.

Tests Dean's hypothesis: is stock target boost designed INTENTIONALLY HIGH
relative to achievable boost, to maintain elevated BoostErr so tip-in
BoostErr comp stays engaged?
"""
import struct
from pathlib import Path
import numpy as np

ROMS = {
    "stock":  Path("rom/ae5l600l.bin"),
    "garn":   Path("rom/13 20g Base rev 25 e garn.hex"),
    "20.14":  Path("rom/AE5L600L 20g rev 20.14.bin"),
}
DATA = {k: v.read_bytes() for k, v in ROMS.items()}

def f(rom, a):     return struct.unpack(">f", DATA[rom][a:a+4])[0]
def u16(rom, a):   return struct.unpack(">H", DATA[rom][a:a+2])[0]
def fs(rom, a, n): return [struct.unpack(">f", DATA[rom][a+4*i:a+4*i+4])[0] for i in range(n)]
def u16s(rom, a, n): return [struct.unpack(">H", DATA[rom][a+2*i:a+2*i+2])[0] for i in range(n)]

# Boost target scaling: psi relative = (raw_u16 - 760) * 0.01933677
def sc_boost(x): return (x - 760) * 0.01933677

# RQTQ scaling — typical Subaru
def sc_rqtq(x): return x * 0.0078125

# Read axes (Requested Torque x 8, RPM x 12)
# Stock and 20.14 should share addresses; need to verify garn has same addresses
TB_ADDR = 0xC1340
XAX = 0xC12D8  # Requested Torque axis (8 floats)
YAX = 0xC1304  # Engine Speed axis (12 floats)

for rom in DATA:
    print(f"\n## {rom} Target Boost (RPM y x RQTQ x):")
    xax = fs(rom, XAX, 8)   # Requested Torque
    yax = fs(rom, YAX, 12)  # Engine Speed
    print(f"  RQTQ axis: {[f'{x:.1f}' for x in xax]}")
    print(f"  RPM axis:  {[f'{y:.0f}' for y in yax]}")
    # data table (12 rows RPM x 8 cols RQTQ, uint16 each)
    # storage order: assume row-major with Y outer, X inner
    raw = u16s(rom, TB_ADDR, 8*12)
    psi = [sc_boost(x) for x in raw]
    print(f"\n         " + "  ".join(f"{xv:>6.0f}" for xv in xax))
    for i in range(12):
        row = psi[i*8:(i+1)*8]
        print(f"  RPM={yax[i]:>5.0f}  " + "  ".join(f"{v:>6.2f}" for v in row))

# Now compute BE we'd expect at typical lean-event operating point:
# 20% throttle (mapped to some RQTQ value), 2800 RPM, mrp ~-5 psi
# Question: at modest RQTQ at 2800 RPM, what target boost does each ROM command?

print("\n\n## Target boost lookup at example operating points (in psi rel sea level):")
print("  RQTQ values shown are interpolated linearly between axis breakpoints.")

def lookup_tb(rom, rqtq, rpm):
    xax = np.array(fs(rom, XAX, 8))
    yax = np.array(fs(rom, YAX, 12))
    raw = np.array(u16s(rom, TB_ADDR, 8*12)).reshape(12, 8)
    psi = (raw - 760) * 0.01933677
    # bilinear interpolate
    from numpy import interp
    # interp along x for each y row
    row_vals = np.array([interp(rqtq, xax, psi[i]) for i in range(12)])
    return float(interp(rpm, yax, row_vals))

cases = [
    ("light cruise: RQTQ 100, 2400 RPM", 100, 2400),
    ("modest stab: RQTQ 200, 2800 RPM", 200, 2800),
    ("Dean's lean spike: RQTQ ~180, 2780 RPM", 180, 2780),
    ("harder stab: RQTQ 300, 3000 RPM", 300, 3000),
    ("approaching WOT: RQTQ 400, 3500 RPM", 400, 3500),
]
hdr = f"  {'case':>50} | " + " | ".join(f"{rom:>8}" for rom in DATA)
print(hdr)
print("  " + "-" * (len(hdr) - 2))
for name, rqtq, rpm in cases:
    row = f"  {name:>50} | "
    vals = [lookup_tb(rom, rqtq, rpm) for rom in DATA]
    row += " | ".join(f"{v:>+7.2f}" for v in vals)
    print(row)
