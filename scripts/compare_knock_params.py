"""Compare knock detection / correction parameters between stock and tuned ROM.

Dumps every documented Ignition Timing - Knock table and related low-level
thresholds so we can eyeball what the tuner changed.
"""
import struct
import sys
from pathlib import Path

ROM_DIR = Path(r"C:\Users\Dean\Documents\GitHub\ae6l600l\rom")
STOCK = ROM_DIR / "ae5l600l.bin"
TUNED = ROM_DIR / "AE5L600L 20g rev 20.8 tiny wrex.bin"

def load(path):
    with open(path, "rb") as f:
        return f.read()

def f32(buf, addr, n=1):
    return [struct.unpack_from(">f", buf, addr + i*4)[0] for i in range(n)]

def u16(buf, addr, n=1):
    return [struct.unpack_from(">H", buf, addr + i*2)[0] for i in range(n)]

def u8(buf, addr, n=1):
    return list(buf[addr:addr+n])

def fmt_floats(vals):
    return "[" + ", ".join(f"{v:.4g}" for v in vals) + "]"

def cmp_scalar(name, addr, kind, n, s, t):
    if kind == "f32":
        sv, tv = f32(s, addr, n), f32(t, addr, n)
    elif kind == "u16":
        sv, tv = u16(s, addr, n), u16(t, addr, n)
    elif kind == "u8":
        sv, tv = u8(s, addr, n), u8(t, addr, n)
    changed = "*" if sv != tv else " "
    print(f"{changed} 0x{addr:06X}  {name}")
    print(f"      stock: {fmt_floats(sv) if kind=='f32' else sv}")
    print(f"      tuned: {fmt_floats(tv) if kind=='f32' else tv}")

stock = load(STOCK)
tuned = load(TUNED)

print("=" * 70)
print(f"STOCK: {STOCK.name}")
print(f"TUNED: {TUNED.name}")
print("=" * 70)
print()
print("--- FLKC hard-coded constants (from knock_flkc_report.txt) ---")
cmp_scalar("FLKC gate threshold (knock_metric max)",   0xD2F40, "f32", 1, stock, tuned)
cmp_scalar("FLKC upper clamp (max advance cap)",       0xD2F44, "f32", 1, stock, tuned)
cmp_scalar("FLKC retard step per event",               0xD2F48, "f32", 1, stock, tuned)
cmp_scalar("FLKC lower clamp (max retard floor)",      0xD2F4C, "f32", 1, stock, tuned)
cmp_scalar("FLKC recovery rate path 1",                0xD2F54, "f32", 1, stock, tuned)
cmp_scalar("FLKC recovery rate path 2",                0xD2F58, "f32", 1, stock, tuned)
cmp_scalar("RPM gate threshold 1 (scaled)",            0xD2D54, "f32", 1, stock, tuned)
cmp_scalar("RPM gate threshold 2 (scaled)",            0xD2D58, "f32", 1, stock, tuned)
cmp_scalar("Knock sig low threshold",                  0xD2D60, "f32", 1, stock, tuned)
cmp_scalar("Knock sig high threshold",                 0xD2D64, "f32", 1, stock, tuned)
cmp_scalar("Low-knock retard step",                    0xD2D68, "f32", 1, stock, tuned)
cmp_scalar("High-knock small step",                    0xD2D6C, "f32", 1, stock, tuned)
cmp_scalar("High-knock step alt",                      0xD2D70, "f32", 1, stock, tuned)
cmp_scalar("Very small step",                          0xD2D74, "f32", 1, stock, tuned)
cmp_scalar("Secondary gate threshold",                 0xD2D78, "f32", 1, stock, tuned)
cmp_scalar("Counter threshold words (250/125)",        0xD29DC, "u16", 2, stock, tuned)
cmp_scalar("FLKC counter threshold (125 cyc)",         0xD29EE, "u16", 1, stock, tuned)
cmp_scalar("knock_enable_rom_flag",                    0xD298B, "u8",  1, stock, tuned)
cmp_scalar("knock_enable_alt_flag 0xD2994",            0xD2994, "u8",  1, stock, tuned)

print()
print("--- XML-defined knock correction calibrations ---")
cmp_scalar("Feedback Correction Range (RPM)",          0xD2DAC, "f32", 2, stock, tuned)
cmp_scalar("Feedback Correction Minimum Load",         0xD2DA4, "f32", 2, stock, tuned)
cmp_scalar("Feedback Correction Retard Value",         0xD2DCC, "f32", 1, stock, tuned)
cmp_scalar("Feedback Correction Retard Limit",         0xD2DC8, "f32", 1, stock, tuned)
cmp_scalar("Feedback Correction Negative Adv Value",   0xD2DD0, "f32", 1, stock, tuned)
cmp_scalar("Feedback Correction Neg Adv Delay",        0xD29DE, "u16", 1, stock, tuned)
cmp_scalar("Extended Feedback HighRPM Comp",           0xD2DD8, "f32", 1, stock, tuned)

print()
cmp_scalar("Fine Correction Range (RPM)",              0xD2F6C, "f32", 2, stock, tuned)
cmp_scalar("Fine Correction Range (Load)",             0xD2F7C, "f32", 2, stock, tuned)
cmp_scalar("Fine Correction Rows (RPM)",               0xD2F0C, "f32", 7, stock, tuned)
cmp_scalar("Fine Correction Cols (Load)",              0xD2F28, "f32", 7, stock, tuned)
cmp_scalar("Fine Correction Retard Value",             0xD2F50, "f32", 1, stock, tuned)
cmp_scalar("Fine Correction Retard Limit",             0xD2F4C, "f32", 1, stock, tuned)
cmp_scalar("Fine Correction Advance Value",            0xD2F48, "f32", 1, stock, tuned)
cmp_scalar("Fine Correction Advance Limit",            0xD2F44, "f32", 1, stock, tuned)
cmp_scalar("Fine Correction Advance Delay",            0xD29EE, "u16", 1, stock, tuned)

print()
cmp_scalar("Rough Correction Range (RPM)",             0xD2EBC, "f32", 2, stock, tuned)
cmp_scalar("Rough Correction Range (Load)",            0xD2ECC, "f32", 2, stock, tuned)
cmp_scalar("Rough Correction Min KC Advance Map Val",  0xD2EDC, "f32", 1, stock, tuned)

print()
cmp_scalar("Advance Multiplier (Initial)",             0xD2EE0, "f32", 1, stock, tuned)
cmp_scalar("Advance Multiplier Step Value",            0xD2EE4, "f32", 1, stock, tuned)

print()
print("--- Knock Correction Advance Max (Cruise) 0xd5904 17x13 ---")
s_km = f32(stock, 0xD5904, 17*13)
t_km = f32(tuned, 0xD5904, 17*13)
changed = sum(1 for a,b in zip(s_km,t_km) if a!=b)
print(f"  Changed cells: {changed}/{17*13}")
print(f"  Stock  min={min(s_km):.3f}  max={max(s_km):.3f}")
print(f"  Tuned  min={min(t_km):.3f}  max={max(t_km):.3f}")

print()
print("--- Knock Correction Advance Max (Non-Cruise) 0xd5ac4 17x13 ---")
s_kn = f32(stock, 0xD5AC4, 17*13)
t_kn = f32(tuned, 0xD5AC4, 17*13)
changed = sum(1 for a,b in zip(s_kn,t_kn) if a!=b)
print(f"  Changed cells: {changed}/{17*13}")
print(f"  Stock  min={min(s_kn):.3f}  max={max(s_kn):.3f}")
print(f"  Tuned  min={min(t_kn):.3f}  max={max(t_kn):.3f}")
