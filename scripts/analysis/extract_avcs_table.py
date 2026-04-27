#!/usr/bin/env python3
"""Extract Intake Cam Advance Angle Cruise (AVCS) table from 20.9 and 20.10 ROMs.

Per project definitions XML (AE5L600L 2013 USDM Impreza WRX MT.xml):
  Table: address=0xda96c, X(Engine Load)=18 elements at 0xda8e4 (float),
         Y(Engine Speed)=16 elements at 0xda92c (float),
         data scaling Advance(degrees) = raw_uint16 * 0.0054931640625
"""
import struct
import json
import os

ROM_DIR = "/sessions/tender-wizardly-brown/mnt/ae6l600l/rom"
ROMS = {
    "20.9":  os.path.join(ROM_DIR, "AE5L600L 20g rev 20.9 tiny wrex.bin"),
    "20.10": os.path.join(ROM_DIR, "AE5L600L 20g rev 20.10 tiny wrex.bin"),
}

LOAD_ADDR  = 0xda8e4   # 18 floats (g/rev)
RPM_ADDR   = 0xda92c   # 16 floats (RPM)
TABLE_ADDR = 0xda96c   # 18 X x 16 Y uint16, big-endian
N_LOAD = 18
N_RPM  = 16
SCALE  = 0.0054931640625  # advance degrees per LSB

def read_floats(buf, off, n):
    return list(struct.unpack(">" + "f"*n, buf[off:off+4*n]))

def read_table(buf, off, nx, ny):
    raw = struct.unpack(">" + "H"*(nx*ny), buf[off:off+2*nx*ny])
    # Subaru: outer index Y (RPM), inner X (Load) -> rows = RPM, cols = Load
    out = [[raw[y*nx + x] * SCALE for x in range(nx)] for y in range(ny)]
    return out

result = {}
for tag, path in ROMS.items():
    with open(path, "rb") as f:
        buf = f.read()
    load_axis = read_floats(buf, LOAD_ADDR, N_LOAD)
    rpm_axis  = read_floats(buf, RPM_ADDR, N_RPM)
    table     = read_table(buf, TABLE_ADDR, N_LOAD, N_RPM)
    result[tag] = {"load": load_axis, "rpm": rpm_axis, "table": table}
    print(f"=== ROM {tag} ===")
    print("Load axis (g/rev):", [f"{v:.2f}" for v in load_axis])
    print("RPM axis:", [f"{v:.0f}" for v in rpm_axis])
    print(f"Table shape: {len(table)} rows (RPM) x {len(table[0])} cols (Load)")
    print("Sample row[0]:", [f"{v:.2f}" for v in table[0]])
    print("Sample row[-1]:", [f"{v:.2f}" for v in table[-1]])

with open("/sessions/tender-wizardly-brown/mnt/outputs/avcs_tables.json", "w") as f:
    json.dump(result, f, indent=2)

print("\n=== DIFF (20.10 - 20.9) ===")
diffs = []
for y in range(N_RPM):
    for x in range(N_LOAD):
        d = result["20.10"]["table"][y][x] - result["20.9"]["table"][y][x]
        if abs(d) > 0.01:
            diffs.append((result["20.9"]["rpm"][y], result["20.9"]["load"][x], d))
print(f"Cells changed: {len(diffs)} / {N_RPM*N_LOAD}")
for rpm, load, d in diffs[:30]:
    print(f"  rpm={rpm:.0f}  load={load:.2f}  delta={d:+.2f}")
