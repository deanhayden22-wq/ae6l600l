#!/usr/bin/env python3
"""Compare ROM tables between Rev 19, Rev 20.1, and Rev 20.2"""

import struct
import sys

# ROM files
ROMS = {
    "Rev 19":  "AE5L600L 20g AI rev 19 RA gears.bin",
    "Rev 20.1": "AE5L600L 20g rev 20.1 tiny wrex.bin",
    "Rev 20.2": "AE5L600L 20g rev 20.2 tiny wrex.bin",
}

def read_rom(path):
    with open(path, "rb") as f:
        return f.read()

def read_float_be(data, addr):
    return struct.unpack(">f", data[addr:addr+4])[0]

def read_uint16_be(data, addr):
    return struct.unpack(">H", data[addr:addr+2])[0]

def read_uint8(data, addr):
    return data[addr]

def read_float_array(data, addr, count):
    return [read_float_be(data, addr + i*4) for i in range(count)]

def read_uint16_array(data, addr, count):
    return [read_uint16_be(data, addr + i*2) for i in range(count)]

def read_uint8_array(data, addr, count):
    return [read_uint8(data, addr + i) for i in range(count)]

# ---- Scaling functions ----
def scale_boost(raw):
    return (raw - 760) * 0.01933677

def scale_wgdc(raw):
    return raw * 0.00390625

def scale_timing(raw):
    return raw * 0.3515625 - 20

def scale_avcs(raw):
    return raw * 0.0054931640625

def scale_req_torque(raw):
    return raw  # raw ECU value

# ---- Table definitions ----
TABLES = {
    "MAF Sensor Scaling": {
        "addr": 0xd8c9c,
        "axis_addr": 0xd8bc4,
        "count": 54,
        "type": "float",
        "axis_type": "float",
        "scale": lambda x: x,
        "axis_scale": lambda x: x,
        "unit": "g/s",
        "axis_unit": "V",
    },
    "Target Boost": {
        "addr": 0xc1340,
        "x_axis_addr": 0xc12d8,  # Requested Torque (11)
        "y_axis_addr": 0xc1304,  # Engine Speed (15)
        "x_count": 11,
        "y_count": 15,
        "type": "uint16",
        "scale": scale_boost,
        "unit": "psi",
        "3d": True,
    },
    "Initial Wastegate Duty": {
        "addr": 0xc1150,
        "x_axis_addr": 0xc10e0,  # Requested Torque (15)
        "y_axis_addr": 0xc111c,  # Engine Speed (13)
        "x_count": 15,
        "y_count": 13,
        "type": "uint16",
        "scale": scale_wgdc,
        "unit": "%",
        "3d": True,
    },
    "Max Wastegate Duty": {
        "addr": 0xc0f58,
        "x_axis_addr": 0xc0ee8,  # Requested Torque (15)
        "y_axis_addr": 0xc0f24,  # Engine Speed (13)
        "x_count": 15,
        "y_count": 13,
        "type": "uint16",
        "scale": scale_wgdc,
        "unit": "%",
        "3d": True,
    },
    "Base Timing Non-Cruise": {
        "addr": 0xd4c54,
        "x_axis_addr": 0xd4bc8,  # Engine Load (17)
        "y_axis_addr": 0xd4c0c,  # Engine Speed
        "x_count": 17,
        "y_count": 16,  # typical
        "type": "uint8",
        "scale": scale_timing,
        "unit": "deg BTDC",
        "3d": True,
    },
    "Base Timing Cruise": {
        "addr": 0xd4a94,
        "x_axis_addr": 0xd4a08,  # Engine Load (17)
        "y_axis_addr": 0xd4a4c,  # Engine Speed
        "x_count": 17,
        "y_count": 16,
        "type": "uint8",
        "scale": scale_timing,
        "unit": "deg BTDC",
        "3d": True,
    },
    "Intake Cam Advance Non-Cruise (AVCS)": {
        "addr": 0xdac34,
        "x_axis_addr": 0xdabac,  # Engine Load (18)
        "y_axis_addr": 0xdabf4,  # Engine Speed (16)
        "x_count": 18,
        "y_count": 16,
        "type": "uint16",
        "scale": scale_avcs,
        "unit": "deg",
        "3d": True,
    },
    "Intake Cam Advance Cruise (AVCS)": {
        "addr": 0xda96c,
        "x_axis_addr": 0xda8e4,  # Engine Load (18)
        "y_axis_addr": 0xda92c,  # Engine Speed (16)
        "x_count": 18,
        "y_count": 16,
        "type": "uint16",
        "scale": scale_avcs,
        "unit": "deg",
        "3d": True,
    },
    "Primary Open Loop Fueling": {
        "addr": 0xd0244,
        "x_axis_addr": 0xd01b8,  # Engine Load (17)
        "y_axis_addr": 0xd01fc,  # Engine Speed (18)
        "x_count": 17,
        "y_count": 18,
        "type": "float",
        "scale": lambda x: x,
        "unit": "AFR",
        "3d": True,
    },
    "Injector Flow Scaling": {
        "addr": 0xcbe0c,
        "count": 1,
        "type": "float",
        "scale": lambda x: x,
        "unit": "cc/min",
    },
    "Turbo Dynamics Proportional": {
        "addr": 0xc0d28,
        "axis_addr": 0xc0d04,
        "count": 9,
        "type": "uint16",
        "axis_type": "uint16",
        "scale": lambda x: x * 0.00390625 - 50,
        "axis_scale": scale_boost,
        "unit": "%",
        "axis_unit": "psi error",
    },
    "Requested Torque Limit A": {
        "addr": 0xf9788,
        "x_axis_addr": 0xf9730,  # Engine Speed (16)
        "y_axis_addr": 0xf9770,  # Gear (6)
        "x_count": 16,
        "y_count": 6,
        "type": "uint16",
        "scale": scale_req_torque,
        "unit": "raw",
        "3d": True,
    },
    "Requested Torque Limit B": {
        "addr": 0xf98a0,
        "x_axis_addr": 0xf9848,
        "y_axis_addr": 0xf9888,
        "x_count": 16,
        "y_count": 6,
        "type": "uint16",
        "scale": scale_req_torque,
        "unit": "raw",
        "3d": True,
    },
}

def extract_1d(data, table):
    count = table["count"]
    addr = table["addr"]
    scale = table["scale"]

    if table["type"] == "float":
        raw = read_float_array(data, addr, count)
    elif table["type"] == "uint16":
        raw = read_uint16_array(data, addr, count)
    elif table["type"] == "uint8":
        raw = read_uint8_array(data, addr, count)

    return [scale(v) for v in raw]

def extract_axis(data, addr, count, dtype="float"):
    if dtype == "float":
        return read_float_array(data, addr, count)
    elif dtype == "uint16":
        return read_uint16_array(data, addr, count)
    elif dtype == "uint8":
        return read_uint8_array(data, addr, count)

def extract_3d(data, table):
    x_count = table["x_count"]
    y_count = table["y_count"]
    addr = table["addr"]
    scale = table["scale"]

    values = []
    for row in range(y_count):
        row_vals = []
        for col in range(x_count):
            if table["type"] == "float":
                offset = (row * x_count + col) * 4
                raw = read_float_be(data, addr + offset)
            elif table["type"] == "uint16":
                offset = (row * x_count + col) * 2
                raw = read_uint16_be(data, addr + offset)
            elif table["type"] == "uint8":
                offset = row * x_count + col
                raw = read_uint8(data, addr + offset)
            row_vals.append(scale(raw))
        values.append(row_vals)
    return values

def compare_and_print():
    roms = {}
    for name, path in ROMS.items():
        roms[name] = read_rom(path)

    rom_names = list(ROMS.keys())

    for tname, tdef in TABLES.items():
        is_3d = tdef.get("3d", False)

        if is_3d:
            all_vals = {}
            for rname in rom_names:
                all_vals[rname] = extract_3d(roms[rname], tdef)

            # Check if any differences exist
            has_diff = False
            for rname in rom_names[1:]:
                for r in range(len(all_vals[rom_names[0]])):
                    for c in range(len(all_vals[rom_names[0]][r])):
                        if abs(all_vals[rom_names[0]][r][c] - all_vals[rname][r][c]) > 0.001:
                            has_diff = True
                            break
                    if has_diff:
                        break
                if has_diff:
                    break

            if not has_diff:
                print(f"\n{'='*80}")
                print(f"  {tname} ({tdef['unit']}) — NO CHANGES across all revisions")
                print(f"{'='*80}")
                continue

            print(f"\n{'='*80}")
            print(f"  {tname} ({tdef['unit']}) — *** CHANGES DETECTED ***")
            print(f"{'='*80}")

            # Get axes
            x_axis = extract_axis(roms[rom_names[0]], tdef["x_axis_addr"], tdef["x_count"], "float")
            y_axis = extract_axis(roms[rom_names[0]], tdef["y_axis_addr"], tdef["y_count"], "float")

            # Print differences only
            for r in range(len(all_vals[rom_names[0]])):
                for c in range(len(all_vals[rom_names[0]][r])):
                    vals = [all_vals[rn][r][c] for rn in rom_names]
                    if any(abs(vals[0] - v) > 0.001 for v in vals[1:]):
                        y_label = f"{y_axis[r]:.0f}" if r < len(y_axis) else f"r{r}"
                        x_label = f"{x_axis[c]:.2f}" if c < len(x_axis) else f"c{c}"
                        val_str = " | ".join(f"{rn}: {v:.2f}" for rn, v in zip(rom_names, vals))
                        print(f"  Y={y_label}, X={x_label}: {val_str}")

        else:
            all_vals = {}
            for rname in rom_names:
                all_vals[rname] = extract_1d(roms[rname], tdef)

            has_diff = False
            for rname in rom_names[1:]:
                for i in range(len(all_vals[rom_names[0]])):
                    if abs(all_vals[rom_names[0]][i] - all_vals[rname][i]) > 0.001:
                        has_diff = True
                        break
                if has_diff:
                    break

            if not has_diff:
                print(f"\n{'='*80}")
                print(f"  {tname} ({tdef['unit']}) — NO CHANGES across all revisions")
                print(f"{'='*80}")
                continue

            print(f"\n{'='*80}")
            print(f"  {tname} ({tdef['unit']}) — *** CHANGES DETECTED ***")
            print(f"{'='*80}")

            # Get axis if available
            axis = None
            if "axis_addr" in tdef:
                atype = tdef.get("axis_type", "float")
                axis = extract_axis(roms[rom_names[0]], tdef["axis_addr"], tdef["count"], atype)

            for i in range(len(all_vals[rom_names[0]])):
                vals = [all_vals[rn][i] for rn in rom_names]
                if any(abs(vals[0] - v) > 0.001 for v in vals[1:]):
                    if axis is not None:
                        a_scale = tdef.get("axis_scale", lambda x: x)
                        label = f"{a_scale(axis[i]):.2f}"
                    else:
                        label = f"[{i}]"
                    val_str = " | ".join(f"{rn}: {v:.4f}" for rn, v in zip(rom_names, vals))
                    print(f"  {label}: {val_str}")

if __name__ == "__main__":
    compare_and_print()
