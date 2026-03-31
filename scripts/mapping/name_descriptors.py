#!/usr/bin/env python3
"""
Auto-name calibration descriptors by axis fingerprinting.

Known axis fingerprints for Subaru WRX:
  ECT:        -40..110 or -40..120 (degF coolant temperature)
  IAT:        -30..55 or -40..60 (degF intake air temperature)
  RPM:        400..7500 (engine speed, various subranges)
  Load:       0.1..3.0 or 0.2..2.5 (g/rev engine load)
  MAF:        0..300 or 0..500 (g/s mass airflow)
  Throttle:   0..100 or 0..200 (throttle %)
  Boost:      0..25 or similar (psi boost pressure)
  VehicleSpd: 0..200 or 0..255 (km/h)
  Voltage:    8..16 (battery voltage)
  Lambda:     0.5..1.5 (air-fuel ratio)
  IPW:        0..10 (injector pulse width ms)
  TimingAdv:  -20..60 (timing advance degrees)
  VVTError:   -12..12 (AVCS VVT error degrees)
  KnockIdx:   0..100 or 0..15 (knock indices)
  Gear:       1..6 (transmission gear)
"""
import os
import struct
import sys
from collections import defaultdict

ROM_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rom")

def load_rom():
    p = os.path.join(ROM_DIR, "ae5l600l.bin")
    if os.path.isfile(p):
        with open(p, "rb") as f:
            return f.read()
    for fn in sorted(os.listdir(ROM_DIR)):
        if fn.lower().endswith(".bin"):
            with open(os.path.join(ROM_DIR, fn), "rb") as f:
                return f.read()
    sys.exit("No ROM found")

def r_u8(rom, a): return rom[a]
def r_u16(rom, a): return struct.unpack_from(">H", rom, a)[0]
def r_u32(rom, a): return struct.unpack_from(">I", rom, a)[0]
def r_f32(rom, a): return struct.unpack_from(">f", rom, a)[0]

TYPE_NAMES = {0x00: "f32", 0x02: "i8", 0x04: "i16", 0x08: "u8", 0x0A: "u16"}
TYPE_SIZES = {0x00: 4, 0x02: 1, 0x04: 2, 0x08: 1, 0x0A: 2}


def read_axis(rom, ptr, size):
    return [r_f32(rom, ptr + i*4) for i in range(size)]


def classify_axis(vals):
    """Classify an axis by its value range."""
    if not vals or len(vals) < 2:
        return "unknown"
    lo, hi = vals[0], vals[-1]
    span = hi - lo

    # ECT: starts around -40, ends around 100-120
    if -50 <= lo <= -20 and 80 <= hi <= 130:
        return "ECT"
    # IAT: starts around -30 to -40, ends around 40-80
    if -50 <= lo <= -20 and 30 <= hi <= 80 and span < 120:
        return "IAT"
    # RPM: values in hundreds to thousands
    if 200 <= lo <= 1000 and 3000 <= hi <= 8000:
        return "RPM"
    if 0 <= lo <= 100 and 5000 <= hi <= 15000:
        return "RPM_wide"
    if 1000 <= lo <= 2000 and 4000 <= hi <= 8000:
        return "RPM_mid"
    # Engine Load: small fractional values
    if 0 <= lo <= 0.5 and 1.5 <= hi <= 4.0:
        return "Load"
    if 0 <= lo <= 1 and 0.5 <= hi <= 3:
        return "Load"
    # Throttle position
    if 0 <= lo <= 5 and 80 <= hi <= 200 and span < 250:
        return "Throttle"
    # Vehicle speed
    if 0 <= lo <= 10 and 150 <= hi <= 300 and span < 350:
        return "VehSpd"
    # Boost / manifold pressure
    if 0 <= lo <= 5 and 15 <= hi <= 50 and span < 60:
        return "Boost"
    # Voltage
    if 6 <= lo <= 10 and 14 <= hi <= 18 and span < 15:
        return "Voltage"
    # Lambda / AF ratio
    if 0.5 <= lo <= 0.8 and 1.0 <= hi <= 1.5 and span < 1.5:
        return "Lambda"
    # Timing advance
    if -30 <= lo <= 0 and 40 <= hi <= 80:
        return "TimingAdv"
    # VVT error (AVCS)
    if -15 <= lo <= -5 and 5 <= hi <= 15 and span < 30:
        return "VVTError"
    # IPW (injector pulse width)
    if 0 <= lo <= 1 and 3 <= hi <= 12 and span < 15:
        return "IPW"
    # Gear (1-6 integers)
    if 0.5 <= lo <= 1.5 and 4.5 <= hi <= 6.5 and len(vals) <= 7:
        return "Gear"
    # Knock/correction indices
    if 0 <= lo <= 2 and 10 <= hi <= 100 and span < 150:
        return "KnockIdx"
    # Atmospheric pressure
    if 200 <= lo <= 500 and 700 <= hi <= 900 and span < 600:
        return "AtmPressure"
    # Small integers (counters, indices)
    if 0 <= lo <= 5 and 5 <= hi <= 30 and all(v == int(v) for v in vals):
        return "Counter"
    # Temperature range (general)
    if -50 <= lo <= 0 and 50 <= hi <= 200:
        return "Temp"
    # Pressure (general kPa)
    if 0 <= lo <= 100 and 100 <= hi <= 500:
        return "Pressure"
    # Ratio (0..1 or 0..2)
    if -0.1 <= lo <= 0.5 and 0.5 <= hi <= 2.5 and span < 3:
        return "Ratio"
    # Angle
    if -2 <= lo <= 0 and 0.5 <= hi <= 2:
        return "SmallRatio"
    # Mass (MAF g/s)
    if 0 <= lo <= 10 and 200 <= hi <= 600:
        return "MAF"
    # Degrees (timing or cam angle)
    if -100 <= lo <= -10 and 50 <= hi <= 250:
        return "Degrees"

    return f"range[{lo:.0f}..{hi:.0f}]"


def is_valid_axis(rom, ptr, size):
    if ptr + size * 4 > len(rom):
        return False
    vals = [r_f32(rom, ptr + i*4) for i in range(size)]
    for v in vals:
        if v != v or abs(v) > 1e8:
            return False
    increasing = sum(1 for i in range(len(vals)-1) if vals[i+1] >= vals[i])
    return increasing >= len(vals) * 0.7


def scan_descriptors(rom):
    """Scan descriptor region for all valid descriptors."""
    rom_len = len(rom)
    descs = []

    for start, end in [(0xA0000, 0xB2000)]:
        addr = start
        while addr < end:
            # Try 2D
            if addr + 28 <= rom_len:
                b0, rows, b2, cols = rom[addr], rom[addr+1], rom[addr+2], rom[addr+3]
                if b0 == 0 and b2 == 0 and 2 <= rows <= 64 and 2 <= cols <= 64:
                    yptr = r_u32(rom, addr+4)
                    xptr = r_u32(rom, addr+8)
                    dptr = r_u32(rom, addr+12)
                    dtype = rom[addr+16]
                    if (dtype in TYPE_NAMES and
                        0x1000 <= yptr < rom_len and 0x1000 <= xptr < rom_len and
                        0x1000 <= dptr < rom_len):
                        if is_valid_axis(rom, yptr, rows) and is_valid_axis(rom, xptr, cols):
                            scale = r_f32(rom, addr+20)
                            bias = r_f32(rom, addr+24)
                            if scale == scale:  # not NaN
                                y_axis = read_axis(rom, yptr, rows)
                                x_axis = read_axis(rom, xptr, cols)
                                descs.append({
                                    'addr': addr, 'type': '2D',
                                    'rows': rows, 'cols': cols,
                                    'dtype': dtype, 'scale': scale, 'bias': bias,
                                    'y_axis': y_axis, 'x_axis': x_axis,
                                    'data_ptr': dptr,
                                })
                                addr += 28
                                continue

            # Try 1D
            if addr + 20 <= rom_len:
                b0, size, dtype, b3 = rom[addr], rom[addr+1], rom[addr+2], rom[addr+3]
                if b0 == 0 and b3 == 0 and 2 <= size <= 64 and dtype in TYPE_NAMES:
                    aptr = r_u32(rom, addr+4)
                    dptr = r_u32(rom, addr+8)
                    if 0x1000 <= aptr < rom_len and 0x1000 <= dptr < rom_len:
                        if is_valid_axis(rom, aptr, size):
                            scale = r_f32(rom, addr+12)
                            bias = r_f32(rom, addr+16)
                            if scale == scale:
                                axis = read_axis(rom, aptr, size)
                                descs.append({
                                    'addr': addr, 'type': '1D',
                                    'size': size, 'dtype': dtype,
                                    'scale': scale, 'bias': bias,
                                    'axis': axis, 'data_ptr': dptr,
                                })
                                addr += 20
                                continue

            addr += 2

    return descs


def name_descriptor(desc):
    """Generate a semantic name for a descriptor based on its axes."""
    dtype_str = TYPE_NAMES.get(desc['dtype'], '??')

    if desc['type'] == '1D':
        axis_type = classify_axis(desc['axis'])
        size = desc['size']
        return f"1D_{axis_type}_{dtype_str}_{size}"
    else:
        y_type = classify_axis(desc['y_axis'])
        x_type = classify_axis(desc['x_axis'])
        rows, cols = desc['rows'], desc['cols']
        return f"2D_{y_type}x{x_type}_{dtype_str}_{rows}x{cols}"


def main():
    rom = load_rom()
    print(f"Loaded ROM: {len(rom)} bytes\n")

    descs = scan_descriptors(rom)
    print(f"Found {len(descs)} descriptors\n")

    # Name each descriptor
    named = []
    for d in descs:
        name = name_descriptor(d)
        d['name'] = name
        named.append(d)

    # Axis type statistics
    if True:
        axis_types_1d = defaultdict(int)
        axis_types_2d_y = defaultdict(int)
        axis_types_2d_x = defaultdict(int)
        for d in named:
            if d['type'] == '1D':
                axis_types_1d[classify_axis(d['axis'])] += 1
            else:
                axis_types_2d_y[classify_axis(d['y_axis'])] += 1
                axis_types_2d_x[classify_axis(d['x_axis'])] += 1

        print("1D Axis Types:")
        for t, c in sorted(axis_types_1d.items(), key=lambda x: -x[1]):
            print(f"  {t:<20} {c:>4}")

        print("\n2D Y-Axis Types:")
        for t, c in sorted(axis_types_2d_y.items(), key=lambda x: -x[1]):
            print(f"  {t:<20} {c:>4}")

        print("\n2D X-Axis Types:")
        for t, c in sorted(axis_types_2d_x.items(), key=lambda x: -x[1]):
            print(f"  {t:<20} {c:>4}")

    # Output named descriptor table
    print(f"\n{'='*110}")
    print(f"NAMED DESCRIPTOR MAP")
    print(f"{'='*110}")
    print(f"{'#':>4} {'Addr':>10} {'Name':<45} {'Scale':>10} {'Bias':>8} {'DataPtr':>10}")
    print(f"{'-'*110}")

    for i, d in enumerate(named):
        scale_str = f"{d['scale']:.6f}" if d['scale'] != 0 else "0"
        bias_str = f"{d['bias']:.1f}" if d['bias'] != 0 else "0"
        print(f"{i:>4} 0x{d['addr']:06X} {d['name']:<45} {scale_str:>10} {bias_str:>8} 0x{d['data_ptr']:06X}")

    # Summary by name pattern
    print(f"\n{'='*80}")
    print(f"DESCRIPTOR NAME PATTERNS (grouped)")
    print(f"{'='*80}")

    name_groups = defaultdict(list)
    for d in named:
        # Group by axis types only (strip size)
        if d['type'] == '1D':
            key = f"1D_{classify_axis(d['axis'])}"
        else:
            key = f"2D_{classify_axis(d['y_axis'])}x{classify_axis(d['x_axis'])}"
        name_groups[key].append(d)

    for key in sorted(name_groups.keys(), key=lambda k: -len(name_groups[k])):
        descs_in_group = name_groups[key]
        addrs = [f"0x{d['addr']:05X}" for d in descs_in_group[:5]]
        more = f" (+{len(descs_in_group)-5})" if len(descs_in_group) > 5 else ""
        print(f"  {key:<35} {len(descs_in_group):>4} tables  {', '.join(addrs)}{more}")


if __name__ == "__main__":
    main()
