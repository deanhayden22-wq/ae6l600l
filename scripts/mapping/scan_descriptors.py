#!/usr/bin/env python3
"""
AE5L600L Descriptor Scanner & Decoder
=======================================
Based on pattern analysis of known descriptors:

1D Descriptor (20 bytes):
  +0x00: 0x00 (padding)
  +0x01: axis_size (uint8, number of axis breakpoints)
  +0x02: data_type (uint8): 0x00=f32, 0x02=i8, 0x04=i16, 0x08=u8, 0x0A=u16
  +0x03: 0x00 (second dim = 0, marks this as 1D)
  +0x04: axis_ptr  (uint32, ROM addr → float32[axis_size])
  +0x08: data_ptr  (uint32, ROM addr → data[axis_size])
  +0x0C: scale     (float32, physical = raw * scale + bias)
  +0x10: bias      (float32)

2D Descriptor (28 bytes):
  +0x00: 0x00 (padding)
  +0x01: Y_size   (uint8, rows)
  +0x02: 0x00 (padding)
  +0x03: X_size   (uint8, cols)
  +0x04: Y_axis_ptr (uint32, ROM addr → float32[Y_size])
  +0x08: X_axis_ptr (uint32, ROM addr → float32[X_size])
  +0x0C: data_ptr   (uint32, ROM addr → data[Y_size * X_size])
  +0x10: data_type  (uint8, same encoding) + 3 pad bytes
  +0x14: scale      (float32)
  +0x18: bias       (float32)

Discriminator: byte[3] == 0 → 1D, byte[3] != 0 → 2D

Data types (from table_desc_1d_float jump table at 0xBE860):
  0x00 = float32 (4 bytes)
  0x02 = int8    (1 byte, sign-extended)
  0x04 = int16   (2 bytes, sign-extended)
  0x08 = uint8   (1 byte)
  0x0A = uint16  (2 bytes)
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

TYPE_NAMES = {
    0x00: "float32", 0x02: "int8", 0x04: "int16",
    0x08: "uint8", 0x0A: "uint16"
}
TYPE_SIZES = {
    0x00: 4, 0x02: 1, 0x04: 2, 0x08: 1, 0x0A: 2
}

def is_rom_ptr(val, rom_len):
    return 0x1000 <= val < rom_len

def is_valid_axis(rom, ptr, size):
    """Check if ptr points to a plausible float32 axis (monotonic or near-monotonic)."""
    if ptr + size * 4 > len(rom):
        return False
    vals = [r_f32(rom, ptr + i*4) for i in range(size)]
    # Check values are finite and reasonable
    for v in vals:
        if v != v or abs(v) > 1e8:  # NaN or extreme
            return False
    # Check roughly monotonic (allow small deviations)
    increasing = sum(1 for i in range(len(vals)-1) if vals[i+1] >= vals[i])
    decreasing = sum(1 for i in range(len(vals)-1) if vals[i+1] <= vals[i])
    return increasing >= len(vals) * 0.7 or decreasing >= len(vals) * 0.7

def try_parse_1d(rom, addr):
    """Try to parse a 1D descriptor at addr. Returns dict or None."""
    rom_len = len(rom)
    if addr + 20 > rom_len:
        return None

    b0 = rom[addr]
    size = rom[addr + 1]
    dtype = rom[addr + 2]
    b3 = rom[addr + 3]

    if b0 != 0 or b3 != 0:
        return None
    if size < 2 or size > 64:
        return None
    if dtype not in TYPE_NAMES:
        return None

    axis_ptr = r_u32(rom, addr + 4)
    data_ptr = r_u32(rom, addr + 8)
    scale = r_f32(rom, addr + 12)
    bias = r_f32(rom, addr + 16)

    if not is_rom_ptr(axis_ptr, rom_len):
        return None
    if not is_rom_ptr(data_ptr, rom_len):
        return None
    # Scale must be finite and non-zero (unless float32 type)
    if scale != scale:  # NaN
        return None
    if dtype != 0x00 and scale == 0:
        return None

    # Validate axis
    if not is_valid_axis(rom, axis_ptr, size):
        return None

    # Validate data fits in ROM
    elem_size = TYPE_SIZES[dtype]
    if data_ptr + size * elem_size > rom_len:
        return None

    return {
        "type": "1D",
        "addr": addr,
        "size": size,
        "dtype": dtype,
        "dtype_name": TYPE_NAMES[dtype],
        "axis_ptr": axis_ptr,
        "data_ptr": data_ptr,
        "scale": scale,
        "bias": bias,
        "total_bytes": 20,
    }


def try_parse_2d(rom, addr):
    """Try to parse a 2D descriptor at addr. Returns dict or None."""
    rom_len = len(rom)
    if addr + 28 > rom_len:
        return None

    b0 = rom[addr]
    rows = rom[addr + 1]
    b2 = rom[addr + 2]
    cols = rom[addr + 3]

    if b0 != 0 or b2 != 0:
        return None
    if rows < 2 or rows > 64:
        return None
    if cols < 2 or cols > 64:
        return None

    y_axis_ptr = r_u32(rom, addr + 4)
    x_axis_ptr = r_u32(rom, addr + 8)
    data_ptr = r_u32(rom, addr + 12)
    dtype = rom[addr + 16]
    scale = r_f32(rom, addr + 20)
    bias = r_f32(rom, addr + 24)

    if not is_rom_ptr(y_axis_ptr, rom_len):
        return None
    if not is_rom_ptr(x_axis_ptr, rom_len):
        return None
    if not is_rom_ptr(data_ptr, rom_len):
        return None
    if dtype not in TYPE_NAMES:
        return None
    if scale != scale:
        return None

    # Validate both axes
    if not is_valid_axis(rom, y_axis_ptr, rows):
        return None
    if not is_valid_axis(rom, x_axis_ptr, cols):
        return None

    # Validate data fits
    elem_size = TYPE_SIZES[dtype]
    if data_ptr + rows * cols * elem_size > rom_len:
        return None

    return {
        "type": "2D",
        "addr": addr,
        "rows": rows,
        "cols": cols,
        "dtype": dtype,
        "dtype_name": TYPE_NAMES[dtype],
        "y_axis_ptr": y_axis_ptr,
        "x_axis_ptr": x_axis_ptr,
        "data_ptr": data_ptr,
        "scale": scale,
        "bias": bias,
        "total_bytes": 28,
    }


def read_axis(rom, ptr, size):
    """Read float32 axis values."""
    return [r_f32(rom, ptr + i*4) for i in range(size)]


def read_data_1d(rom, ptr, size, dtype):
    """Read 1D data array."""
    elem_size = TYPE_SIZES[dtype]
    values = []
    for i in range(size):
        a = ptr + i * elem_size
        if dtype == 0x00:
            values.append(r_f32(rom, a))
        elif dtype == 0x02:
            v = rom[a]
            values.append(v - 256 if v > 127 else v)
        elif dtype == 0x04:
            v = r_u16(rom, a)
            values.append(v - 65536 if v > 32767 else v)
        elif dtype == 0x08:
            values.append(rom[a])
        elif dtype == 0x0A:
            values.append(r_u16(rom, a))
    return values


def main():
    rom = load_rom()
    rom_len = len(rom)
    print(f"Loaded ROM: {rom_len} bytes")

    # Scan the descriptor region (0xAC000-0xB0000 based on known descriptors)
    # Also scan calibration region (0xC0000-0xD8000)
    # And the broader ROM for any descriptors
    SCAN_REGIONS = [
        (0x0A0000, 0x0B2000, "Descriptor region A"),
        (0x0B2000, 0x0BE000, "Descriptor region B"),
    ]

    all_descs = []

    for start, end, region_name in SCAN_REGIONS:
        print(f"\nScanning {region_name} (0x{start:06X}-0x{end:06X})...")
        addr = start
        while addr < end:
            # Try 2D first (it's more specific)
            d = try_parse_2d(rom, addr)
            if d:
                all_descs.append(d)
                addr += d["total_bytes"]
                continue

            # Try 1D
            d = try_parse_1d(rom, addr)
            if d:
                all_descs.append(d)
                addr += d["total_bytes"]
                continue

            addr += 2  # Advance by 2 bytes (aligned)

    print(f"\n{'='*90}")
    print(f"DESCRIPTOR SCAN RESULTS: {len(all_descs)} descriptors found")
    print(f"{'='*90}")

    # Stats
    d1_count = sum(1 for d in all_descs if d["type"] == "1D")
    d2_count = sum(1 for d in all_descs if d["type"] == "2D")
    print(f"  1D: {d1_count}   2D: {d2_count}")

    # Type distribution
    type_dist = defaultdict(int)
    for d in all_descs:
        type_dist[d["dtype_name"]] += 1
    print(f"  Data types: {dict(type_dist)}")

    # Print all descriptors
    print(f"\n{'='*90}")
    print(f"{'#':>4} {'Addr':>10} {'Dim':>4} {'Size':>8} {'Type':>8} "
          f"{'Scale':>12} {'Bias':>10} {'AxisPtr':>10} {'DataPtr':>10}")
    print(f"{'='*90}")

    for i, d in enumerate(all_descs):
        if d["type"] == "1D":
            size_str = str(d["size"])
            axis_str = f"0x{d['axis_ptr']:06X}"
            data_str = f"0x{d['data_ptr']:06X}"
            # Show axis range
            axis = read_axis(rom, d["axis_ptr"], d["size"])
            axis_range = f"[{axis[0]:.1f}..{axis[-1]:.1f}]"
        else:
            size_str = f"{d['rows']}x{d['cols']}"
            axis_str = f"Y:0x{d['y_axis_ptr']:06X}"
            data_str = f"0x{d['data_ptr']:06X}"
            y_axis = read_axis(rom, d["y_axis_ptr"], d["rows"])
            x_axis = read_axis(rom, d["x_axis_ptr"], d["cols"])
            axis_range = f"Y[{y_axis[0]:.1f}..{y_axis[-1]:.1f}] X[{x_axis[0]:.1f}..{x_axis[-1]:.1f}]"

        print(f"{i:>4} 0x{d['addr']:06X} {d['type']:>4} {size_str:>8} "
              f"{d['dtype_name']:>8} {d['scale']:>12.6f} {d['bias']:>10.3f} "
              f"{axis_str:>10} {data_str:>10}  {axis_range}")

    # Print data samples for first 20
    print(f"\n{'='*90}")
    print(f"DATA SAMPLES (first 30 descriptors)")
    print(f"{'='*90}")
    for i, d in enumerate(all_descs[:30]):
        if d["type"] == "1D":
            raw = read_data_1d(rom, d["data_ptr"], min(d["size"], 8), d["dtype"])
            physical = [v * d["scale"] + d["bias"] for v in raw]
            axis = read_axis(rom, d["axis_ptr"], min(d["size"], 8))
            print(f"\n  #{i} 0x{d['addr']:06X} 1D {d['dtype_name']} [{d['size']}] "
                  f"scale={d['scale']:.6f} bias={d['bias']:.3f}")
            print(f"    Axis: {[f'{v:.1f}' for v in axis]}")
            print(f"    Raw:  {raw}")
            print(f"    Phys: {[f'{v:.4f}' for v in physical]}")
        else:
            y_axis = read_axis(rom, d["y_axis_ptr"], min(d["rows"], 4))
            x_axis = read_axis(rom, d["x_axis_ptr"], min(d["cols"], 4))
            print(f"\n  #{i} 0x{d['addr']:06X} 2D {d['dtype_name']} [{d['rows']}x{d['cols']}] "
                  f"scale={d['scale']:.6f} bias={d['bias']:.3f}")
            print(f"    Y-Axis: {[f'{v:.1f}' for v in y_axis]}{'...' if d['rows'] > 4 else ''}")
            print(f"    X-Axis: {[f'{v:.1f}' for v in x_axis]}{'...' if d['cols'] > 4 else ''}")
            # First row
            first_row = read_data_1d(rom, d["data_ptr"], min(d["cols"], 6), d["dtype"])
            phys_row = [v * d["scale"] + d["bias"] for v in first_row]
            print(f"    Row 0:  {first_row} -> {[f'{v:.4f}' for v in phys_row]}")


if __name__ == "__main__":
    main()
