#!/usr/bin/env python3
"""Decode ignition timing descriptor tables from the AE5L600L ECU ROM."""
import struct
import sys
import os

# Force UTF-8 stdout
sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', errors='replace', buffering=1)

ROM_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        'rom', 'ae5l600l.bin')
OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           'disassembly', 'analysis', 'ignition_timing_descriptors.txt')

with open(ROM_PATH, 'rb') as f:
    rom = f.read()

ROM_SIZE = len(rom)


def read_u8(addr):
    return rom[addr]

def read_u16(addr):
    return struct.unpack_from('>H', rom, addr)[0]

def read_i16(addr):
    return struct.unpack_from('>h', rom, addr)[0]

def read_u32(addr):
    return struct.unpack_from('>I', rom, addr)[0]

def read_f32(addr):
    return struct.unpack_from('>f', rom, addr)[0]


def decode_descriptor(addr):
    """Decode a table descriptor at the given ROM address.

    Format (16 bytes):
      +0: u16  count (X axis size for 1D; X axis size for 2D)
      +2: u8   interp_type (0x00=float, 0x04=u8+scale, 0x08=u16+scale)
      +3: u8   y_count (0 for 1D tables, >0 for 2D tables)
      +4: u32  pointer 1 (axis for 1D; X-axis for 2D)
      +8: u32  pointer 2 (data for 1D; Y-axis for 2D)
     +12: u32/f32  scale (1D) or data pointer (2D)
    """
    x_count = read_u16(addr)
    interp_type = read_u8(addr + 2)
    y_count = read_u8(addr + 3)

    p1 = read_u32(addr + 4)
    p2 = read_u32(addr + 8)
    last4_raw = rom[addr + 12:addr + 16]
    last4_u32 = read_u32(addr + 12)
    last4_f32 = read_f32(addr + 12)

    is_2d = (interp_type == 0x00 and y_count > 0)
    is_1d_float = (interp_type == 0x00 and y_count == 0)

    desc = {
        'addr': addr,
        'x_count': x_count,
        'interp_type': interp_type,
        'y_count': y_count,
        'p1': p1,
        'p2': p2,
        'last4_u32': last4_u32,
        'last4_f32': last4_f32,
        'raw_hex': rom[addr:addr+16].hex(),
    }

    if is_2d:
        desc['type'] = '2D'
        desc['x_axis_ptr'] = p1
        desc['y_axis_ptr'] = p2
        desc['data_ptr'] = last4_u32
    elif is_1d_float:
        desc['type'] = '1D_float'
        desc['axis_ptr'] = p1
        desc['data_ptr'] = p2
        desc['scale'] = None  # no scale needed for float
    else:
        # 1D with scale: type 0x04 (u8 data) or 0x08 (u16 data)
        desc['type'] = '1D_scaled'
        desc['axis_ptr'] = p1
        desc['data_ptr'] = p2
        desc['scale'] = last4_f32

    return desc


def read_float_array(ptr, count):
    vals = []
    for i in range(count):
        vals.append(read_f32(ptr + i * 4))
    return vals


def read_data(desc):
    """Read table data values based on descriptor type."""
    if desc['type'] == '2D':
        x_axis = read_float_array(desc['x_axis_ptr'], desc['x_count'])
        y_axis = read_float_array(desc['y_axis_ptr'], desc['y_count'])
        data = []
        dp = desc['data_ptr']
        for y in range(desc['y_count']):
            row = []
            for x in range(desc['x_count']):
                row.append(read_f32(dp + (y * desc['x_count'] + x) * 4))
            data.append(row)
        return x_axis, y_axis, data

    elif desc['type'] == '1D_float':
        axis = read_float_array(desc['axis_ptr'], desc['x_count'])
        data = read_float_array(desc['data_ptr'], desc['x_count'])
        return axis, data

    elif desc['type'] == '1D_scaled':
        axis = read_float_array(desc['axis_ptr'], desc['x_count'])
        scale = desc['scale']
        dp = desc['data_ptr']
        if desc['interp_type'] == 0x04:
            # u8 data
            raw = [read_u8(dp + i) for i in range(desc['x_count'])]
            scaled = [v * scale for v in raw]
            return axis, raw, scaled
        elif desc['interp_type'] == 0x08:
            # u16 data
            raw = [read_u16(dp + i * 2) for i in range(desc['x_count'])]
            scaled = [v * scale for v in raw]
            return axis, raw, scaled
        else:
            raw = [read_u8(dp + i) for i in range(desc['x_count'])]
            return axis, raw, raw

    return None


def format_float(v):
    """Format a float nicely for display."""
    if v == int(v) and abs(v) < 100000:
        return f'{int(v)}'
    elif abs(v) < 0.001 and v != 0:
        return f'{v:.6f}'
    elif abs(v) < 1:
        return f'{v:.4f}'
    elif abs(v) < 100:
        return f'{v:.2f}'
    elif abs(v) < 10000:
        return f'{v:.1f}'
    else:
        return f'{v:.0f}'


def print_descriptor(desc, out):
    """Print a decoded descriptor to the output."""
    addr = desc['addr']
    out.write(f'  Descriptor @ 0x{addr:05X}\n')
    out.write(f'    Raw: {desc["raw_hex"]}\n')
    out.write(f'    X count: {desc["x_count"]}\n')
    out.write(f'    Interp type: 0x{desc["interp_type"]:02X}')
    if desc['interp_type'] == 0x00:
        out.write(' (float)')
    elif desc['interp_type'] == 0x04:
        out.write(' (u8 + scale)')
    elif desc['interp_type'] == 0x08:
        out.write(' (u16 + scale)')
    out.write('\n')
    out.write(f'    Y count: {desc["y_count"]}\n')
    out.write(f'    Table type: {desc["type"]}\n')

    if desc['type'] == '2D':
        out.write(f'    X-axis ptr: 0x{desc["x_axis_ptr"]:06X}\n')
        out.write(f'    Y-axis ptr: 0x{desc["y_axis_ptr"]:06X}\n')
        out.write(f'    Data ptr:   0x{desc["data_ptr"]:06X}\n')
        out.write(f'    Dimensions: {desc["x_count"]}x{desc["y_count"]} = {desc["x_count"]*desc["y_count"]} cells\n')
    elif desc['type'] == '1D_float':
        out.write(f'    Axis ptr: 0x{desc["axis_ptr"]:06X}\n')
        out.write(f'    Data ptr: 0x{desc["data_ptr"]:06X}\n')
    else:
        out.write(f'    Axis ptr: 0x{desc["axis_ptr"]:06X}\n')
        out.write(f'    Data ptr: 0x{desc["data_ptr"]:06X}\n')
        out.write(f'    Scale:    {desc["scale"]}\n')

    out.write('\n')

    result = read_data(desc)
    if result is None:
        out.write('    [Could not decode data]\n\n')
        return

    if desc['type'] == '2D':
        x_axis, y_axis, data = result
        xcnt = desc['x_count']
        ycnt = desc['y_count']

        if xcnt > 20 and ycnt > 20:
            out.write(f'    [Table too large to display: {xcnt}x{ycnt}]\n')
            out.write(f'    X-axis range: {format_float(x_axis[0])} .. {format_float(x_axis[-1])}\n')
            out.write(f'    Y-axis range: {format_float(y_axis[0])} .. {format_float(y_axis[-1])}\n')
            # Show corners
            out.write(f'    Corner values: [{format_float(data[0][0])}, {format_float(data[0][-1])}, {format_float(data[-1][0])}, {format_float(data[-1][-1])}]\n\n')
            return

        # Determine column widths
        col_width = 8
        # Format header
        x_strs = [format_float(v) for v in x_axis]
        y_strs = [format_float(v) for v in y_axis]
        max_y_width = max(len(s) for s in y_strs) if y_strs else 4

        # Adjust col width
        all_data_strs = []
        for row in data:
            row_strs = [format_float(v) for v in row]
            all_data_strs.append(row_strs)
        max_data_w = 0
        for row_strs in all_data_strs:
            for s in row_strs:
                if len(s) > max_data_w:
                    max_data_w = len(s)
        for s in x_strs:
            if len(s) > max_data_w:
                max_data_w = len(s)
        col_width = max(max_data_w + 1, 6)

        # Print header row
        out.write('    ' + ' ' * max_y_width + ' |')
        for xs in x_strs:
            out.write(xs.rjust(col_width))
        out.write('\n')
        out.write('    ' + '-' * max_y_width + '-+' + '-' * (col_width * xcnt) + '\n')

        # Print data rows
        for yi, (ys, row_strs) in enumerate(zip(y_strs, all_data_strs)):
            out.write('    ' + ys.rjust(max_y_width) + ' |')
            for ds in row_strs:
                out.write(ds.rjust(col_width))
            out.write('\n')
        out.write('\n')

    elif desc['type'] == '1D_float':
        axis, data = result
        out.write('    Axis       | Value\n')
        out.write('    -----------+-----------\n')
        for a, d in zip(axis, data):
            out.write(f'    {format_float(a):>10s} | {format_float(d)}\n')
        out.write('\n')

    elif desc['type'] == '1D_scaled':
        if desc['interp_type'] == 0x04:
            axis, raw, scaled = result
            out.write('    Axis       | Raw(u8) | Scaled\n')
            out.write('    -----------+---------+-----------\n')
            for a, r, s in zip(axis, raw, scaled):
                out.write(f'    {format_float(a):>10s} | {r:7d} | {format_float(s)}\n')
        elif desc['interp_type'] == 0x08:
            axis, raw, scaled = result
            out.write('    Axis       | Raw(u16)| Scaled\n')
            out.write('    -----------+---------+-----------\n')
            for a, r, s in zip(axis, raw, scaled):
                out.write(f'    {format_float(a):>10s} | {r:7d} | {format_float(s)}\n')
        out.write('\n')


# ============================================================================
# Define all descriptor groups
# ============================================================================

descriptor_groups = [
    ('task49_base_advance', [0xADAFC, 0xADB10]),
    ('task30_base_timing', [0xADB38, 0xADB9C]),
    ('task32_timing_blend_app', [
        0xADB4C, 0xADB60, 0xADB74, 0xADB88,   # found via scan
        0xADBB0, 0xADBC4, 0xADBD8, 0xADBEC,
        0xADC00, 0xADC14,
    ]),
    ('task36_timing_percond', [0xADDE0, 0xAE0D8, 0xAE0EC, 0xAE450, 0xAE46C, 0xAE488]),
    ('task42_timing_comp_b', [0xADFAC]),
    ('task45_timing_lu_b', [0xADFC0, 0xAE530]),
    ('task12_knock_post', [0xAE00C, 0xAE020, 0xAE0F8, 0xAE10C, 0xAE26C, 0xAE278]),
    ('task48_final_timing', [0xAE54C, 0xAE568, 0xAE584, 0xAE5A0, 0xAE5BC]),
    ('task00_timing_percyl', [0xAE5D8, 0xAE5F4, 0xAE610, 0xAE62C]),
    ('task01_knock_timing_fb', [0xAE664, 0xAE680, 0xAE69C]),
]


# ============================================================================
# Generate output
# ============================================================================

lines = []

class LineWriter:
    def __init__(self):
        self.lines = []
    def write(self, s):
        # Split into lines to track
        parts = s.split('\n')
        if len(parts) == 1:
            if not self.lines:
                self.lines.append('')
            self.lines[-1] += parts[0]
        else:
            for i, p in enumerate(parts):
                if i == 0:
                    if not self.lines:
                        self.lines.append('')
                    self.lines[-1] += p
                else:
                    self.lines.append(p)

out = LineWriter()

out.write('=' * 80 + '\n')
out.write('AE5L600L Ignition Timing Descriptor Tables\n')
out.write('=' * 80 + '\n')
out.write(f'ROM: {ROM_PATH}\n')
out.write(f'ROM size: {ROM_SIZE} bytes (0x{ROM_SIZE:X})\n')
out.write('\n')
out.write('Descriptor format (16 bytes):\n')
out.write('  +0: u16  X count\n')
out.write('  +2: u8   Interp type (0x00=float, 0x04=u8+scale, 0x08=u16+scale)\n')
out.write('  +3: u8   Y count (0=1D, >0=2D)\n')
out.write('  +4: u32  Pointer 1 (X-axis data)\n')
out.write('  +8: u32  Pointer 2 (Y-axis / 1D data)\n')
out.write(' +12: u32  Pointer 3 / f32 scale factor\n')
out.write('\n')
out.write('For 1D tables:\n')
out.write('  P1 = axis pointer (float array)\n')
out.write('  P2 = data pointer (u8/u16/float depending on type)\n')
out.write(' +12 = scale factor (float, for types 0x04 and 0x08)\n')
out.write('\n')
out.write('For 2D tables (type=0x00, Y>0):\n')
out.write('  P1 = X-axis pointer (float array)\n')
out.write('  P2 = Y-axis pointer (float array)\n')
out.write(' +12 = data pointer (float array, row-major: Y rows x X cols)\n')
out.write('\n')

total_descs = sum(len(addrs) for _, addrs in descriptor_groups)
out.write(f'Total descriptors: {total_descs}\n')
out.write('\n')

for group_name, addrs in descriptor_groups:
    out.write('=' * 80 + '\n')
    out.write(f'{group_name} ({len(addrs)} descriptors)\n')
    out.write('=' * 80 + '\n\n')

    for i, addr in enumerate(addrs):
        desc = decode_descriptor(addr)
        out.write(f'--- [{group_name} #{i}] ')
        out.write('-' * 50 + '\n')
        print_descriptor(desc, out)

# Write output
output_text = '\n'.join(out.lines)

os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
    f.write(output_text)

print(f'Written to: {OUTPUT_PATH}')
print(f'Total lines: {len(out.lines)}')
print(f'Total descriptors decoded: {total_descs}')
