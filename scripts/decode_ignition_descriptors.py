#!/usr/bin/env python3
"""Decode ignition timing descriptor tables from the AE5L600L ECU ROM.

Descriptor formats (Subaru SH7058 / SH7055):

  1D scaled (16 bytes):
    +0: u16  count
    +2: u8   interp_type (0x04=u8 data, 0x08=u16 data)
    +3: u8   0
    +4: u32  axis pointer (float array)
    +8: u32  data pointer (u8 or u16 array)
   +12: f32  scale factor (output = raw * scale)

  1D float (16 bytes):
    +0: u16  count
    +2: u8   0x00
    +3: u8   0
    +4: u32  axis pointer (float array)
    +8: u32  data pointer (float array)
   +12: u32  (metadata)

  2D scaled (24 bytes):
    +0: u16  X count (columns)
    +2: u8   0x00
    +3: u8   Y count (rows, >0)
    +4: u32  X-axis pointer (float array)
    +8: u32  Y-axis pointer (float array)
   +12: u32  data pointer (u8 array, row-major)
   +16: u32  data type tag (0x04000000)
   +20: f32  scale factor (output = raw_u8 * scale)
"""
import struct
import sys
import os

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

def read_u32(addr):
    return struct.unpack_from('>I', rom, addr)[0]

def read_f32(addr):
    return struct.unpack_from('>f', rom, addr)[0]


def read_float_array(ptr, count):
    return [read_f32(ptr + i * 4) for i in range(count)]


def is_valid_scale(addr):
    """Check if the 4 bytes at addr look like a valid scale factor (not another descriptor)."""
    raw = read_u32(addr)
    if raw == 0:
        return True  # 0.0 is valid
    exp = (raw >> 23) & 0xFF
    # Valid IEEE754 float exponents for reasonable scales: ~1e-10 to ~1e10
    return 0x20 < exp < 0xC0


def decode_descriptor(addr):
    """Decode a table descriptor at the given ROM address."""
    x_count = read_u16(addr)
    interp_type = read_u8(addr + 2)
    y_count = read_u8(addr + 3)

    p1 = read_u32(addr + 4)
    p2 = read_u32(addr + 8)

    desc = {
        'addr': addr,
        'x_count': x_count,
        'interp_type': interp_type,
        'y_count': y_count,
        'raw_hex': rom[addr:addr + 16].hex(),
    }

    is_2d = (y_count > 0)

    if is_2d:
        desc['type'] = '2D'
        desc['x_axis_ptr'] = p1
        desc['y_axis_ptr'] = p2
        desc['data_ptr'] = read_u32(addr + 12)
        desc['data_type_tag'] = read_u32(addr + 16)
        desc['scale'] = read_f32(addr + 20)
        desc['raw_hex'] = rom[addr:addr + 24].hex()
    elif interp_type == 0x00:
        desc['type'] = '1D_float'
        desc['axis_ptr'] = p1
        desc['data_ptr'] = p2
    elif interp_type in (0x04, 0x08):
        desc['type'] = '1D_scaled'
        desc['axis_ptr'] = p1
        desc['data_ptr'] = p2
        if is_valid_scale(addr + 12):
            desc['scale'] = read_f32(addr + 12)
        else:
            desc['scale'] = None
            desc['scale_note'] = 'Scale field invalid (0x{:08X}); raw values shown'.format(read_u32(addr + 12))
    else:
        desc['type'] = 'unknown'

    return desc


def read_data(desc):
    """Read and return decoded table data."""
    if desc['type'] == '2D':
        x_axis = read_float_array(desc['x_axis_ptr'], desc['x_count'])
        y_axis = read_float_array(desc['y_axis_ptr'], desc['y_count'])
        dp = desc['data_ptr']
        scale = desc['scale']
        xcnt = desc['x_count']
        ycnt = desc['y_count']
        data = []
        for y in range(ycnt):
            row = []
            for x in range(xcnt):
                raw = read_u8(dp + y * xcnt + x)
                row.append(raw * scale)
            data.append(row)
        return {'x_axis': x_axis, 'y_axis': y_axis, 'data': data}

    elif desc['type'] == '1D_float':
        axis = read_float_array(desc['axis_ptr'], desc['x_count'])
        data = read_float_array(desc['data_ptr'], desc['x_count'])
        return {'axis': axis, 'data': data}

    elif desc['type'] == '1D_scaled':
        axis = read_float_array(desc['axis_ptr'], desc['x_count'])
        dp = desc['data_ptr']
        scale = desc.get('scale')
        cnt = desc['x_count']
        if desc['interp_type'] == 0x04:
            raw = [read_u8(dp + i) for i in range(cnt)]
        elif desc['interp_type'] == 0x08:
            raw = [read_u16(dp + i * 2) for i in range(cnt)]
        else:
            raw = [read_u8(dp + i) for i in range(cnt)]
        if scale is not None:
            scaled = [v * scale for v in raw]
        else:
            scaled = None
        return {'axis': axis, 'raw': raw, 'scaled': scaled}

    return None


def fmt(v):
    """Format a float for display."""
    if v == 0 or (abs(v) < 1e-10 and abs(v) > 0):
        return '0'
    neg = v < 0
    av = abs(v)
    if av == int(av) and av < 100000:
        return str(int(v))
    if av < 0.01:
        return f'{v:.6f}'
    if av < 1:
        return f'{v:.4f}'
    if av < 100:
        return f'{v:.2f}'
    if av < 10000:
        return f'{v:.1f}'
    return f'{v:.0f}'


def write_descriptor(desc, out):
    """Write a decoded descriptor to output."""
    addr = desc['addr']
    out(f'  Descriptor @ 0x{addr:05X}\n')
    out(f'    Raw: {desc["raw_hex"]}\n')
    out(f'    Type: {desc["type"]}')
    if desc['type'] == '2D':
        out(f'  ({desc["x_count"]} cols x {desc["y_count"]} rows)')
    elif desc['type'] != 'unknown':
        out(f'  ({desc["x_count"]} entries)')
    out('\n')

    out(f'    X count: {desc["x_count"]}')
    if desc['type'] == '2D':
        out(f',  Y count: {desc["y_count"]}')
    out('\n')

    out(f'    Interp type: 0x{desc["interp_type"]:02X}')
    types = {0x00: 'float/u8', 0x04: 'u8 + scale', 0x08: 'u16 + scale'}
    if desc['interp_type'] in types:
        out(f' ({types[desc["interp_type"]]})')
    out('\n')

    if desc['type'] == '2D':
        out(f'    X-axis ptr: 0x{desc["x_axis_ptr"]:06X}\n')
        out(f'    Y-axis ptr: 0x{desc["y_axis_ptr"]:06X}\n')
        out(f'    Data ptr:   0x{desc["data_ptr"]:06X}\n')
        out(f'    Data tag:   0x{desc["data_type_tag"]:08X}\n')
        out(f'    Scale:      {desc["scale"]}\n')
    elif desc['type'] == '1D_float':
        out(f'    Axis ptr: 0x{desc["axis_ptr"]:06X}\n')
        out(f'    Data ptr: 0x{desc["data_ptr"]:06X}\n')
    elif desc['type'] == '1D_scaled':
        out(f'    Axis ptr: 0x{desc["axis_ptr"]:06X}\n')
        out(f'    Data ptr: 0x{desc["data_ptr"]:06X}\n')
        if desc.get('scale') is not None:
            out(f'    Scale:    {desc["scale"]}\n')
        if desc.get('scale_note'):
            out(f'    NOTE: {desc["scale_note"]}\n')

    out('\n')

    result = read_data(desc)
    if result is None:
        out('    [Could not decode data]\n\n')
        return

    if desc['type'] == '2D':
        x_axis = result['x_axis']
        y_axis = result['y_axis']
        data = result['data']
        xcnt = desc['x_count']
        ycnt = desc['y_count']

        if xcnt > 25 and ycnt > 25:
            out(f'    [Table too large: {xcnt}x{ycnt}]\n')
            out(f'    X range: {fmt(x_axis[0])} .. {fmt(x_axis[-1])}\n')
            out(f'    Y range: {fmt(y_axis[0])} .. {fmt(y_axis[-1])}\n\n')
            return

        x_strs = [fmt(v) for v in x_axis]
        y_strs = [fmt(v) for v in y_axis]
        data_strs = [[fmt(v) for v in row] for row in data]

        col_widths = []
        for xi in range(xcnt):
            w = len(x_strs[xi])
            for yi in range(ycnt):
                w = max(w, len(data_strs[yi][xi]))
            col_widths.append(w + 1)

        y_label_w = max(len(s) for s in y_strs) if y_strs else 4

        # Header
        out('    ' + ' ' * y_label_w + ' |')
        for xi in range(xcnt):
            out(x_strs[xi].rjust(col_widths[xi]))
        out('\n')

        # Separator
        out('    ' + '-' * y_label_w + '-+' + '-' * sum(col_widths) + '\n')

        # Rows
        for yi in range(ycnt):
            out('    ' + y_strs[yi].rjust(y_label_w) + ' |')
            for xi in range(xcnt):
                out(data_strs[yi][xi].rjust(col_widths[xi]))
            out('\n')
        out('\n')

    elif desc['type'] == '1D_float':
        axis = result['axis']
        data = result['data']
        out('    Axis       | Value\n')
        out('    -----------+-----------\n')
        for a, d in zip(axis, data):
            out(f'    {fmt(a):>10s} | {fmt(d)}\n')
        out('\n')

    elif desc['type'] == '1D_scaled':
        axis = result['axis']
        raw = result['raw']
        scaled = result['scaled']
        if desc['interp_type'] == 0x04:
            dtype_label = 'u8'
            rw = 5
        else:
            dtype_label = 'u16'
            rw = 7

        if scaled is not None:
            out(f'    {"Axis":>10s} | {"Raw":>{rw}s} | Scaled\n')
            out(f'    {"-"*10}-+-{"-"*rw}-+-{"-"*10}\n')
            for a, r, s in zip(axis, raw, scaled):
                out(f'    {fmt(a):>10s} | {r:{rw}d} | {fmt(s)}\n')
        else:
            out(f'    {"Axis":>10s} | {"Raw":>{rw}s}\n')
            out(f'    {"-"*10}-+-{"-"*rw}\n')
            for a, r in zip(axis, raw):
                out(f'    {fmt(a):>10s} | {r:{rw}d}\n')
        out('\n')


# ============================================================================
# Descriptor groups
# ============================================================================

descriptor_groups = [
    ('task49_base_advance', 'Base ignition advance (cranking/startup)', [
        0xADAFC, 0xADB10,
    ]),
    ('task30_base_timing', 'Base timing 1D curves', [
        0xADB38, 0xADB9C,
    ]),
    ('task32_timing_blend_app', 'Timing blend application (ECT-indexed 1D curves)', [
        0xADB4C, 0xADB60, 0xADB74, 0xADB88,
        0xADBB0, 0xADBC4, 0xADBD8, 0xADBEC,
        0xADC00, 0xADC14,
    ]),
    ('task36_timing_percond', 'Per-condition timing corrections', [
        0xADDE0, 0xAE450, 0xAE46C, 0xAE488, 0xAE0D8, 0xAE0EC,
    ]),
    ('task42_timing_comp_b', 'Timing compensation B (ECT-indexed)', [
        0xADFAC,
    ]),
    ('task45_timing_lu_b', 'Timing lookup B', [
        0xADFC0, 0xAE530,
    ]),
    ('task12_knock_post', 'Post-knock timing corrections', [
        0xAE00C, 0xAE020, 0xAE0F8, 0xAE10C, 0xAE26C, 0xAE278,
    ]),
    ('task48_final_timing', 'Final timing limits/clamps', [
        0xAE54C, 0xAE568, 0xAE584, 0xAE5A0, 0xAE5BC,
    ]),
    ('task00_timing_percyl', 'Per-cylinder timing trim (load x RPM)', [
        0xAE5D8, 0xAE5F4, 0xAE610, 0xAE62C,
    ]),
    ('task01_knock_timing_fb', 'Knock feedback timing retard (load x RPM)', [
        0xAE664, 0xAE680, 0xAE69C,
    ]),
]


# ============================================================================
# Generate output
# ============================================================================

buf = []

def out(s):
    buf.append(s)

out('=' * 80 + '\n')
out('AE5L600L Ignition Timing Descriptor Tables\n')
out('ROM: ae5l600l.bin (1,048,576 bytes)\n')
out('=' * 80 + '\n\n')

out('DESCRIPTOR FORMAT SUMMARY\n')
out('-' * 40 + '\n')
out('1D scaled (16 bytes):\n')
out('  [count:u16][type:u8][0:u8] [axis_ptr:u32] [data_ptr:u32] [scale:f32]\n')
out('  type 0x04: u8 data,  type 0x08: u16 data.  Output = raw * scale.\n\n')
out('1D float (16 bytes):\n')
out('  [count:u16][0x00:u8][0:u8] [axis_ptr:u32] [data_ptr:u32] [meta:u32]\n')
out('  Both axis and data are IEEE754 float arrays.\n\n')
out('2D scaled (24 bytes):\n')
out('  [xcnt:u16][0x00:u8][ycnt:u8] [x_axis_ptr:u32] [y_axis_ptr:u32]\n')
out('  [data_ptr:u32] [tag:u32] [scale:f32]\n')
out('  Data is u8 row-major (Y rows x X cols). Output = raw_u8 * scale.\n\n')
out('Common scale values:\n')
out('  0.3515625 = 90/256  (maps u8 0-255 to ~0-89.6 degrees)\n')
out('  0.0078125 = 1/128   (maps u8 0-255 to ~0-2.0)\n')
out('  1/65536             (maps u16 to ~0-1)\n')
out('  2.0                 (maps u16 to large values)\n\n')

total_descs = sum(len(addrs) for _, _, addrs in descriptor_groups)
out(f'Total descriptors: {total_descs}\n\n')

for group_name, group_desc, addrs in descriptor_groups:
    out('=' * 80 + '\n')
    out(f'{group_name}: {group_desc}\n')
    out(f'  ({len(addrs)} descriptor{"s" if len(addrs) != 1 else ""})\n')
    out('=' * 80 + '\n\n')

    for i, addr in enumerate(addrs):
        desc = decode_descriptor(addr)
        label = f'[{group_name} #{i}]'
        out(f'--- {label} ' + '-' * max(1, 70 - len(label)) + '\n')
        write_descriptor(desc, out)

# Write output
output_text = ''.join(buf)

os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
    f.write(output_text)

line_count = output_text.count('\n')
print(f'Written to: {OUTPUT_PATH}')
print(f'Total lines: {line_count}')
print(f'Total descriptors decoded: {total_descs}')
