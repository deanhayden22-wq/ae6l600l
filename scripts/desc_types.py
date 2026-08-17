"""
Calibration descriptor typecodes -- THE single source of truth.

Created 2026-08-16 because this constant had been copy-pasted into five
separate scripts, all five carried a GUESSED map, and the guess mis-sized
611 of 760 descriptors. See docs/corrections.md item 39.

--------------------------------------------------------------------------
DO NOT re-declare TYPE_NAMES / TYPE_SIZES anywhere else. Import from here.
--------------------------------------------------------------------------

VERIFIED from ROM bytes, not inferred from the data.

`table_lookup` at 0x0BE830 dispatches on the typecode byte:

    0BE83C  8442  mov.b @(2,r4),r0      ; typecode byte, 1-D record+2
    0BE83E  630C  extu.b r0,r3
    0BE840  C707  mova @(0x0BE860),r0   ; base of a table of LONGS
    0BE842  023E  mov.l @(r0,r3),r2     ; r2 = handler
    0BE846  420B  jsr  @r2

Because 0x0BE860 is a table of longs indexed by the RAW byte, the typecode is
ALWAYS a multiple of 4. Typecodes 0x02 and 0x0A -- which the old map used --
are structurally impossible; they would fetch a misaligned handler pointer.

The five handlers, decoded:

  typecode  handler    index scaling        element load            meaning
  0x00      0x0BEACC   shll2 r0   (x4)      fmov.s                  float32, 4 B
  0x04      0x0BEB20   add r0,r1  (x1)      mov.b + extu.b          uint8,   1 B
  0x08      0x0BEB6C   shll  r0   (x2)      mov.w + extu.w          uint16,  2 B
  0x0C      0x0BEAE4   add r0,r1  (x1)      mov.b,  no extu         int8,    1 B
  0x10      0x0BEB00   shll  r0   (x2)      mov.w,  no extu         int16,   2 B

The table ends at 0x0BE874, where the next function's prologue
(`4F22 sts.l pr,@-r15`) begins -- so there are exactly five entries.

Where the typecode lives in the record:
  1-D (20-byte record):  offset +2      (helper 0x0BE830)
  2-D (28-byte record):  offset +16     (helper 0x0BE8E4:
                                         `mov #16,r0 / add r4,r0 / mov.b @r0,r6`)

Census of this ROM (rev 20.19c, md5 92cae8275cd4f9b473a3a9e36efe6449):
  float32 149,  uint8 215,  uint16 396,  int8 0,  int16 0   (total 760)
Note there are ZERO int8/int16 descriptors -- the old map's 215 "int16" rows
were uint8 and its 396 "uint8" rows were uint16.
"""

# typecode byte -> short name (the form used in Ghidra label names)
TYPE_SHORT = {
    0x00: "f32",
    0x04: "u8",
    0x08: "u16",
    0x0C: "i8",
    0x10: "i16",
}

# typecode byte -> long name (the form used in the report tables)
TYPE_NAMES = {
    0x00: "float32",
    0x04: "uint8",
    0x08: "uint16",
    0x0C: "int8",
    0x10: "int16",
}

# typecode byte -> bytes per cell
TYPE_SIZES = {
    0x00: 4,
    0x04: 1,
    0x08: 2,
    0x0C: 1,
    0x10: 2,
}

# Some callers read the field as a 16-bit word at +2 instead of a byte at +2.
# coverage_map.py does this. Same information, shifted left 8.
TYPE_WIDTH_BY_WORD = {
    0x0000: 4,
    0x0400: 1,
    0x0800: 2,
    0x0C00: 1,
    0x1000: 2,
}

SIGNED = {0x0C, 0x10}


def decode_cell(rom, addr, dtype):
    """Read one cell of the given typecode from `rom` at `addr`."""
    import struct
    if dtype == 0x00:
        return struct.unpack_from(">f", rom, addr)[0]
    if dtype == 0x04:
        return rom[addr]
    if dtype == 0x08:
        return struct.unpack_from(">H", rom, addr)[0]
    if dtype == 0x0C:
        return struct.unpack_from(">b", rom, addr)[0]
    if dtype == 0x10:
        return struct.unpack_from(">h", rom, addr)[0]
    raise ValueError(f"not a valid descriptor typecode: {dtype:#x}")


# ---------------------------------------------------------------------------
# READING VALUES -- use these, do not hand-roll `raw * scale + bias`.
#
# THE TRAP (cost this project a wrong conclusion on 2026-08-16, corrections
# item 59): for typecode 0x00 the data IS already float32 and `table_lookup`
# SKIPS scale/bias entirely --
#     0BE84A  2338  tst r3,r3
#     0BE84C  8D04  bt/s 0x0BE858     ; typecode 0 -> raw is the value
# The scale/bias FIELDS still exist in the record but hold unrelated bytes.
# Applying them silently corrupts the table: all 149 float32 descriptors in
# this ROM have an implausible value sitting in that field, so the product
# collapses to ~0 or explodes. Every value looks wrong in a plausible way.
# ---------------------------------------------------------------------------

# 1-D record: +0 u16 count, +2 u8 typecode, +4 axis, +8 data, +12 scale, +16 bias
# 2-D record: +0 u16 rows,  +1 u8 Y, +3 u8 X, +4 Yaxis, +8 Xaxis, +12 data,
#             +16 typecode, +20 scale, +24 bias
_OFF = {
    "1D": {"typecode": 2, "axis": 4, "data": 8, "scale": 12, "bias": 16},
    "2D": {"typecode": 16, "yaxis": 4, "xaxis": 8, "data": 12, "scale": 20, "bias": 24},
}


def is_2d(rom, addr):
    """Byte +3 is the second-dimension size; 0 means 1-D."""
    return rom[addr + 3] != 0


def typecode(rom, addr):
    o = _OFF["2D" if is_2d(rom, addr) else "1D"]["typecode"]
    return rom[addr + o]


def scaling(rom, addr):
    """(scale, bias) or (None, None) when the typecode makes them inapplicable.

    Returns None for typecode 0x00 -- the fields are NOT a scale there.
    """
    import struct
    tc = typecode(rom, addr)
    if tc == 0x00:
        return None, None
    o = _OFF["2D" if is_2d(rom, addr) else "1D"]
    return (struct.unpack_from(">f", rom, addr + o["scale"])[0],
            struct.unpack_from(">f", rom, addr + o["bias"])[0])


def read_table(rom, addr):
    """Decode a descriptor into physical values. Handles the typecode-0 trap.

    Returns dict: dim, typecode, type_name, axes, values (list, or list of
    rows for 2-D), scale, bias. `values` are PHYSICAL -- scaled where the
    typecode calls for it, raw float32 where it does not.

    2-D layout note: the data is stored as X planes of Y values (verified on
    0xAE6D4 -- the two 18-value load planes are byte-identical), so
    values[x][y]. Do not assume row-major.
    """
    import struct
    two = is_2d(rom, addr)
    o = _OFF["2D" if two else "1D"]
    tc = typecode(rom, addr)
    if tc not in TYPE_SIZES:
        raise ValueError(f"{addr:#x}: typecode {tc:#x} is not valid (must be a multiple of 4, 0x00-0x10)")
    w = TYPE_SIZES[tc]
    sc, bi = scaling(rom, addr)

    def cell(a):
        v = decode_cell(rom, a, tc)
        return v if sc is None else v * sc + bi

    dp = struct.unpack_from(">I", rom, addr + o["data"])[0]
    if two:
        ny, nx = rom[addr + 1], rom[addr + 3]
        ya = struct.unpack_from(">I", rom, addr + o["yaxis"])[0]
        xa = struct.unpack_from(">I", rom, addr + o["xaxis"])[0]
        axes = {
            "y": [struct.unpack_from(">f", rom, ya + 4 * i)[0] for i in range(ny)],
            "x": [struct.unpack_from(">f", rom, xa + 4 * i)[0] for i in range(nx)],
        }
        vals = [[cell(dp + (p * ny + i) * w) for i in range(ny)] for p in range(nx)]
    else:
        n = struct.unpack_from(">H", rom, addr)[0]
        ax = struct.unpack_from(">I", rom, addr + o["axis"])[0]
        axes = {"x": [struct.unpack_from(">f", rom, ax + 4 * i)[0] for i in range(n)]}
        vals = [cell(dp + i * w) for i in range(n)]
    return {"dim": "2D" if two else "1D", "typecode": tc, "type_name": TYPE_NAMES[tc],
            "axes": axes, "values": vals, "scale": sc, "bias": bi}
