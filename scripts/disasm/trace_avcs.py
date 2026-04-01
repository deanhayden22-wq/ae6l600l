#!/usr/bin/env python3
"""
AE5L600L AVCS (Active Valve Control System) Subsystem Trace
=============================================================
Traces VVT/AVCS code paths, tables, descriptors, and I/O in the SH7058 ROM.

Known AVCS descriptors:
  - AVCS Intake Duty Correction:  0xAD620 (28-byte 2D, uint8, 10x9)
  - AVCS Exhaust Duty Correction: 0xAD848 (28-byte 2D, uint16, 10x9)
  - VVT Error descriptors: 0xAF830, 0xAF84C, 0xAF868, 0xAF884

Output: disassembly/analysis/avcs_raw.txt
"""
import os
import struct
import sys
import math

# Force UTF-8 stdout
sys.stdout.reconfigure(encoding='utf-8')

ROM_PATH = "C:/Users/Dean/Documents/GitHub/ae6l600l/rom/ae5l600l.bin"
OUTPUT_PATH = "C:/Users/Dean/Documents/GitHub/ae6l600l/disassembly/analysis/avcs_raw.txt"

with open(ROM_PATH, "rb") as f:
    rom = f.read()

ROM_LEN = len(rom)
GBR = 0xFFFF7450

# ============================================================================
# Primitives
# ============================================================================

def r_u8(a):  return rom[a]
def r_u16(a): return struct.unpack_from(">H", rom, a)[0]
def r_s16(a): return struct.unpack_from(">h", rom, a)[0]
def r_u32(a): return struct.unpack_from(">I", rom, a)[0]
def r_f32(a): return struct.unpack_from(">f", rom, a)[0]

def is_rom_ptr(v): return 0x1000 <= v < ROM_LEN
def is_ram_ptr(v): return 0xFFFF0000 <= v <= 0xFFFFFFFF

TYPE_NAMES = {0x00:"float32", 0x02:"int8", 0x04:"int16", 0x08:"uint8", 0x0A:"uint16"}
TYPE_SIZES = {0x00:4, 0x02:1, 0x04:2, 0x08:1, 0x0A:2}

# ============================================================================
# SH-2 Disassembler
# ============================================================================

def sign8(v):
    return v - 256 if v > 127 else v

def disasm_one(addr):
    """Disassemble one SH-2 instruction. Returns (mnemonic, comment, is_branch)."""
    if addr + 1 >= ROM_LEN:
        return (".word  ???", "", False)
    op = r_u16(addr)
    n4 = [(op >> 12) & 0xF, (op >> 8) & 0xF, (op >> 4) & 0xF, op & 0xF]
    top = n4[0]
    n = n4[1]; m = n4[2]; d4 = n4[3]
    d8 = op & 0xFF
    rn = f"R{n}"; rm = f"R{m}"
    mn = ""; cmt = ""; is_br = False

    if op == 0x0009: mn = "nop"
    elif op == 0x000B: mn = "rts"; is_br = True
    elif op == 0x0019: mn = "div0u"
    elif top == 0x0:
        sub = d4
        if sub == 0xC:   mn = f"mov.b  @(R0,{rm}),{rn}"
        elif sub == 0xD: mn = f"mov.w  @(R0,{rm}),{rn}"
        elif sub == 0xE: mn = f"mov.l  @(R0,{rm}),{rn}"
        elif sub == 0x4: mn = f"mov.b  {rm},@(R0,{rn})"
        elif sub == 0x5: mn = f"mov.w  {rm},@(R0,{rn})"
        elif sub == 0x6: mn = f"mov.l  {rm},@(R0,{rn})"
        elif sub == 0x7: mn = f"mul.l  {rm},{rn}"
        elif sub == 0x2:
            if m == 0: mn = f"stc    SR,{rn}"
            elif m == 1: mn = f"stc    GBR,{rn}"
            else: mn = f".word  0x{op:04X}"
        elif sub == 0xA:
            if m == 0: mn = f"sts    MACH,{rn}"
            elif m == 1: mn = f"sts    MACL,{rn}"
            elif m == 2: mn = f"sts    PR,{rn}"
            else: mn = f".word  0x{op:04X}"
        elif sub == 0x3:
            if m == 0: mn = f"bsrf   {rn}"; is_br = True
            elif m == 2: mn = f"braf   {rn}"; is_br = True
            else: mn = f".word  0x{op:04X}"
        elif sub == 0xB:
            mn = f".word  0x{op:04X}"
        else:
            mn = f".word  0x{op:04X}"
    elif top == 0x1:
        disp = d4 * 4
        mn = f"mov.l  {rm},@({disp},{rn})"
    elif top == 0x2:
        sub = d4
        sz_map = {0:".b",1:".w",2:".l"}
        sz_map2 = {4:".b",5:".w",6:".l"}
        if sub in sz_map:
            mn = f"mov{sz_map[sub]}  {rm},@{rn}"
        elif sub in sz_map2:
            mn = f"mov{sz_map2[sub]}  {rm},@-{rn}"
        elif sub == 8: mn = f"tst    {rm},{rn}"
        elif sub == 9: mn = f"and    {rm},{rn}"
        elif sub == 0xA: mn = f"xor    {rm},{rn}"
        elif sub == 0xB: mn = f"or     {rm},{rn}"
        elif sub == 0xD: mn = f"xtrct  {rm},{rn}"
        else: mn = f".word  0x{op:04X}"
    elif top == 0x3:
        sub = d4
        ops3 = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",4:"div1",5:"dmulu.l",
                6:"cmp/hi",7:"cmp/gt",8:"sub",0xA:"subc",0xC:"add",
                0xD:"dmuls.l",0xE:"addc",0xF:"addv"}
        if sub in ops3: mn = f"{ops3[sub]:7s}{rm},{rn}"
        else: mn = f".word  0x{op:04X}"
    elif top == 0x4:
        low8 = op & 0xFF
        tbl4 = {
            0x22: f"sts.l  PR,@-{rn}", 0x26: f"lds.l  @{rn}+,PR",
            0x13: f"stc.l  GBR,@-{rn}", 0x17: f"ldc.l  @{rn}+,GBR",
            0x1E: f"ldc    {rn},GBR",
            0x0B: f"jsr    @{rn}", 0x2B: f"jmp    @{rn}",
            0x15: f"cmp/pl {rn}", 0x11: f"cmp/pz {rn}", 0x10: f"dt     {rn}",
            0x00: f"shll   {rn}", 0x01: f"shlr   {rn}",
            0x04: f"rotl   {rn}", 0x05: f"rotr   {rn}",
            0x08: f"shll2  {rn}", 0x09: f"shlr2  {rn}",
            0x18: f"shll8  {rn}", 0x19: f"shlr8  {rn}",
            0x28: f"shll16 {rn}", 0x29: f"shlr16 {rn}",
            0x24: f"rotcl  {rn}", 0x25: f"rotcr  {rn}",
            0x20: f"shal   {rn}", 0x21: f"shar   {rn}",
        }
        if low8 in tbl4:
            mn = tbl4[low8]
            if low8 in (0x0B, 0x2B): is_br = True
        else:
            mn = f".word  0x{op:04X}"
    elif top == 0x5:
        disp = d4 * 4
        mn = f"mov.l  @({disp},{rm}),{rn}"
    elif top == 0x6:
        sub = d4
        ops6 = {
            0:"mov.b  @{m},{n}", 1:"mov.w  @{m},{n}", 2:"mov.l  @{m},{n}",
            3:"mov    {m},{n}", 4:"mov.b  @{m}+,{n}", 5:"mov.w  @{m}+,{n}",
            6:"mov.l  @{m}+,{n}", 7:"not    {m},{n}", 8:"swap.b {m},{n}",
            9:"swap.w {m},{n}", 0xA:"negc   {m},{n}", 0xB:"neg    {m},{n}",
            0xC:"extu.b {m},{n}", 0xD:"extu.w {m},{n}",
            0xE:"exts.b {m},{n}", 0xF:"exts.w {m},{n}",
        }
        if sub in ops6: mn = ops6[sub].format(m=rm, n=rn)
        else: mn = f".word  0x{op:04X}"
    elif top == 0x7:
        imm = sign8(d8)
        mn = f"add    #{imm},{rn}"
    elif top == 0x8:
        sub = n
        if sub == 0x0:   mn = f"mov.b  R0,@({d8},{rm})"
        elif sub == 0x1: mn = f"mov.w  R0,@({d8*2},{rm})"
        elif sub == 0x4: mn = f"mov.b  @({d8},{rm}),R0"
        elif sub == 0x5: mn = f"mov.w  @({d8*2},{rm}),R0"
        elif sub == 0x8:
            imm = sign8(d8)
            mn = f"cmp/eq #{imm},R0"
        elif sub in (0x9, 0xB, 0xD, 0xF):
            disp = sign8(d8) * 2 + 4
            target = addr + disp
            br_names = {0x9:"bt", 0xB:"bf", 0xD:"bt/s", 0xF:"bf/s"}
            mn = f"{br_names[sub]}    0x{target:06X}"
            is_br = (sub in (0x9, 0xB))
        else: mn = f".word  0x{op:04X}"
    elif top == 0x9:
        disp = d8 * 2
        pool_addr = addr + 4 + disp
        if pool_addr + 1 < ROM_LEN:
            val = r_u16(pool_addr)
            mn = f"mov.w  @(0x{pool_addr:06X}),{rn}"
            cmt = f"  ; #{val} (0x{val:04X})"
        else:
            mn = f"mov.w  @(?),{rn}"
    elif top == 0xA:
        disp12 = op & 0xFFF
        if disp12 > 0x7FF: disp12 -= 0x1000
        target = addr + 4 + disp12 * 2
        mn = f"bra    0x{target:06X}"; is_br = True
    elif top == 0xB:
        disp12 = op & 0xFFF
        if disp12 > 0x7FF: disp12 -= 0x1000
        target = addr + 4 + disp12 * 2
        mn = f"bsr    0x{target:06X}"; is_br = True
    elif top == 0xC:
        sub = n
        if sub == 0x0:
            disp = d8; ga = GBR + disp
            mn = f"mov.b  R0,@(0x{disp:02X},GBR)"; cmt = f"  ; [{ga:08X}]"
        elif sub == 0x1:
            disp = d8*2; ga = GBR + disp
            mn = f"mov.w  R0,@(0x{disp:04X},GBR)"; cmt = f"  ; [{ga:08X}]"
        elif sub == 0x2:
            disp = d8*4; ga = GBR + disp
            mn = f"mov.l  R0,@(0x{disp:04X},GBR)"; cmt = f"  ; [{ga:08X}]"
        elif sub == 0x4:
            disp = d8; ga = GBR + disp
            mn = f"mov.b  @(0x{disp:02X},GBR),R0"; cmt = f"  ; [{ga:08X}]"
        elif sub == 0x5:
            disp = d8*2; ga = GBR + disp
            mn = f"mov.w  @(0x{disp:04X},GBR),R0"; cmt = f"  ; [{ga:08X}]"
        elif sub == 0x6:
            disp = d8*4; ga = GBR + disp
            mn = f"mov.l  @(0x{disp:04X},GBR),R0"; cmt = f"  ; [{ga:08X}]"
        elif sub == 0x7:
            disp = d8*4; pa = ((addr + 4) & ~3) + disp
            mn = f"mova   @(0x{pa:06X}),R0"
        elif sub == 0x8: mn = f"tst    #0x{d8:02X},R0"
        elif sub == 0x9: mn = f"and    #0x{d8:02X},R0"
        elif sub == 0xA: mn = f"xor    #0x{d8:02X},R0"
        elif sub == 0xB: mn = f"or     #0x{d8:02X},R0"
        elif sub == 0xD: mn = f"and.b  #0x{d8:02X},@(R0,GBR)"
        elif sub == 0xF: mn = f"or.b   #0x{d8:02X},@(R0,GBR)"
        else: mn = f".word  0x{op:04X}"
    elif top == 0xD:
        disp = d8 * 4
        pool_addr = ((addr + 4) & ~3) + disp
        if pool_addr + 3 < ROM_LEN:
            val = r_u32(pool_addr)
            mn = f"mov.l  @(0x{pool_addr:06X}),{rn}"
            if 0xFFFF0000 <= val <= 0xFFFFFFFF:
                cmt = f"  ; =0x{val:08X} (RAM)"
            elif 0xFFFE0000 <= val < 0xFFFF0000:
                cmt = f"  ; =0x{val:08X} (I/O)"
            elif val < 0x00200000:
                cmt = f"  ; =0x{val:08X} (code)"
            elif 0x000A0000 <= val <= 0x000FFFFF:
                cmt = f"  ; =0x{val:08X} (cal)"
                try:
                    fv = r_f32(val)
                    if not math.isnan(fv) and abs(fv) < 1e12:
                        cmt += f" val={fv}"
                except: pass
            else:
                cmt = f"  ; =0x{val:08X}"
        else:
            mn = f"mov.l  @(?),{rn}"
    elif top == 0xE:
        imm = sign8(d8)
        mn = f"mov    #{imm},{rn}"
    elif top == 0xF:
        sub = d4
        fn = f"FR{n}"; fm = f"FR{m}"
        fpu = {
            0x0: f"fadd   {fm},{fn}", 0x1: f"fsub   {fm},{fn}",
            0x2: f"fmul   {fm},{fn}", 0x3: f"fdiv   {fm},{fn}",
            0x4: f"fcmp/eq {fm},{fn}", 0x5: f"fcmp/gt {fm},{fn}",
            0x6: f"fmov.s @(R0,R{m}),{fn}", 0x7: f"fmov.s {fm},@(R0,R{n})",
            0x8: f"fmov.s @R{m},{fn}", 0x9: f"fmov.s @R{m}+,{fn}",
            0xA: f"fmov.s {fm},@R{n}", 0xB: f"fmov.s {fm},@-R{n}",
            0xC: f"fmov   {fm},{fn}",
        }
        if sub in fpu:
            mn = fpu[sub]
        elif sub == 0xD:
            fpuD = {
                0x0: f"fsts   FPUL,{fn}", 0x1: f"flds   {fn},FPUL",
                0x2: f"float  FPUL,{fn}", 0x3: f"ftrc   {fn},FPUL",
                0x4: f"fneg   {fn}", 0x5: f"fabs   {fn}",
                0x6: f"fsqrt  {fn}", 0x8: f"fldi0  {fn}", 0x9: f"fldi1  {fn}",
            }
            mn = fpuD.get(m, f".word  0x{op:04X}")
        else:
            mn = f".word  0x{op:04X}"

    if not mn: mn = f".word  0x{op:04X}"
    return (mn, cmt, is_br)


def disasm_range(start, count, out):
    """Disassemble 'count' instructions starting at 'start', write to out."""
    addr = start
    for _ in range(count):
        if addr + 1 >= ROM_LEN: break
        op = r_u16(addr)
        mn, cmt, _ = disasm_one(addr)
        out.write(f"  {addr:06X}: {op:04X}  {mn}{cmt}\n")
        addr += 2


def collect_literals(start, count):
    """Collect all literal pool values referenced in a code region."""
    literals = {}
    addr = start
    for _ in range(count):
        if addr + 1 >= ROM_LEN: break
        op = r_u16(addr)
        top = (op >> 12) & 0xF
        if top == 0xD:
            d8 = op & 0xFF
            pool_addr = ((addr + 4) & ~3) + d8 * 4
            if pool_addr + 3 < ROM_LEN:
                val = r_u32(pool_addr)
                reg = (op >> 8) & 0xF
                literals[addr] = (pool_addr, val, reg)
        elif top == 0x9:
            d8 = op & 0xFF
            pool_addr = addr + 4 + d8 * 2
            if pool_addr + 1 < ROM_LEN:
                val = r_u16(pool_addr)
                reg = (op >> 8) & 0xF
                literals[addr] = (pool_addr, val, reg)
        addr += 2
    return literals


# ============================================================================
# Search for u32 references in ROM
# ============================================================================

def find_u32_refs(target_val):
    """Find all addresses where a u32 == target_val appears (likely literal pool entries)."""
    results = []
    for a in range(0, ROM_LEN - 3, 4):
        if r_u32(a) == target_val:
            results.append(a)
    return results


def find_movl_pc_refs(target_val):
    """Find mov.l @(disp,PC),Rn instructions that load target_val from literal pools."""
    results = []
    # First find literal pool entries
    pool_addrs = find_u32_refs(target_val)
    for pool_addr in pool_addrs:
        # Now find mov.l instructions that reference this pool address
        # mov.l @(disp,PC),Rn: 1101nnnndddddddd
        # pool_addr = ((PC+4) & ~3) + disp*4
        # So PC = pool_addr - disp*4 - 4 (roughly), but PC must be aligned consideration
        # Search backwards from pool_addr
        for pc in range(max(0, pool_addr - 1024), pool_addr, 2):
            op = r_u16(pc)
            if (op >> 12) == 0xD:
                d8 = op & 0xFF
                calc_pool = ((pc + 4) & ~3) + d8 * 4
                if calc_pool == pool_addr:
                    reg = (op >> 8) & 0xF
                    results.append((pc, reg, pool_addr))
    return results


# ============================================================================
# Descriptor Parsing
# ============================================================================

def parse_2d_desc(addr):
    """Parse a 28-byte 2D descriptor."""
    rows = rom[addr + 1]
    cols = rom[addr + 3]
    y_ptr = r_u32(addr + 4)
    x_ptr = r_u32(addr + 8)
    d_ptr = r_u32(addr + 12)
    dtype = rom[addr + 16]
    scale = r_f32(addr + 20)
    bias = r_f32(addr + 24)
    return {
        "rows": rows, "cols": cols,
        "y_ptr": y_ptr, "x_ptr": x_ptr, "d_ptr": d_ptr,
        "dtype": dtype, "dtype_name": TYPE_NAMES.get(dtype, f"?{dtype}"),
        "scale": scale, "bias": bias,
    }


def parse_1d_desc(addr):
    """Parse a 20-byte 1D descriptor."""
    size = rom[addr + 1]
    dtype = rom[addr + 2]
    axis_ptr = r_u32(addr + 4)
    data_ptr = r_u32(addr + 8)
    scale = r_f32(addr + 12)
    bias = r_f32(addr + 16)
    return {
        "size": size, "dtype": dtype,
        "dtype_name": TYPE_NAMES.get(dtype, f"?{dtype}"),
        "axis_ptr": axis_ptr, "data_ptr": data_ptr,
        "scale": scale, "bias": bias,
    }


def read_axis(ptr, count):
    """Read float32 axis values."""
    return [r_f32(ptr + i*4) for i in range(count)]


def read_data(ptr, count, dtype, scale, bias):
    """Read data values and apply scale/bias."""
    raw = []
    phys = []
    esz = TYPE_SIZES.get(dtype, 1)
    for i in range(count):
        a = ptr + i * esz
        if dtype == 0x00:
            rv = r_f32(a)
        elif dtype == 0x02:
            rv = rom[a]
            if rv > 127: rv -= 256
        elif dtype == 0x04:
            rv = r_s16(a)
        elif dtype == 0x08:
            rv = rom[a]
        elif dtype == 0x0A:
            rv = r_u16(a)
        else:
            rv = rom[a]
        raw.append(rv)
        if dtype == 0x00:
            phys.append(rv)
        else:
            phys.append(rv * scale + bias)
    return raw, phys


def format_2d_table(y_axis, x_axis, data_2d, label, fmt="{:8.2f}"):
    """Format a 2D table as a grid string."""
    lines = []
    # Header
    hdr = f"{'':>10s}"
    for xv in x_axis:
        hdr += f"{xv:>8.1f}"
    lines.append(hdr)
    lines.append("-" * len(hdr))
    for ri, yv in enumerate(y_axis):
        row = f"{yv:>10.1f}"
        for ci in range(len(x_axis)):
            val = data_2d[ri][ci]
            row += fmt.format(val)
        lines.append(row)
    return "\n".join(lines)


# ============================================================================
# Main analysis
# ============================================================================

def main():
    out_dir = os.path.dirname(OUTPUT_PATH)
    os.makedirs(out_dir, exist_ok=True)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as out:
        out.write("=" * 78 + "\n")
        out.write("AE5L600L AVCS (Active Valve Control System) Subsystem - Raw Trace\n")
        out.write("=" * 78 + "\n\n")
        out.write(f"ROM: {ROM_PATH}\n")
        out.write(f"ROM size: {ROM_LEN} bytes (0x{ROM_LEN:X})\n")
        out.write(f"Generated by trace_avcs.py\n\n")

        # ==================================================================
        # PART 1: References to AVCS Intake/Exhaust Duty Correction descriptors
        # ==================================================================
        out.write("=" * 78 + "\n")
        out.write("PART 1: AVCS DESCRIPTOR REFERENCES (Code Cross-References)\n")
        out.write("=" * 78 + "\n\n")

        desc_addrs = {
            0x0AD620: "AVCS Intake Duty Correction",
            0x0AD848: "AVCS Exhaust Duty Correction",
        }

        avcs_code_regions = []  # collect code regions for later I/O search

        for desc_addr, desc_name in desc_addrs.items():
            out.write(f"\n--- References to {desc_name} (0x{desc_addr:06X}) ---\n\n")
            refs = find_movl_pc_refs(desc_addr)
            if not refs:
                out.write(f"  No mov.l references found for 0x{desc_addr:06X}\n")
                # Also search as raw u32
                raw_refs = find_u32_refs(desc_addr)
                if raw_refs:
                    out.write(f"  Raw u32 occurrences at: {', '.join(f'0x{a:06X}' for a in raw_refs)}\n")
            else:
                out.write(f"  Found {len(refs)} reference(s):\n\n")
                for pc, reg, pool in refs:
                    out.write(f"  Instruction at 0x{pc:06X}: mov.l @(0x{pool:06X}),R{reg}"
                              f"  ; loads 0x{desc_addr:06X} ({desc_name})\n")
                    out.write(f"  Literal pool entry at 0x{pool:06X}\n\n")

                    # Disassemble ~100 instructions centered around this reference
                    region_start = max(0, (pc - 100) & ~1)
                    region_count = 120
                    avcs_code_regions.append((region_start, region_start + region_count * 2))
                    out.write(f"  Disassembly around 0x{pc:06X} ({region_start:06X} - {region_start + region_count*2:06X}):\n")
                    out.write(f"  {'='*70}\n")
                    disasm_range(region_start, region_count, out)
                    out.write(f"\n  Literal pool values in this region:\n")
                    lits = collect_literals(region_start, region_count)
                    for la in sorted(lits.keys()):
                        pa, val, reg = lits[la]
                        ann = ""
                        if 0xFFFF0000 <= val <= 0xFFFFFFFF: ann = " (RAM)"
                        elif 0xFFFE0000 <= val < 0xFFFF0000: ann = " (I/O reg)"
                        elif is_rom_ptr(val): ann = " (ROM)"
                        out.write(f"    0x{la:06X} -> pool 0x{pa:06X} = 0x{val:08X} -> R{reg}{ann}\n")
                    out.write("\n")

        # ==================================================================
        # PART 2: References to VVT Error descriptors
        # ==================================================================
        out.write("=" * 78 + "\n")
        out.write("PART 2: VVT ERROR DESCRIPTOR REFERENCES\n")
        out.write("=" * 78 + "\n\n")

        vvt_err_descs = {
            0x0AF830: "VVT Error Desc 1",
            0x0AF84C: "VVT Error Desc 2",
            0x0AF868: "VVT Error Desc 3",
            0x0AF884: "VVT Error Desc 4",
        }

        for desc_addr, desc_name in vvt_err_descs.items():
            out.write(f"\n--- References to {desc_name} (0x{desc_addr:06X}) ---\n\n")

            # Decode the descriptor first
            out.write(f"  Descriptor raw bytes:\n")
            for i in range(0, 28, 4):
                if desc_addr + i + 3 < ROM_LEN:
                    val = r_u32(desc_addr + i)
                    out.write(f"    +0x{i:02X}: 0x{val:08X}\n")

            # Check if 1D or 2D
            b3 = rom[desc_addr + 3]
            if b3 != 0:
                # 2D descriptor
                desc = parse_2d_desc(desc_addr)
                out.write(f"  Parsed as 2D: {desc['rows']}x{desc['cols']}, "
                          f"dtype={desc['dtype_name']}, "
                          f"scale={desc['scale']}, bias={desc['bias']}\n")
                out.write(f"  Y-axis ptr: 0x{desc['y_ptr']:06X}, "
                          f"X-axis ptr: 0x{desc['x_ptr']:06X}, "
                          f"Data ptr: 0x{desc['d_ptr']:06X}\n")
            else:
                # 1D descriptor
                desc = parse_1d_desc(desc_addr)
                out.write(f"  Parsed as 1D: size={desc['size']}, "
                          f"dtype={desc['dtype_name']}, "
                          f"scale={desc['scale']}, bias={desc['bias']}\n")
                out.write(f"  Axis ptr: 0x{desc['axis_ptr']:06X}, "
                          f"Data ptr: 0x{desc['data_ptr']:06X}\n")

            # Find code refs
            refs = find_movl_pc_refs(desc_addr)
            if not refs:
                out.write(f"  No mov.l references found\n")
                raw_refs = find_u32_refs(desc_addr)
                if raw_refs:
                    out.write(f"  Raw u32 at: {', '.join(f'0x{a:06X}' for a in raw_refs)}\n")
            else:
                out.write(f"  Found {len(refs)} code reference(s):\n")
                for pc, reg, pool in refs:
                    out.write(f"    0x{pc:06X}: mov.l -> R{reg} (pool at 0x{pool:06X})\n")
                    region_start = max(0, (pc - 80) & ~1)
                    region_count = 100
                    avcs_code_regions.append((region_start, region_start + region_count * 2))
                    out.write(f"\n  Disassembly around 0x{pc:06X}:\n")
                    out.write(f"  {'='*70}\n")
                    disasm_range(region_start, region_count, out)
                    out.write("\n")

        # ==================================================================
        # PART 3: Decode AVCS Duty Correction Tables
        # ==================================================================
        out.write("=" * 78 + "\n")
        out.write("PART 3: AVCS DUTY CORRECTION TABLES (Fully Decoded)\n")
        out.write("=" * 78 + "\n\n")

        # --- Intake Duty Correction ---
        out.write("--- AVCS Intake Duty Correction ---\n")
        out.write("  Descriptor: 0xAD620 (2D, uint8, 10x9, scale=0.2)\n")
        out.write("  Y-axis (VVT Error, 10 floats @ 0xCF9EC): ")
        y_intake = read_axis(0xCF9EC, 10)
        out.write(", ".join(f"{v:.1f}" for v in y_intake) + "\n")
        out.write("  X-axis (RPM, 9 floats @ 0xCFA14): ")
        x_intake = read_axis(0xCFA14, 9)
        out.write(", ".join(f"{v:.0f}" for v in x_intake) + "\n")
        out.write("  Data (90 uint8 @ 0xCFA38, scale=0.2, bias=0):\n\n")

        raw_in, phys_in = read_data(0xCFA38, 90, 0x08, 0.2, 0.0)
        # Reshape
        data_in_2d = []
        for ri in range(10):
            row = phys_in[ri*9:(ri+1)*9]
            data_in_2d.append(row)
        out.write("  " + format_2d_table(y_intake, x_intake, data_in_2d, "Intake Duty Corr (%)") + "\n\n")

        # Also show raw values
        out.write("  Raw uint8 values:\n")
        hdr = f"{'':>10s}"
        for xv in x_intake:
            hdr += f"{xv:>8.0f}"
        out.write("  " + hdr + "\n")
        out.write("  " + "-" * len(hdr) + "\n")
        for ri, yv in enumerate(y_intake):
            row = f"{yv:>10.1f}"
            for ci in range(9):
                row += f"{raw_in[ri*9+ci]:>8d}"
            out.write("  " + row + "\n")
        out.write("\n")

        # --- Exhaust Duty Correction ---
        out.write("--- AVCS Exhaust Duty Correction ---\n")
        out.write("  Descriptor: 0xAD848 (2D, uint16, 10x9, scale=0.000061, bias=-100)\n")
        y_exh = read_axis(0xD11D0, 10)
        out.write("  Y-axis (VVT Error, 10 floats @ 0xD11D0): ")
        out.write(", ".join(f"{v:.1f}" for v in y_exh) + "\n")
        x_exh = read_axis(0xD11F8, 9)
        out.write("  X-axis (RPM, 9 floats @ 0xD11F8): ")
        out.write(", ".join(f"{v:.0f}" for v in x_exh) + "\n")
        out.write("  Data (90 uint16 @ 0xD121C, scale=0.000061, bias=-100):\n\n")

        raw_ex, phys_ex = read_data(0xD121C, 90, 0x0A, 0.000061, -100.0)
        data_ex_2d = []
        for ri in range(10):
            row = phys_ex[ri*9:(ri+1)*9]
            data_ex_2d.append(row)
        out.write("  " + format_2d_table(y_exh, x_exh, data_ex_2d, "Exhaust Duty Corr (%)") + "\n\n")

        # Raw u16 values
        out.write("  Raw uint16 values:\n")
        hdr = f"{'':>10s}"
        for xv in x_exh:
            hdr += f"{xv:>8.0f}"
        out.write("  " + hdr + "\n")
        out.write("  " + "-" * len(hdr) + "\n")
        for ri, yv in enumerate(y_exh):
            row = f"{yv:>10.1f}"
            for ci in range(9):
                row += f"{raw_ex[ri*9+ci]:>8d}"
            out.write("  " + row + "\n")
        out.write("\n")

        # ==================================================================
        # PART 4: Decode VVT Error Tables
        # ==================================================================
        out.write("=" * 78 + "\n")
        out.write("PART 4: VVT ERROR TABLES (Decoded)\n")
        out.write("=" * 78 + "\n\n")

        for desc_addr, desc_name in vvt_err_descs.items():
            out.write(f"--- {desc_name} @ 0x{desc_addr:06X} ---\n")
            b3 = rom[desc_addr + 3]
            if b3 != 0:
                desc = parse_2d_desc(desc_addr)
                out.write(f"  2D table: {desc['rows']}x{desc['cols']}, "
                          f"type={desc['dtype_name']}, "
                          f"scale={desc['scale']:.6f}, bias={desc['bias']:.2f}\n")
                y = read_axis(desc['y_ptr'], desc['rows'])
                x = read_axis(desc['x_ptr'], desc['cols'])
                out.write(f"  Y-axis @ 0x{desc['y_ptr']:06X}: {', '.join(f'{v:.2f}' for v in y)}\n")
                out.write(f"  X-axis @ 0x{desc['x_ptr']:06X}: {', '.join(f'{v:.2f}' for v in x)}\n")
                raw, phys = read_data(desc['d_ptr'], desc['rows']*desc['cols'],
                                      desc['dtype'], desc['scale'], desc['bias'])
                data_2d = []
                for ri in range(desc['rows']):
                    data_2d.append(phys[ri*desc['cols']:(ri+1)*desc['cols']])
                out.write("  Data @ 0x{:06X}:\n".format(desc['d_ptr']))
                out.write("  " + format_2d_table(y, x, data_2d, desc_name) + "\n\n")
            else:
                desc = parse_1d_desc(desc_addr)
                out.write(f"  1D table: size={desc['size']}, "
                          f"type={desc['dtype_name']}, "
                          f"scale={desc['scale']:.6f}, bias={desc['bias']:.2f}\n")
                axis = read_axis(desc['axis_ptr'], desc['size'])
                out.write(f"  Axis @ 0x{desc['axis_ptr']:06X}: {', '.join(f'{v:.2f}' for v in axis)}\n")
                raw, phys = read_data(desc['data_ptr'], desc['size'],
                                      desc['dtype'], desc['scale'], desc['bias'])
                out.write(f"  Data @ 0x{desc['data_ptr']:06X}:\n")
                for i in range(desc['size']):
                    out.write(f"    [{i:2d}] axis={axis[i]:10.2f}  raw={raw[i]:6d}  phys={phys[i]:10.4f}\n")
                out.write("\n")

        # ==================================================================
        # PART 5: AVCS-related RAM address search
        # ==================================================================
        out.write("=" * 78 + "\n")
        out.write("PART 5: AVCS-RELATED RAM AND CAL REFERENCES\n")
        out.write("=" * 78 + "\n\n")

        # Collect all literal pool values from AVCS code regions
        out.write("--- RAM addresses (0xFFFF4xxx range) near AVCS code ---\n\n")
        avcs_ram_refs = set()
        avcs_io_refs = set()
        avcs_cal_refs = set()

        for region_start, region_end in avcs_code_regions:
            lits = collect_literals(region_start, (region_end - region_start) // 2)
            for la in sorted(lits.keys()):
                pa, val, reg = lits[la]
                if 0xFFFF4000 <= val <= 0xFFFF4FFF:
                    avcs_ram_refs.add((val, la))
                if 0xFFFF0000 <= val <= 0xFFFFFFFF:
                    avcs_ram_refs.add((val, la))
                if 0xFFFE0000 <= val < 0xFFFF0000:
                    avcs_io_refs.add((val, la))
                if 0x000C0000 <= val <= 0x000D3000:
                    avcs_cal_refs.add((val, la))

        # Sort and deduplicate by value
        ram_by_addr = {}
        for val, la in avcs_ram_refs:
            if val not in ram_by_addr:
                ram_by_addr[val] = []
            ram_by_addr[val].append(la)

        for val in sorted(ram_by_addr.keys()):
            refs_list = ram_by_addr[val]
            out.write(f"  RAM 0x{val:08X}  referenced from: {', '.join(f'0x{a:06X}' for a in refs_list[:5])}\n")

        out.write(f"\n  Total unique RAM addresses found in AVCS regions: {len(ram_by_addr)}\n\n")

        # Cal references
        out.write("--- Calibration data references (0xCxxxx-0xD2xxx range) ---\n\n")
        cal_by_addr = {}
        for val, la in avcs_cal_refs:
            if val not in cal_by_addr:
                cal_by_addr[val] = []
            cal_by_addr[val].append(la)

        for val in sorted(cal_by_addr.keys()):
            refs_list = cal_by_addr[val]
            ann = ""
            try:
                fv = r_f32(val)
                if not math.isnan(fv) and abs(fv) < 1e12:
                    ann = f"  (float={fv})"
            except: pass
            out.write(f"  CAL 0x{val:06X}{ann}  referenced from: {', '.join(f'0x{a:06X}' for a in refs_list[:5])}\n")

        out.write(f"\n  Total unique cal addresses: {len(cal_by_addr)}\n\n")

        # Also search for specific AVCS cal ranges used broadly
        out.write("--- Broader ROM search for AVCS cal data pointers ---\n\n")
        avcs_cal_ranges = [
            (0x0CF9EC, "Intake VVT Error Y-axis"),
            (0x0CFA14, "Intake RPM X-axis"),
            (0x0CFA38, "Intake Duty Corr data"),
            (0x0D11D0, "Exhaust VVT Error Y-axis"),
            (0x0D11F8, "Exhaust RPM X-axis"),
            (0x0D121C, "Exhaust Duty Corr data"),
        ]
        for target, name in avcs_cal_ranges:
            refs = find_movl_pc_refs(target)
            out.write(f"  0x{target:06X} ({name}):\n")
            if refs:
                for pc, reg, pool in refs:
                    out.write(f"    mov.l at 0x{pc:06X} -> R{reg} (pool 0x{pool:06X})\n")
            else:
                # Check raw u32
                raw = find_u32_refs(target)
                if raw:
                    out.write(f"    Raw u32 at: {', '.join(f'0x{a:06X}' for a in raw)}\n")
                else:
                    out.write(f"    Not referenced directly\n")

        out.write("\n")

        # ==================================================================
        # PART 6: Search for AVCS Target Angle Tables
        # ==================================================================
        out.write("=" * 78 + "\n")
        out.write("PART 6: AVCS TARGET ANGLE TABLE SEARCH\n")
        out.write("=" * 78 + "\n\n")

        out.write("Scanning descriptor region 0xAA000-0xB0000 for 2D descriptors\n")
        out.write("with data pointers in 0xCF000-0xD2000 and dimensions >= 10x10...\n\n")

        found_target_tables = []
        for scan_addr in range(0xAA000, 0xB0000, 4):
            if scan_addr + 28 > ROM_LEN:
                break
            b0 = rom[scan_addr]
            rows = rom[scan_addr + 1]
            b2 = rom[scan_addr + 2]
            cols = rom[scan_addr + 3]

            if b0 != 0 or b2 != 0:
                continue
            if rows < 10 or rows > 40 or cols < 10 or cols > 40:
                continue

            y_ptr = r_u32(scan_addr + 4)
            x_ptr = r_u32(scan_addr + 8)
            d_ptr = r_u32(scan_addr + 12)
            dtype = rom[scan_addr + 16]

            if not is_rom_ptr(y_ptr) or not is_rom_ptr(x_ptr) or not is_rom_ptr(d_ptr):
                continue
            if dtype not in TYPE_NAMES:
                continue

            # Check data pointer range
            if not (0x0CF000 <= d_ptr <= 0x0D2000):
                continue

            scale = r_f32(scan_addr + 20)
            bias = r_f32(scan_addr + 24)
            if math.isnan(scale) or math.isnan(bias):
                continue

            # Validate axes
            try:
                y_ax = read_axis(y_ptr, rows)
                x_ax = read_axis(x_ptr, cols)
                # Check axes are plausible
                if any(math.isnan(v) or abs(v) > 1e8 for v in y_ax + x_ax):
                    continue
            except:
                continue

            found_target_tables.append({
                "addr": scan_addr, "rows": rows, "cols": cols,
                "y_ptr": y_ptr, "x_ptr": x_ptr, "d_ptr": d_ptr,
                "dtype": dtype, "scale": scale, "bias": bias,
                "y_ax": y_ax, "x_ax": x_ax,
            })

        if not found_target_tables:
            out.write("  No large 2D tables found with data in AVCS cal range.\n")
            out.write("  Expanding search to include dimensions >= 8x8 and data range 0xC0000-0xD5000...\n\n")

            for scan_addr in range(0xAA000, 0xB0000, 4):
                if scan_addr + 28 > ROM_LEN:
                    break
                b0 = rom[scan_addr]
                rows = rom[scan_addr + 1]
                b2 = rom[scan_addr + 2]
                cols = rom[scan_addr + 3]

                if b0 != 0 or b2 != 0:
                    continue
                if rows < 8 or rows > 40 or cols < 8 or cols > 40:
                    continue

                y_ptr = r_u32(scan_addr + 4)
                x_ptr = r_u32(scan_addr + 8)
                d_ptr = r_u32(scan_addr + 12)
                dtype = rom[scan_addr + 16]

                if not is_rom_ptr(y_ptr) or not is_rom_ptr(x_ptr) or not is_rom_ptr(d_ptr):
                    continue
                if dtype not in TYPE_NAMES:
                    continue

                if not (0x0C0000 <= d_ptr <= 0x0D5000):
                    continue

                scale = r_f32(scan_addr + 20)
                bias = r_f32(scan_addr + 24)
                if math.isnan(scale) or math.isnan(bias):
                    continue

                try:
                    y_ax = read_axis(y_ptr, rows)
                    x_ax = read_axis(x_ptr, cols)
                    if any(math.isnan(v) or abs(v) > 1e8 for v in y_ax + x_ax):
                        continue
                except:
                    continue

                found_target_tables.append({
                    "addr": scan_addr, "rows": rows, "cols": cols,
                    "y_ptr": y_ptr, "x_ptr": x_ptr, "d_ptr": d_ptr,
                    "dtype": dtype, "scale": scale, "bias": bias,
                    "y_ax": y_ax, "x_ax": x_ax,
                })

        out.write(f"  Found {len(found_target_tables)} candidate table(s):\n\n")

        for tbl in found_target_tables:
            out.write(f"  Descriptor @ 0x{tbl['addr']:06X}: {tbl['rows']}x{tbl['cols']}, "
                      f"dtype={TYPE_NAMES.get(tbl['dtype'],'?')}, "
                      f"scale={tbl['scale']:.6f}, bias={tbl['bias']:.2f}\n")
            out.write(f"    Y-axis @ 0x{tbl['y_ptr']:06X}: {', '.join(f'{v:.1f}' for v in tbl['y_ax'][:15])}"
                      + ("..." if len(tbl['y_ax']) > 15 else "") + "\n")
            out.write(f"    X-axis @ 0x{tbl['x_ptr']:06X}: {', '.join(f'{v:.1f}' for v in tbl['x_ax'][:15])}"
                      + ("..." if len(tbl['x_ax']) > 15 else "") + "\n")
            out.write(f"    Data   @ 0x{tbl['d_ptr']:06X}\n")

            # Check if axes look like RPM x Load
            has_rpm = any(v > 500 for v in tbl['x_ax']) or any(v > 500 for v in tbl['y_ax'])
            if has_rpm:
                out.write(f"    ** Axes contain values > 500, may be RPM axis **\n")

            # Decode and print table if not too large
            if tbl['rows'] * tbl['cols'] <= 400:
                raw, phys = read_data(tbl['d_ptr'], tbl['rows'] * tbl['cols'],
                                      tbl['dtype'], tbl['scale'], tbl['bias'])
                data_2d = []
                for ri in range(tbl['rows']):
                    data_2d.append(phys[ri*tbl['cols']:(ri+1)*tbl['cols']])
                out.write("\n")

                # Determine format width
                max_val = max(abs(v) for v in phys) if phys else 1
                if max_val > 1000:
                    fmt = "{:>9.1f}"
                elif max_val > 10:
                    fmt = "{:>8.2f}"
                else:
                    fmt = "{:>8.3f}"

                out.write("  " + format_2d_table(tbl['y_ax'], tbl['x_ax'], data_2d,
                                                  f"Table @ 0x{tbl['addr']:06X}", fmt) + "\n")
            out.write("\n")

        # ==================================================================
        # PART 7: OCV Solenoid I/O and Hardware References
        # ==================================================================
        out.write("=" * 78 + "\n")
        out.write("PART 7: OCV SOLENOID I/O AND HARDWARE REFERENCES\n")
        out.write("=" * 78 + "\n\n")

        # Search for I/O addresses near AVCS code regions
        out.write("--- I/O register references (0xFFFE0000-0xFFFF0000) in AVCS code ---\n\n")

        io_by_addr = {}
        for val, la in avcs_io_refs:
            if val not in io_by_addr:
                io_by_addr[val] = []
            io_by_addr[val].append(la)

        if io_by_addr:
            for val in sorted(io_by_addr.keys()):
                refs_list = io_by_addr[val]
                # Annotate known SH7058 I/O registers
                ann = annotate_io(val)
                out.write(f"  I/O 0x{val:08X}{ann}  referenced from: "
                          f"{', '.join(f'0x{a:06X}' for a in refs_list[:5])}\n")
        else:
            out.write("  No I/O references found in initial AVCS code regions.\n")

        out.write("\n--- Broader I/O search in AVCS-adjacent code (scanning wider) ---\n\n")

        # Scan broader region around known AVCS code
        # Find function boundaries by looking at the code regions
        if avcs_code_regions:
            min_code = min(s for s, e in avcs_code_regions)
            max_code = max(e for s, e in avcs_code_regions)
            out.write(f"  AVCS code spans approximately 0x{min_code:06X} - 0x{max_code:06X}\n")

            # Expand search range
            scan_start = max(0, min_code - 0x400)
            scan_end = min(ROM_LEN, max_code + 0x400)
            scan_count = (scan_end - scan_start) // 2
            wider_lits = collect_literals(scan_start, scan_count)

            io_wider = {}
            for la in sorted(wider_lits.keys()):
                pa, val, reg = wider_lits[la]
                if 0xFFFE0000 <= val < 0xFFFF0000:
                    if val not in io_wider:
                        io_wider[val] = []
                    io_wider[val].append(la)

            for val in sorted(io_wider.keys()):
                refs_list = io_wider[val]
                ann = annotate_io(val)
                out.write(f"  I/O 0x{val:08X}{ann}  at: "
                          f"{', '.join(f'0x{a:06X}' for a in refs_list[:8])}\n")

            if not io_wider:
                out.write("  No I/O refs found in extended range either.\n")
        else:
            out.write("  No AVCS code regions identified.\n")

        # Also search for SH7058 ATU (Advanced Timer Unit) registers used for PWM
        out.write("\n--- SH7058 ATU/PWM registers (global ROM search for AVCS PWM) ---\n\n")
        # SH7058 ATU5 timer registers (typical PWM for OCV)
        atu_regs = [
            (0xFFFE4000, "ATU0 TSTR"),
            (0xFFFE4020, "ATU0 TCNT0"),
            (0xFFFE4080, "ATU1 TCNT"),
            (0xFFFE40C0, "ATU2 TCNT"),
            (0xFFFE4100, "ATU3 base"),
            (0xFFFE4140, "ATU4 base"),
            (0xFFFE4180, "ATU5 base"),
            (0xFFFE41C0, "ATU6 base"),
            (0xFFFE4200, "ATU7 base"),
            (0xFFFE4240, "ATU8 base"),
            (0xFFFE4280, "ATU9 base"),
            (0xFFFE42C0, "ATU10 base"),
            (0xFFFE4300, "ATU11 base"),
            (0xFFFE6800, "CMT base"),
            (0xFFFE6000, "MTU2 base"),
        ]

        # Broader: search for any 0xFFFE4xxx reference in the ROM
        out.write("  Searching ROM for timer I/O references (0xFFFE4000-0xFFFE4400)...\n")
        timer_refs = {}
        for a in range(0, ROM_LEN - 3, 4):
            val = r_u32(a)
            if 0xFFFE4000 <= val <= 0xFFFE4400:
                if val not in timer_refs:
                    timer_refs[val] = []
                if len(timer_refs[val]) < 10:
                    timer_refs[val].append(a)

        for val in sorted(timer_refs.keys()):
            refs = timer_refs[val]
            ann = annotate_io(val)
            out.write(f"    Timer I/O 0x{val:08X}{ann}: {len(refs)} ref(s)\n")
            # Show refs that are in or near AVCS code
            for r in refs:
                near_avcs = any(abs(r - s) < 0x1000 or abs(r - e) < 0x1000
                               for s, e in avcs_code_regions)
                if near_avcs:
                    out.write(f"      ** NEAR AVCS CODE: 0x{r:06X}\n")

        # Search for port output data registers (OCV solenoid output)
        out.write("\n  Searching ROM for port I/O (0xFFFE3800-0xFFFE3900)...\n")
        port_refs = {}
        for a in range(0, ROM_LEN - 3, 4):
            val = r_u32(a)
            if 0xFFFE3800 <= val <= 0xFFFE3900:
                if val not in port_refs:
                    port_refs[val] = []
                if len(port_refs[val]) < 10:
                    port_refs[val].append(a)

        for val in sorted(port_refs.keys()):
            refs = port_refs[val]
            ann = annotate_io(val)
            out.write(f"    Port I/O 0x{val:08X}{ann}: {len(refs)} ref(s)\n")
            for r in refs:
                near_avcs = any(abs(r - s) < 0x1000 or abs(r - e) < 0x1000
                               for s, e in avcs_code_regions)
                if near_avcs:
                    out.write(f"      ** NEAR AVCS CODE: 0x{r:06X}\n")

        out.write("\n")

        # ==================================================================
        # Summary
        # ==================================================================
        out.write("=" * 78 + "\n")
        out.write("SUMMARY\n")
        out.write("=" * 78 + "\n\n")
        out.write(f"AVCS code regions found: {len(avcs_code_regions)}\n")
        for s, e in avcs_code_regions:
            out.write(f"  0x{s:06X} - 0x{e:06X}\n")
        out.write(f"\nUnique RAM addresses in AVCS code: {len(ram_by_addr)}\n")
        out.write(f"Unique I/O addresses in AVCS code: {len(io_by_addr)}\n")
        out.write(f"Unique cal addresses in AVCS code: {len(cal_by_addr)}\n")
        out.write(f"Candidate target angle tables found: {len(found_target_tables)}\n")

    print(f"Output written to: {OUTPUT_PATH}")


def annotate_io(addr):
    """Annotate known SH7058 I/O register addresses."""
    # SH7058F I/O register map (simplified)
    io_map = {
        # Port Data Registers
        0xFFFE3802: " (PADRL - Port A Data)",
        0xFFFE3804: " (PAIORL - Port A I/O)",
        0xFFFE3812: " (PBDRL - Port B Data)",
        0xFFFE3814: " (PBIORL - Port B I/O)",
        0xFFFE3822: " (PCDRL - Port C Data)",
        0xFFFE3832: " (PDDRL - Port D Data)",
        0xFFFE3842: " (PEDRL - Port E Data)",
        0xFFFE3852: " (PFDRL - Port F Data)",
        # ATU registers
        0xFFFE4000: " (ATU TSTR - Timer Start)",
        0xFFFE4004: " (ATU TSTR2)",
    }

    # Check exact match
    if addr in io_map:
        return io_map[addr]

    # Range-based annotations
    if 0xFFFE3800 <= addr < 0xFFFE3900:
        port_num = (addr - 0xFFFE3800) // 0x10
        port_names = "ABCDEFGHJK"
        if port_num < len(port_names):
            offset = (addr - 0xFFFE3800) % 0x10
            return f" (Port {port_names[port_num]} +0x{offset:X})"
    if 0xFFFE4000 <= addr < 0xFFFE4400:
        return f" (ATU Timer +0x{addr - 0xFFFE4000:03X})"
    if 0xFFFE6000 <= addr < 0xFFFE6100:
        return f" (MTU2 +0x{addr - 0xFFFE6000:03X})"
    if 0xFFFE6800 <= addr < 0xFFFE6900:
        return f" (CMT +0x{addr - 0xFFFE6800:03X})"
    if 0xFFFE8000 <= addr < 0xFFFE8100:
        return f" (SCI0 +0x{addr - 0xFFFE8000:03X})"
    if 0xFFFE8800 <= addr < 0xFFFE8900:
        return f" (SCI1 +0x{addr - 0xFFFE8800:03X})"
    if 0xFFFEC000 <= addr < 0xFFFEC100:
        return f" (A/D +0x{addr - 0xFFFEC000:03X})"

    return ""


if __name__ == "__main__":
    main()
