#!/usr/bin/env python3
"""
DTC/Diagnostic system analysis for AE5L600L ROM.
Extracts calibration thresholds, disassembles helper functions,
and searches for DTC-related references.
"""
import struct
import sys
import os

ROM_PATH = r"C:\Users\Dean\Documents\GitHub\ae6l600l\rom\ae5l600l.bin"
OUT_PATH = r"C:\Users\Dean\Documents\GitHub\ae6l600l\disassembly\analysis\dtc_helpers_raw.txt"

# Force UTF-8 stdout
sys.stdout.reconfigure(encoding='utf-8')

rom = open(ROM_PATH, 'rb').read()

def read_float_be(offset):
    return struct.unpack('>f', rom[offset:offset+4])[0]

def read_u16(offset):
    return struct.unpack('>H', rom[offset:offset+2])[0]

def read_u32(offset):
    return struct.unpack('>I', rom[offset:offset+4])[0]

def read_i8(val):
    """Sign-extend 8-bit value."""
    if val & 0x80:
        return val - 256
    return val

def read_i12(val):
    """Sign-extend 12-bit value."""
    if val & 0x800:
        return val - 4096
    return val

# SH2 register names
def rn(n):
    return f"R{n}"

def disasm_one(addr):
    """Disassemble a single SH-2 instruction at addr. Returns (mnemonic, length)."""
    if addr + 2 > len(rom):
        return f".word 0x????", 2

    insn = read_u16(addr)
    hi4 = (insn >> 12) & 0xF
    lo4 = insn & 0xF
    lo8 = insn & 0xFF
    n = (insn >> 8) & 0xF
    m = (insn >> 4) & 0xF

    # Group 0
    if insn == 0x0009:
        return "nop", 2
    if insn == 0x000B:
        return "rts", 2
    if insn == 0x0008:
        return "clrt", 2
    if insn == 0x0018:
        return "sett", 2
    if insn == 0x0019:
        return "div0u", 2
    if insn == 0x001B:
        return "sleep", 2
    if insn == 0x002B:
        return "rte", 2

    if hi4 == 0x0:
        if lo4 == 0x2:
            mid = (insn >> 4) & 0xF
            if mid == 0x0:
                return f"stc    SR, {rn(n)}", 2
            if mid == 0x1:
                return f"stc    GBR, {rn(n)}", 2
            if mid == 0x2:
                return f"stc    VBR, {rn(n)}", 2
        if lo4 == 0x3:
            if m == 0x0:
                return f"bsrf   {rn(n)}", 2
            if m == 0x2:
                return f"braf   {rn(n)}", 2
        if lo4 == 0x4:
            return f"mov.b  {rn(m)}, @(R0,{rn(n)})", 2
        if lo4 == 0x5:
            return f"mov.w  {rn(m)}, @(R0,{rn(n)})", 2
        if lo4 == 0x6:
            return f"mov.l  {rn(m)}, @(R0,{rn(n)})", 2
        if lo4 == 0x7:
            return f"mul.l  {rn(m)}, {rn(n)}", 2
        if lo4 == 0xC:
            return f"mov.b  @(R0,{rn(m)}), {rn(n)}", 2
        if lo4 == 0xD:
            return f"mov.w  @(R0,{rn(m)}), {rn(n)}", 2
        if lo4 == 0xE:
            return f"mov.l  @(R0,{rn(m)}), {rn(n)}", 2
        if lo4 == 0xF:
            return f"mac.l  @{rn(m)}+, @{rn(n)}+", 2

    # Group 1: mov.l Rm, @(disp,Rn)
    if hi4 == 0x1:
        disp = lo4 * 4
        return f"mov.l  {rn(m)}, @({disp},{rn(n)})", 2

    # Group 2
    if hi4 == 0x2:
        if lo4 == 0x0:
            return f"mov.b  {rn(m)}, @{rn(n)}", 2
        if lo4 == 0x1:
            return f"mov.w  {rn(m)}, @{rn(n)}", 2
        if lo4 == 0x2:
            return f"mov.l  {rn(m)}, @{rn(n)}", 2
        if lo4 == 0x4:
            return f"mov.b  {rn(m)}, @-{rn(n)}", 2
        if lo4 == 0x5:
            return f"mov.w  {rn(m)}, @-{rn(n)}", 2
        if lo4 == 0x6:
            return f"mov.l  {rn(m)}, @-{rn(n)}", 2
        if lo4 == 0x7:
            return f"div0s  {rn(m)}, {rn(n)}", 2
        if lo4 == 0x8:
            return f"tst    {rn(m)}, {rn(n)}", 2
        if lo4 == 0x9:
            return f"and    {rn(m)}, {rn(n)}", 2
        if lo4 == 0xA:
            return f"xor    {rn(m)}, {rn(n)}", 2
        if lo4 == 0xB:
            return f"or     {rn(m)}, {rn(n)}", 2
        if lo4 == 0xC:
            return f"cmp/str {rn(m)}, {rn(n)}", 2
        if lo4 == 0xD:
            return f"xtrct  {rn(m)}, {rn(n)}", 2
        if lo4 == 0xE:
            return f"mulu.w {rn(m)}, {rn(n)}", 2
        if lo4 == 0xF:
            return f"muls.w {rn(m)}, {rn(n)}", 2

    # Group 3
    if hi4 == 0x3:
        if lo4 == 0x0:
            return f"cmp/eq {rn(m)}, {rn(n)}", 2
        if lo4 == 0x2:
            return f"cmp/hs {rn(m)}, {rn(n)}", 2
        if lo4 == 0x3:
            return f"cmp/ge {rn(m)}, {rn(n)}", 2
        if lo4 == 0x4:
            return f"div1   {rn(m)}, {rn(n)}", 2
        if lo4 == 0x5:
            return f"dmulu.l {rn(m)}, {rn(n)}", 2
        if lo4 == 0x6:
            return f"cmp/hi {rn(m)}, {rn(n)}", 2
        if lo4 == 0x7:
            return f"cmp/gt {rn(m)}, {rn(n)}", 2
        if lo4 == 0x8:
            return f"sub    {rn(m)}, {rn(n)}", 2
        if lo4 == 0xA:
            return f"subc   {rn(m)}, {rn(n)}", 2
        if lo4 == 0xB:
            return f"subv   {rn(m)}, {rn(n)}", 2
        if lo4 == 0xC:
            return f"add    {rn(m)}, {rn(n)}", 2
        if lo4 == 0xD:
            return f"dmuls.l {rn(m)}, {rn(n)}", 2
        if lo4 == 0xE:
            return f"addc   {rn(m)}, {rn(n)}", 2
        if lo4 == 0xF:
            return f"addv   {rn(m)}, {rn(n)}", 2

    # Group 4
    if hi4 == 0x4:
        if lo8 == 0x0B:
            return f"jsr    @{rn(n)}", 2
        if lo8 == 0x2B:
            return f"jmp    @{rn(n)}", 2
        if lo4 == 0x0:
            if m == 0x0:
                return f"shll   {rn(n)}", 2
            if m == 0x1:
                return f"dt     {rn(n)}", 2
            if m == 0x2:
                return f"shal   {rn(n)}", 2
        if lo4 == 0x1:
            if m == 0x0:
                return f"shlr   {rn(n)}", 2
            if m == 0x1:
                return f"cmp/pz {rn(n)}", 2
            if m == 0x2:
                return f"shar   {rn(n)}", 2
        if lo4 == 0x2:
            if m == 0x0:
                return f"sts.l  MACH, @-{rn(n)}", 2
            if m == 0x1:
                return f"sts.l  MACL, @-{rn(n)}", 2
            if m == 0x2:
                return f"sts.l  PR, @-{rn(n)}", 2
        if lo4 == 0x4:
            if m == 0x0:
                return f"rotl   {rn(n)}", 2
            if m == 0x2:
                return f"rotcl  {rn(n)}", 2
        if lo4 == 0x5:
            if m == 0x0:
                return f"rotr   {rn(n)}", 2
            if m == 0x1:
                return f"cmp/pl {rn(n)}", 2
            if m == 0x2:
                return f"rotcr  {rn(n)}", 2
        if lo4 == 0x6:
            if m == 0x0:
                return f"lds.l  @{rn(n)}+, MACH", 2
            if m == 0x1:
                return f"lds.l  @{rn(n)}+, MACL", 2
            if m == 0x2:
                return f"lds.l  @{rn(n)}+, PR", 2
        if lo4 == 0x8:
            if m == 0x0:
                return f"shll2  {rn(n)}", 2
            if m == 0x1:
                return f"shll8  {rn(n)}", 2
            if m == 0x2:
                return f"shll16 {rn(n)}", 2
        if lo4 == 0x9:
            if m == 0x0:
                return f"shlr2  {rn(n)}", 2
            if m == 0x1:
                return f"shlr8  {rn(n)}", 2
            if m == 0x2:
                return f"shlr16 {rn(n)}", 2
        if lo4 == 0xA:
            if m == 0x0:
                return f"lds    {rn(n)}, MACH", 2
            if m == 0x1:
                return f"lds    {rn(n)}, MACL", 2
            if m == 0x2:
                return f"lds    {rn(n)}, PR", 2
        if lo4 == 0xE:
            if m == 0x0:
                return f"ldc    {rn(n)}, SR", 2
            if m == 0x1:
                return f"ldc    {rn(n)}, GBR", 2
            if m == 0x2:
                return f"ldc    {rn(n)}, VBR", 2
        if lo4 == 0xC:
            return f"shad   {rn(m)}, {rn(n)}", 2
        if lo4 == 0xD:
            return f"shld   {rn(m)}, {rn(n)}", 2
        if lo4 == 0xF:
            return f"mac.w  @{rn(m)}+, @{rn(n)}+", 2
        if lo4 == 0x7:
            if m == 0x0:
                return f"ldc.l  @{rn(n)}+, SR", 2
            if m == 0x1:
                return f"ldc.l  @{rn(n)}+, GBR", 2
            if m == 0x2:
                return f"ldc.l  @{rn(n)}+, VBR", 2
        if lo4 == 0x3:
            if m == 0x0:
                return f"stc.l  SR, @-{rn(n)}", 2
            if m == 0x1:
                return f"stc.l  GBR, @-{rn(n)}", 2
            if m == 0x2:
                return f"stc.l  VBR, @-{rn(n)}", 2

    # Group 5: mov.l @(disp,Rm), Rn
    if hi4 == 0x5:
        disp = lo4 * 4
        return f"mov.l  @({disp},{rn(m)}), {rn(n)}", 2

    # Group 6
    if hi4 == 0x6:
        if lo4 == 0x0:
            return f"mov.b  @{rn(m)}, {rn(n)}", 2
        if lo4 == 0x1:
            return f"mov.w  @{rn(m)}, {rn(n)}", 2
        if lo4 == 0x2:
            return f"mov.l  @{rn(m)}, {rn(n)}", 2
        if lo4 == 0x3:
            return f"mov    {rn(m)}, {rn(n)}", 2
        if lo4 == 0x4:
            return f"mov.b  @{rn(m)}+, {rn(n)}", 2
        if lo4 == 0x5:
            return f"mov.w  @{rn(m)}+, {rn(n)}", 2
        if lo4 == 0x6:
            return f"mov.l  @{rn(m)}+, {rn(n)}", 2
        if lo4 == 0x7:
            return f"not    {rn(m)}, {rn(n)}", 2
        if lo4 == 0x8:
            return f"swap.b {rn(m)}, {rn(n)}", 2
        if lo4 == 0x9:
            return f"swap.w {rn(m)}, {rn(n)}", 2
        if lo4 == 0xA:
            return f"negc   {rn(m)}, {rn(n)}", 2
        if lo4 == 0xB:
            return f"neg    {rn(m)}, {rn(n)}", 2
        if lo4 == 0xC:
            return f"extu.b {rn(m)}, {rn(n)}", 2
        if lo4 == 0xD:
            return f"extu.w {rn(m)}, {rn(n)}", 2
        if lo4 == 0xE:
            return f"exts.b {rn(m)}, {rn(n)}", 2
        if lo4 == 0xF:
            return f"exts.w {rn(m)}, {rn(n)}", 2

    # Group 7: add #imm, Rn
    if hi4 == 0x7:
        imm = read_i8(lo8)
        return f"add    #{imm}, {rn(n)}", 2

    # Group 8
    if hi4 == 0x8:
        if n == 0x0:
            disp = lo4
            return f"mov.b  R0, @({disp},{rn(m)})", 2
        if n == 0x1:
            disp = lo4 * 2
            return f"mov.w  R0, @({disp},{rn(m)})", 2
        if n == 0x4:
            disp = lo4
            return f"mov.b  @({disp},{rn(m)}), R0", 2
        if n == 0x5:
            disp = lo4 * 2
            return f"mov.w  @({disp},{rn(m)}), R0", 2
        if n == 0x8:
            imm = lo8
            return f"cmp/eq #{read_i8(imm)}, R0", 2
        if n == 0x9:
            disp = read_i8(lo8)
            target = addr + 4 + disp * 2
            return f"bt     0x{target:08X}", 2
        if n == 0xB:
            disp = read_i8(lo8)
            target = addr + 4 + disp * 2
            return f"bf     0x{target:08X}", 2
        if n == 0xD:
            disp = read_i8(lo8)
            target = addr + 4 + disp * 2
            return f"bt/s   0x{target:08X}", 2
        if n == 0xF:
            disp = read_i8(lo8)
            target = addr + 4 + disp * 2
            return f"bf/s   0x{target:08X}", 2

    # Group 9: mov.w @(disp,PC), Rn
    if hi4 == 0x9:
        disp = lo8 * 2
        ref_addr = (addr & ~1) + 4 + disp
        if ref_addr + 2 <= len(rom):
            val = read_u16(ref_addr)
            return f"mov.w  @(0x{ref_addr:08X}), {rn(n)}  ; =0x{val:04X} ({val})", 2
        return f"mov.w  @(0x{ref_addr:08X}), {rn(n)}", 2

    # Group A: bra
    if hi4 == 0xA:
        disp = insn & 0xFFF
        disp = read_i12(disp)
        target = addr + 4 + disp * 2
        return f"bra    0x{target:08X}", 2

    # Group B: bsr
    if hi4 == 0xB:
        disp = insn & 0xFFF
        disp = read_i12(disp)
        target = addr + 4 + disp * 2
        return f"bsr    0x{target:08X}", 2

    # Group C
    if hi4 == 0xC:
        if n == 0x0:
            return f"mov.b  R0, @({lo8},GBR)", 2
        if n == 0x1:
            return f"mov.w  R0, @({lo8*2},GBR)", 2
        if n == 0x2:
            return f"mov.l  R0, @({lo8*4},GBR)", 2
        if n == 0x3:
            return f"trapa  #{lo8}", 2
        if n == 0x4:
            return f"mov.b  @({lo8},GBR), R0", 2
        if n == 0x5:
            return f"mov.w  @({lo8*2},GBR), R0", 2
        if n == 0x6:
            return f"mov.l  @({lo8*4},GBR), R0", 2
        if n == 0x7:
            ref_addr = (addr & ~1) + 4 + lo8 * 2
            if ref_addr + 2 <= len(rom):
                val = read_u16(ref_addr)
                return f"mova   @(0x{ref_addr:08X}), R0  ; =0x{val:04X}", 2
            return f"mova   @(0x{ref_addr:08X}), R0", 2
        if n == 0x8:
            return f"tst    #0x{lo8:02X}, R0", 2
        if n == 0x9:
            return f"and    #0x{lo8:02X}, R0", 2
        if n == 0xA:
            return f"xor    #0x{lo8:02X}, R0", 2
        if n == 0xB:
            return f"or     #0x{lo8:02X}, R0", 2
        if n == 0xC:
            return f"tst.b  #0x{lo8:02X}, @(R0,GBR)", 2
        if n == 0xD:
            return f"and.b  #0x{lo8:02X}, @(R0,GBR)", 2
        if n == 0xE:
            return f"xor.b  #0x{lo8:02X}, @(R0,GBR)", 2
        if n == 0xF:
            return f"or.b   #0x{lo8:02X}, @(R0,GBR)", 2

    # Group D: mov.l @(disp,PC), Rn
    if hi4 == 0xD:
        disp = lo8 * 4
        ref_addr = (addr & ~1) + 4 + disp
        if ref_addr + 4 <= len(rom):
            val = read_u32(ref_addr)
            return f"mov.l  @(0x{ref_addr:08X}), {rn(n)}  ; =0x{val:08X}", 2
        return f"mov.l  @(0x{ref_addr:08X}), {rn(n)}", 2

    # Group E: mov #imm, Rn
    if hi4 == 0xE:
        imm = read_i8(lo8)
        return f"mov    #{imm}, {rn(n)}", 2

    # Group F (FPU - just show raw)
    if hi4 == 0xF:
        return f".word  0x{insn:04X}  ; FPU/unknown", 2

    return f".word  0x{insn:04X}", 2


def disasm_block(start_addr, count, out):
    """Disassemble 'count' instructions starting at start_addr."""
    addr = start_addr
    for i in range(count):
        if addr + 2 > len(rom):
            break
        raw = read_u16(addr)
        mnem, sz = disasm_one(addr)
        out.append(f"  0x{addr:08X}:  {raw:04X}  {mnem}")
        addr += sz
    return addr


def search_references_32(target_val, start=0, end=None):
    """Search ROM for 32-bit big-endian occurrences of target_val."""
    if end is None:
        end = len(rom) - 3
    target_bytes = struct.pack('>I', target_val)
    results = []
    pos = start
    while pos < end:
        pos = rom.find(target_bytes, pos, end)
        if pos == -1:
            break
        results.append(pos)
        pos += 1
    return results


# ============================================================
# Main output
# ============================================================
out = []

# --- 1. Task53 calibration thresholds ---
out.append("=" * 70)
out.append("TASK53 CALIBRATION THRESHOLDS (0x0D9A3C - 0x0D9A64)")
out.append("=" * 70)
for addr in range(0x0D9A3C, 0x0D9A68, 4):
    val = read_float_be(addr)
    raw = read_u32(addr)
    out.append(f"  0x{addr:06X}: {val:15.6f}  (raw: 0x{raw:08X})")

out.append("")
out.append("=" * 70)
out.append("TASK58 MAF DIAG THRESHOLDS")
out.append("=" * 70)
for addr in [0x0D8B14, 0x0D8B18]:
    val = read_float_be(addr)
    raw = read_u32(addr)
    out.append(f"  0x{addr:06X}: {val:15.6f}  (raw: 0x{raw:08X})")

out.append("")
out.append("=" * 70)
out.append("MAF DIAG MATURATION THRESHOLD (0x0D8A40)")
out.append("=" * 70)
addr = 0x0D8A40
val = read_float_be(addr)
raw = read_u32(addr)
out.append(f"  0x{addr:06X}: {val:15.6f}  (raw: 0x{raw:08X})")

# --- 3-6. Disassemble helper functions ---
helpers = [
    (0x0582AC, 40, "FUNCTION @ 0x0582AC (check_engine_running?)"),
    (0x0582D2, 40, "FUNCTION @ 0x0582D2 (diag helper 2)"),
    (0x0584BE, 40, "FUNCTION @ 0x0584BE (diag helper 3)"),
    (0x0584C8, 40, "FUNCTION @ 0x0584C8 (diag helper 4)"),
]

for start, count, label in helpers:
    out.append("")
    out.append("=" * 70)
    out.append(label)
    out.append("=" * 70)
    disasm_block(start, count, out)

# --- 7. Search for references to dtc_set / dtc_clear ---
out.append("")
out.append("=" * 70)
out.append("REFERENCES TO 0x0009ED90 (dtc_set_pending?)")
out.append("=" * 70)
refs = search_references_32(0x0009ED90)
for r in refs:
    out.append(f"  Found at ROM offset 0x{r:08X}")
out.append(f"  Total: {len(refs)} references")

out.append("")
out.append("=" * 70)
out.append("REFERENCES TO 0x0009EDEC (dtc_clear?)")
out.append("=" * 70)
refs = search_references_32(0x0009EDEC)
for r in refs:
    out.append(f"  Found at ROM offset 0x{r:08X}")
out.append(f"  Total: {len(refs)} references")

# --- 8-9. Disassemble dtc_set and dtc_clear ---
dtc_funcs = [
    (0x09ED90, 80, "FUNCTION @ 0x09ED90 (dtc_set_pending?)"),
    (0x09EDEC, 80, "FUNCTION @ 0x09EDEC (dtc_clear?)"),
]

for start, count, label in dtc_funcs:
    out.append("")
    out.append("=" * 70)
    out.append(label)
    out.append("=" * 70)
    disasm_block(start, count, out)

# --- 10. DTC processing loop - search for dtc_enable_flag refs ---
out.append("")
out.append("=" * 70)
out.append("REFERENCES TO 0xFFFF36F4 (dtc_enable_flag) IN 0x09E000-0x0A2000")
out.append("=" * 70)

target_bytes = struct.pack('>I', 0xFFFF36F4)
search_start = 0x09E000
search_end = 0x0A2000
pos = search_start
ref_addrs = []
while pos < search_end:
    pos = rom.find(target_bytes, pos, search_end)
    if pos == -1:
        break
    ref_addrs.append(pos)
    pos += 1

out.append(f"  Found {len(ref_addrs)} references:")
for r in ref_addrs:
    out.append(f"    0x{r:08X}")

for r in ref_addrs:
    out.append("")
    out.append("-" * 50)
    # Find which instruction references this literal pool entry.
    # The mov.l @(disp,PC), Rn instruction that loads from this address
    # must be before the literal pool entry.
    # Disassemble context: 20 instructions before and 30 total
    context_start = max(search_start, r - 20 * 2)
    # Align to 2-byte boundary
    context_start = context_start & ~1
    out.append(f"CONTEXT AROUND LITERAL 0xFFFF36F4 AT 0x{r:08X}")
    out.append(f"(Disassembling from 0x{context_start:08X})")
    out.append("-" * 50)
    disasm_block(context_start, 30, out)

# Write output
output_text = "\n".join(out) + "\n"
with open(OUT_PATH, 'w', encoding='utf-8') as f:
    f.write(output_text)

print(output_text)
print(f"\nOutput written to: {OUT_PATH}")
