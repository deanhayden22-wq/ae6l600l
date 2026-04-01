import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
"""
DTC / Diagnostic System Disassembly -- AE5L600L
Traces:
  - task53_diag_monitor @ 0x602DC
  - diag_check_status (called by task56_evap_purge and others)
  - DTC table structure @ 0x09A834
  - DTC enable flags @ 0x09A770
  - DTC RAM state machine (diag_state region)
  - MIL/CEL activation logic
"""
import struct

with open('C:/Users/Dean/Documents/GitHub/ae6l600l/rom/ae5l600l.bin', 'rb') as f:
    rom = f.read()

def u8(addr):  return rom[addr]
def u16(addr): return struct.unpack('>H', rom[addr:addr+2])[0]
def u32(addr): return struct.unpack('>I', rom[addr:addr+4])[0]
def s8(v):     return v - 256 if v > 127 else v
def s12(v):    return v - 4096 if v > 2047 else v
def flt(addr): return struct.unpack('>f', rom[addr:addr+4])[0]

def rn(n): return f"R{n}"
def frn(n): return f"FR{n}"

# ── SH-2A disassembler (subset) ──────────────────────────────────────────
def disasm_range(start, end, label=""):
    addr = start
    lines = []
    if label:
        lines.append(f"\n{'='*78}")
        lines.append(f"  {label}")
        lines.append(f"  0x{start:05X} - 0x{end:05X}")
        lines.append(f"{'='*78}")

    while addr < end and addr < len(rom) - 1:
        op = u16(addr)
        nib = [(op >> 12) & 0xF, (op >> 8) & 0xF, (op >> 4) & 0xF, op & 0xF]
        n = nib[1]; m = nib[2]; d8 = op & 0xFF; d4 = op & 0xF
        top = nib[0]
        mnem = ""; cmt = ""

        if op == 0x0009: mnem = "nop"
        elif op == 0x000B: mnem = "rts"
        elif op == 0x0019: mnem = "div0u"
        elif op == 0x0008: mnem = "clrt"
        elif op == 0x0018: mnem = "sett"
        elif op == 0x0028: mnem = "clrmac"
        elif op == 0x001B: mnem = "sleep"
        elif op == 0x0038: mnem = "ldtlb"
        elif op == 0x002B: mnem = "rte"
        elif top == 0x0:
            sub = nib[3]
            if sub == 0x2:
                ss = nib[2]
                if ss == 0: mnem = f"stc    SR,{rn(n)}"
                elif ss == 1: mnem = f"stc    GBR,{rn(n)}"
                elif ss == 2: mnem = f"stc    VBR,{rn(n)}"
            elif sub == 0x3:
                ss = nib[2]
                if ss == 0: mnem = f"bsrf   {rn(n)}"
                elif ss == 2: mnem = f"braf   {rn(n)}"
            elif sub == 0x4: mnem = f"mov.b  {rn(m)},@(R0,{rn(n)})"
            elif sub == 0x5: mnem = f"mov.w  {rn(m)},@(R0,{rn(n)})"
            elif sub == 0x6: mnem = f"mov.l  {rn(m)},@(R0,{rn(n)})"
            elif sub == 0x7: mnem = f"mul.l  {rn(m)},{rn(n)}"
            elif sub == 0xC: mnem = f"mov.b  @(R0,{rn(m)}),{rn(n)}"
            elif sub == 0xD: mnem = f"mov.w  @(R0,{rn(m)}),{rn(n)}"
            elif sub == 0xE: mnem = f"mov.l  @(R0,{rn(m)}),{rn(n)}"
        elif top == 0x1:
            d = nib[3]
            mnem = f"mov.l  {rn(m)},@({d*4},{rn(n)})"
        elif top == 0x2:
            sub = nib[3]
            if sub == 0: mnem = f"mov.b  {rn(m)},@{rn(n)}"
            elif sub == 1: mnem = f"mov.w  {rn(m)},@{rn(n)}"
            elif sub == 2: mnem = f"mov.l  {rn(m)},@{rn(n)}"
            elif sub == 4: mnem = f"mov.b  {rn(m)},@-{rn(n)}"
            elif sub == 5: mnem = f"mov.w  {rn(m)},@-{rn(n)}"
            elif sub == 6: mnem = f"mov.l  {rn(m)},@-{rn(n)}"
            elif sub == 7: mnem = f"div0s  {rn(m)},{rn(n)}"
            elif sub == 8: mnem = f"tst    {rn(m)},{rn(n)}"
            elif sub == 9: mnem = f"and    {rn(m)},{rn(n)}"
            elif sub == 0xA: mnem = f"xor    {rn(m)},{rn(n)}"
            elif sub == 0xB: mnem = f"or     {rn(m)},{rn(n)}"
            elif sub == 0xC: mnem = f"cmp/str {rn(m)},{rn(n)}"
            elif sub == 0xD: mnem = f"xtrct  {rn(m)},{rn(n)}"
            elif sub == 0xE: mnem = f"mulu.w {rn(m)},{rn(n)}"
            elif sub == 0xF: mnem = f"muls.w {rn(m)},{rn(n)}"
            elif sub == 3: mnem = f"cas.l  {rn(m)},{rn(n)},@R0"
        elif top == 0x3:
            sub = nib[3]
            if sub == 0: mnem = f"cmp/eq {rn(m)},{rn(n)}"
            elif sub == 2: mnem = f"cmp/hs {rn(m)},{rn(n)}"
            elif sub == 3: mnem = f"cmp/ge {rn(m)},{rn(n)}"
            elif sub == 4: mnem = f"div1   {rn(m)},{rn(n)}"
            elif sub == 5: mnem = f"dmulu.l {rn(m)},{rn(n)}"
            elif sub == 6: mnem = f"cmp/hi {rn(m)},{rn(n)}"
            elif sub == 7: mnem = f"cmp/gt {rn(m)},{rn(n)}"
            elif sub == 8: mnem = f"sub    {rn(m)},{rn(n)}"
            elif sub == 0xA: mnem = f"subc   {rn(m)},{rn(n)}"
            elif sub == 0xC: mnem = f"add    {rn(m)},{rn(n)}"
            elif sub == 0xD: mnem = f"dmuls.l {rn(m)},{rn(n)}"
            elif sub == 0xE: mnem = f"addc   {rn(m)},{rn(n)}"
        elif top == 0x4:
            sub = (nib[2] << 4) | nib[3]
            if sub == 0x00: mnem = f"shll   {rn(n)}"
            elif sub == 0x01: mnem = f"shlr   {rn(n)}"
            elif sub == 0x04: mnem = f"rotl   {rn(n)}"
            elif sub == 0x05: mnem = f"rotr   {rn(n)}"
            elif sub == 0x08: mnem = f"shll2  {rn(n)}"
            elif sub == 0x09: mnem = f"shlr2  {rn(n)}"
            elif sub == 0x10: mnem = f"dt     {rn(n)}"
            elif sub == 0x11: mnem = f"cmp/pz {rn(n)}"
            elif sub == 0x15: mnem = f"cmp/pl {rn(n)}"
            elif sub == 0x18: mnem = f"shll8  {rn(n)}"
            elif sub == 0x19: mnem = f"shlr8  {rn(n)}"
            elif sub == 0x20: mnem = f"shal   {rn(n)}"
            elif sub == 0x21: mnem = f"shar   {rn(n)}"
            elif sub == 0x24: mnem = f"rotcl  {rn(n)}"
            elif sub == 0x25: mnem = f"rotcr  {rn(n)}"
            elif sub == 0x28: mnem = f"shll16 {rn(n)}"
            elif sub == 0x29: mnem = f"shlr16 {rn(n)}"
            elif sub == 0x0B: mnem = f"jsr    @{rn(n)}"
            elif sub == 0x2B: mnem = f"jmp    @{rn(n)}"
            elif sub == 0x0E: mnem = f"ldc    {rn(n)},SR"
            elif sub == 0x1E: mnem = f"ldc    {rn(n)},GBR"
            elif sub == 0x2E: mnem = f"ldc    {rn(n)},VBR"
            elif sub == 0x0A: mnem = f"lds    {rn(n)},MACH"
            elif sub == 0x1A: mnem = f"lds    {rn(n)},MACL"
            elif sub == 0x2A: mnem = f"lds    {rn(n)},PR"
            elif sub == 0x06: mnem = f"lds.l  @{rn(n)}+,MACH"
            elif sub == 0x16: mnem = f"lds.l  @{rn(n)}+,MACL"
            elif sub == 0x26: mnem = f"lds.l  @{rn(n)}+,PR"
            elif sub == 0x03: mnem = f"stc.l  SR,@-{rn(n)}"
            elif sub == 0x13: mnem = f"stc.l  GBR,@-{rn(n)}"
            elif sub == 0x02: mnem = f"sts.l  MACH,@-{rn(n)}"
            elif sub == 0x12: mnem = f"sts.l  MACL,@-{rn(n)}"
            elif sub == 0x22: mnem = f"sts.l  PR,@-{rn(n)}"
            elif nib[3] == 0xF: mnem = f"mac.w  @{rn(m)}+,@{rn(n)}+"
            elif nib[3] == 0xC: mnem = f"shad   {rn(m)},{rn(n)}"
            elif nib[3] == 0xD: mnem = f"shld   {rn(m)},{rn(n)}"
        elif top == 0x5:
            d = nib[3]
            mnem = f"mov.l  @({d*4},{rn(m)}),{rn(n)}"
        elif top == 0x6:
            sub = nib[3]
            if sub == 0: mnem = f"mov.b  @{rn(m)},{rn(n)}"
            elif sub == 1: mnem = f"mov.w  @{rn(m)},{rn(n)}"
            elif sub == 2: mnem = f"mov.l  @{rn(m)},{rn(n)}"
            elif sub == 3: mnem = f"mov    {rn(m)},{rn(n)}"
            elif sub == 4: mnem = f"mov.b  @{rn(m)}+,{rn(n)}"
            elif sub == 5: mnem = f"mov.w  @{rn(m)}+,{rn(n)}"
            elif sub == 6: mnem = f"mov.l  @{rn(m)}+,{rn(n)}"
            elif sub == 7: mnem = f"not    {rn(m)},{rn(n)}"
            elif sub == 8: mnem = f"swap.b {rn(m)},{rn(n)}"
            elif sub == 9: mnem = f"swap.w {rn(m)},{rn(n)}"
            elif sub == 0xA: mnem = f"negc   {rn(m)},{rn(n)}"
            elif sub == 0xB: mnem = f"neg    {rn(m)},{rn(n)}"
            elif sub == 0xC: mnem = f"extu.b {rn(m)},{rn(n)}"
            elif sub == 0xD: mnem = f"extu.w {rn(m)},{rn(n)}"
            elif sub == 0xE: mnem = f"exts.b {rn(m)},{rn(n)}"
            elif sub == 0xF: mnem = f"exts.w {rn(m)},{rn(n)}"
        elif top == 0x7:
            imm = s8(d8)
            mnem = f"add    #{imm},{rn(n)}"
        elif top == 0x8:
            sub = nib[1]
            if sub == 0:
                mnem = f"mov.b  R0,@({d4},{rn(m)})"
            elif sub == 1:
                mnem = f"mov.w  R0,@({d4*2},{rn(m)})"
            elif sub == 4:
                mnem = f"mov.b  @({d4},{rn(m)}),R0"
            elif sub == 5:
                mnem = f"mov.w  @({d4*2},{rn(m)}),R0"
            elif sub == 8:
                disp = s8(d8)
                target = addr + 4 + disp * 2
                mnem = f"cmp/eq #{s8(d8)},R0"
            elif sub == 9:
                disp = s8(d8)
                target = addr + 4 + disp * 2
                mnem = f"bt     0x{target:05X}"
            elif sub == 0xB:
                disp = s8(d8)
                target = addr + 4 + disp * 2
                mnem = f"bf     0x{target:05X}"
            elif sub == 0xD:
                disp = s8(d8)
                target = addr + 4 + disp * 2
                mnem = f"bt/s   0x{target:05X}"
            elif sub == 0xF:
                disp = s8(d8)
                target = addr + 4 + disp * 2
                mnem = f"bf/s   0x{target:05X}"
        elif top == 0x9:
            disp = d8
            pc = addr + 4
            ea = pc + disp * 2
            val = u16(ea)
            mnem = f"mov.w  @(0x{ea:05X}),{rn(n)}"
            cmt = f"; =0x{val:04X} ({val})"
        elif top == 0xA:
            disp = op & 0xFFF
            if disp & 0x800: disp -= 0x1000
            target = addr + 4 + disp * 2
            mnem = f"bra    0x{target:05X}"
        elif top == 0xB:
            disp = op & 0xFFF
            if disp & 0x800: disp -= 0x1000
            target = addr + 4 + disp * 2
            mnem = f"bsr    0x{target:05X}"
        elif top == 0xC:
            sub = nib[1]
            if sub == 0: mnem = f"mov.b  R0,@({d8},GBR)"
            elif sub == 1: mnem = f"mov.w  R0,@({d8*2},GBR)"
            elif sub == 2: mnem = f"mov.l  R0,@({d8*4},GBR)"
            elif sub == 3: mnem = f"trapa  #{d8}"
            elif sub == 4: mnem = f"mov.b  @({d8},GBR),R0"
            elif sub == 5: mnem = f"mov.w  @({d8*2},GBR),R0"
            elif sub == 6: mnem = f"mov.l  @({d8*4},GBR),R0"
            elif sub == 7: mnem = f"mova   @(0x{(addr&~3)+4+d8*4:05X}),R0"
            elif sub == 8: mnem = f"tst    #0x{d8:02X},R0"
            elif sub == 9: mnem = f"and    #0x{d8:02X},R0"
            elif sub == 0xA: mnem = f"xor    #0x{d8:02X},R0"
            elif sub == 0xB: mnem = f"or     #0x{d8:02X},R0"
            elif sub == 0xD:
                mnem = f"and.b  #0x{d8:02X},@(R0,GBR)"
            elif sub == 0xE:
                mnem = f"or.b   #0x{d8:02X},@(R0,GBR)"
            elif sub == 0xF:
                mnem = f"xor.b  #0x{d8:02X},@(R0,GBR)"
        elif top == 0xD:
            disp = d8
            pc = (addr & ~3) + 4
            ea = pc + disp * 4
            if ea < len(rom):
                val = u32(ea)
                mnem = f"mov.l  @(0x{ea:05X}),{rn(n)}"
                if val >= 0xFFFF0000:
                    cmt = f"; =0x{val:08X} (RAM)"
                elif val < 0x100000:
                    cmt = f"; =0x{val:08X} (ROM)"
                else:
                    try:
                        fv = struct.unpack('>f', struct.pack('>I', val))[0]
                        if 1e-10 < abs(fv) < 1e10:
                            cmt = f"; =0x{val:08X} ({fv:.6g})"
                        else:
                            cmt = f"; =0x{val:08X}"
                    except:
                        cmt = f"; =0x{val:08X}"
            else:
                mnem = f"mov.l  @(0x{ea:05X}),{rn(n)}"
        elif top == 0xE:
            imm = s8(d8)
            mnem = f"mov    #{imm},{rn(n)}"
        elif top == 0xF:
            sub = nib[3]
            if sub == 0xC: mnem = f"fmov   {frn(m)},{frn(n)}"
            elif sub == 0x8: mnem = f"fmov.s @{rn(m)},{frn(n)}"
            elif sub == 0x6: mnem = f"fmov.s @(R0,{rn(m)}),{frn(n)}"
            elif sub == 0x9: mnem = f"fmov.s @{rn(m)}+,{frn(n)}"
            elif sub == 0xA: mnem = f"fmov.s {frn(m)},@{rn(n)}"
            elif sub == 0x7: mnem = f"fmov.s {frn(m)},@(R0,{rn(n)})"
            elif sub == 0xB: mnem = f"fmov.s {frn(m)},@-{rn(n)}"
            elif sub == 0x0: mnem = f"fadd   {frn(m)},{frn(n)}"
            elif sub == 0x1: mnem = f"fsub   {frn(m)},{frn(n)}"
            elif sub == 0x2: mnem = f"fmul   {frn(m)},{frn(n)}"
            elif sub == 0x3: mnem = f"fdiv   {frn(m)},{frn(n)}"
            elif sub == 0x4: mnem = f"fcmp/eq {frn(m)},{frn(n)}"
            elif sub == 0x5: mnem = f"fcmp/gt {frn(m)},{frn(n)}"
            elif sub == 0xE:
                if nib[2] == 0x0: mnem = f"fmac   FR0,{frn(m)},{frn(n)}"
                else: mnem = f"fmac   FR0,{frn(m)},{frn(n)}"
            elif sub == 0xD:
                ss = nib[2]
                if ss == 0: mnem = f"float  FPUL,{frn(n)}"
                elif ss == 2: mnem = f"ftrc   {frn(n)},FPUL"
                elif ss == 1: mnem = f"fneg   {frn(n)}"
                elif ss == 4: mnem = f"fcnvsd FPUL,{frn(n)}"
                elif ss == 5: mnem = f"fcnvds {frn(n)},FPUL"
                elif ss == 8: mnem = f"sts    FPUL,{rn(n)}"
                elif ss == 0xA: mnem = f"lds    {rn(n)},FPUL"

        if not mnem:
            mnem = f".word  0x{op:04X}"

        line = f"  0x{addr:05X}:  {op:04X}  {mnem:<40s} {cmt}"
        lines.append(line)
        addr += 2

    return lines

# ── DTC Table Decoder ────────────────────────────────────────────────────
print("="*78)
print("  DTC / DIAGNOSTIC SYSTEM — COMPLETE ANALYSIS")
print("  AE5L600L (2013 Subaru WRX MT)")
print("="*78)

# ── Section 1: DTC table structure details ───────────────────────────────
DTC_TABLE = 0x09A834
DTC_ENABLE = 0x09A770
DTC_COUNT = 93
DTC_ENTRY_SIZE = 20

print("\n" + "="*78)
print("  SECTION 1: DTC TABLE STRUCTURE (0x09A834)")
print("="*78)
print(f"\n  Table base:    0x{DTC_TABLE:05X}")
print(f"  Enable flags:  0x{DTC_ENABLE:05X}")
print(f"  Entries:       {DTC_COUNT}")
print(f"  Entry size:    {DTC_ENTRY_SIZE} bytes")
print(f"  Table size:    {DTC_COUNT * DTC_ENTRY_SIZE} bytes (0x{DTC_COUNT * DTC_ENTRY_SIZE:X})")
print(f"  Table end:     0x{DTC_TABLE + DTC_COUNT * DTC_ENTRY_SIZE:05X}")

# Decode the W0 (monitor class) field patterns
print("\n  DTC Entry Fields (20 bytes each):")
print("  ──────────────────────────────────────────────────────────────────")
print("  +0x00: W0 (u16) - Monitor class / type code")
print("  +0x02: W1 (u16) - Monitor ID / sub-parameter")
print("  +0x04: W2 (u16) - P-code (ISO 15031-6, big-endian)")
print("  +0x06: W3 (u16) - Sub-type / severity flags")
print("  +0x08: W4 (u16) - Threshold / parameter A")
print("  +0x0A: W5 (u16) - Threshold / parameter B")
print("  +0x0C: W6 (u16) - Maturation count / trip counter")
print("  +0x0E: W7 (u16) - Healing count / clear threshold")
print("  +0x10: W8 (u16) - MIL flags / emission class")
print("  +0x12: W9 (u16) - Extended flags")

# Analyze W0 class codes to find monitor categories
print("\n  Monitor Class Analysis (W0 field):")
print("  ──────────────────────────────────────────────────────────────────")
class_map = {}
for i in range(DTC_COUNT):
    base = DTC_TABLE + i * DTC_ENTRY_SIZE
    w0 = u16(base)
    pcode_raw = u16(base + 4)
    enabled = u8(DTC_ENABLE + i)
    if w0 not in class_map:
        class_map[w0] = []
    # Decode P-code
    p_hi = (pcode_raw >> 12) & 0xF
    p_mid = (pcode_raw >> 8) & 0xF
    p_lo = pcode_raw & 0xFF
    pcode_str = f"P{p_hi}{p_mid}{p_lo:02X}"
    # Actually decode properly
    p_thousands = (pcode_raw >> 12) & 0xF
    p_hundreds = (pcode_raw >> 8) & 0xF
    p_tens = (pcode_raw >> 4) & 0xF
    p_ones = pcode_raw & 0xF
    pcode_str = f"P{p_thousands}{p_hundreds}{p_tens}{p_ones}"
    class_map[w0].append((i, pcode_str, enabled))

for cls in sorted(class_map.keys()):
    entries = class_map[cls]
    codes = [e[1] for e in entries]
    print(f"  W0=0x{cls:04X}: {len(entries)} entries → {', '.join(codes[:6])}" +
          (f" (+{len(codes)-6} more)" if len(codes) > 6 else ""))

# ── Section 2: Full DTC table dump with all fields ────────────────────────
print("\n" + "="*78)
print("  SECTION 2: COMPLETE DTC TABLE DUMP")
print("="*78)
print(f"\n  {'Idx':>3} {'Addr':>8} {'En':>2} {'P-Code':>6} {'W0':>6} {'W1':>6} {'W3':>6} {'W4':>6} {'W5':>6} {'W6':>6} {'W7':>6} {'W8':>6} {'W9':>6}")
print("  " + "─"*90)
for i in range(DTC_COUNT):
    base = DTC_TABLE + i * DTC_ENTRY_SIZE
    w = [u16(base + j*2) for j in range(10)]
    enabled = u8(DTC_ENABLE + i)
    en_str = "Y" if enabled else "N"
    # Decode P-code
    pr = w[2]
    pcode = f"P{(pr>>12)&0xF}{(pr>>8)&0xF}{(pr>>4)&0xF}{pr&0xF}"
    print(f"  {i:3d} 0x{base:05X} {en_str:>2} {pcode:>6} 0x{w[0]:04X} 0x{w[1]:04X} 0x{w[3]:04X} 0x{w[4]:04X} 0x{w[5]:04X} 0x{w[6]:04X} 0x{w[7]:04X} 0x{w[8]:04X} 0x{w[9]:04X}")

# ── Section 3: Enable flag analysis ──────────────────────────────────────
print("\n" + "="*78)
print("  SECTION 3: ENABLE FLAGS (0x09A770)")
print("="*78)
enabled_count = 0
disabled_list = []
for i in range(DTC_COUNT):
    en = u8(DTC_ENABLE + i)
    if en:
        enabled_count += 1
    else:
        base = DTC_TABLE + i * DTC_ENTRY_SIZE
        pr = u16(base + 4)
        pcode = f"P{(pr>>12)&0xF}{(pr>>8)&0xF}{(pr>>4)&0xF}{pr&0xF}"
        disabled_list.append((i, pcode))

print(f"\n  Enabled:  {enabled_count} / {DTC_COUNT}")
print(f"  Disabled: {DTC_COUNT - enabled_count}")
print("\n  Disabled DTCs:")
for idx, pc in disabled_list:
    print(f"    [{idx:2d}] {pc}")

# ── Section 4: Disassemble task53_diag_monitor ──────────────────────────
print("\n" + "="*78)
print("  SECTION 4: task53_diag_monitor @ 0x602DC")
print("="*78)
for line in disasm_range(0x602DC, 0x60500, "task53_diag_monitor"):
    print(line)

# ── Section 5: Disassemble the two unknown calls ─────────────────────────
print("\n" + "="*78)
print("  SECTION 5: task53 sub-functions")
print("="*78)
for line in disasm_range(0x6035A, 0x604A0, "sub_6035A (called from task53)"):
    print(line)

for line in disasm_range(0x60392, 0x604A0, "sub_60392 (called from task53)"):
    print(line)

# ── Section 6: Look for diag_check_status ────────────────────────────────
# Search for common diagnostic subroutines that reference the DTC table
print("\n" + "="*78)
print("  SECTION 6: DTC STATE MACHINE HELPERS")
print("="*78)

# Find references to DTC table base (0x09A834) in ROM
print("\n  Searching for references to DTC table base 0x09A834...")
dtc_refs = []
for a in range(0, len(rom)-4, 2):
    if u32(a) == 0x0009A834:
        # Check if this is in a literal pool (aligned)
        dtc_refs.append(a)
for ref in dtc_refs[:20]:
    print(f"    0x{ref:05X}: {u32(ref):08X}")

# Find references to DTC enable base (0x09A770)
print(f"\n  Searching for references to DTC enable flags 0x09A770...")
en_refs = []
for a in range(0, len(rom)-4, 2):
    if u32(a) == 0x0009A770:
        en_refs.append(a)
for ref in en_refs[:20]:
    print(f"    0x{ref:05X}: {u32(ref):08X}")

# ── Section 7: Disassemble around DTC table references ───────────────────
print("\n" + "="*78)
print("  SECTION 7: FUNCTIONS REFERENCING DTC TABLE")
print("="*78)

# For each reference to the DTC table, find the function start
# (search backward for a common function prologue or known boundary)
for ref in dtc_refs[:10]:
    # The reference is in a literal pool — find what instruction loads it
    # Search backward for code that uses mov.l @(disp,PC)
    func_start = max(0, ref - 256)
    # Find the actual code that references this literal
    for check in range(ref - 256, ref, 2):
        if check < 0: continue
        op = u16(check)
        if (op >> 12) == 0xD:  # mov.l @(disp,PC),Rn
            disp = op & 0xFF
            pc = (check & ~3) + 4
            ea = pc + disp * 4
            if ea == ref:
                print(f"\n  Instruction at 0x{check:05X} loads DTC table ptr → R{(op>>8)&0xF}")
                # Disassemble this function region
                start = max(0, check - 64)
                end = min(len(rom), check + 128)
                for line in disasm_range(start, end, f"Function near 0x{check:05X}"):
                    print(line)
                break

# ── Section 8: DTC RAM layout analysis ────────────────────────────────────
print("\n" + "="*78)
print("  SECTION 8: DTC RAM STATE REGIONS")
print("="*78)

# Known diag_state RAM regions from ram_map_raw.txt
diag_regions = [
    (0xFFFFAF70, 0xFFFFAFAB, 59, 144, "diag_state_A"),
    (0xFFFFA156, 0xFFFFA18D, 55, 135, "diag_state_B"),
    (0xFFFFA32C, 0xFFFFA39F, 115, 132, "diag_state_C"),
    (0xFFFFA2A0, 0xFFFFA308, 104, 32, "diag_state_D"),
    (0xFFFFAD14, 0xFFFFAD52, 62, 268, "diag_state_E"),
    (0xFFFFAB76, 0xFFFFABC5, 79, 66, "diag_state_F"),
]

print(f"\n  {'Region':>15} {'Start':>12} {'End':>12} {'Size':>5} {'Refs':>5}")
print("  " + "─"*55)
for start, end, size, refs, name in diag_regions:
    print(f"  {name:>15} 0x{start:08X} 0x{end:08X} {size:>5} {refs:>5}")

# Total
total_bytes = sum(s for _, _, s, _, _ in diag_regions)
total_refs = sum(r for _, _, _, r, _ in diag_regions)
print(f"  {'TOTAL':>15} {'':>12} {'':>12} {total_bytes:>5} {total_refs:>5}")

# ── Section 9: Search for MIL/CEL activation ──────────────────────────────
print("\n" + "="*78)
print("  SECTION 9: MIL (CHECK ENGINE LIGHT) ACTIVATION")
print("="*78)

# Search for common MIL-related RAM addresses
# Typically there's a master MIL flag byte
# Search for 0xFFFF36F4 (dtc_enable_flag from ram_map) references
print("\n  Searching for dtc_enable_flag (0xFFFF36F4) references...")
mil_refs = []
for a in range(0, len(rom)-4, 2):
    val = u32(a)
    if val == 0xFFFF36F4:
        mil_refs.append(a)
print(f"  Found {len(mil_refs)} references")
for ref in mil_refs[:10]:
    print(f"    0x{ref:05X}")

# Search for dtc_master_enable (0xFFFFB71C)
print(f"\n  Searching for dtc_master_enable (0xFFFFB71C) references...")
master_refs = []
for a in range(0, len(rom)-4, 2):
    val = u32(a)
    if val == 0xFFFFB71C:
        master_refs.append(a)
print(f"  Found {len(master_refs)} references")
for ref in master_refs[:10]:
    print(f"    0x{ref:05X}")

# ── Section 10: Decode DTC struct decode_dtc_table.py reference ──────────
# Look for the main DTC processing loop — likely iterates 93 times over the table
print("\n" + "="*78)
print("  SECTION 10: DTC PROCESSING LOOP SEARCH")
print("="*78)

# Search for the constant 93 (0x5D) as immediate or in literal pools
# Also search for 20 (0x14) as the stride
print("\n  Looking for DTC iteration patterns (count=93, stride=20)...")
# Search for mov #93 patterns or literal 0x5D
count_refs = []
for a in range(0, len(rom)-2, 2):
    op = u16(a)
    # mov #imm8, Rn where imm8 = 93 (0x5D)
    if (op >> 8) == 0xE5 and (op & 0xFF) == 0x5D:  # mov #93, R5
        count_refs.append((a, f"mov #93,R5"))
    elif (op >> 8) == 0xE0 | ((op >> 12) == 0xE and (op & 0xFF) == 0x5D):
        rr = (op >> 8) & 0xF
        count_refs.append((a, f"mov #{op & 0xFF},R{rr}"))

# Filter to actual #93 moves
count_refs = [(a, m) for a, m in count_refs if '93' in m or '0x5D' in m.lower()]
print(f"  Found {len(count_refs)} instructions loading #93:")
for a, m in count_refs[:20]:
    print(f"    0x{a:05X}: {m}")
    # Disassemble context
    for line in disasm_range(max(0, a-16), min(len(rom), a+32)):
        print(f"      {line}")

# Also look for GBR-relative accesses to the diag_state high-traffic region
# diag_state_E (0xFFFFAD14-0xFFFFAD52) has 268 refs
# GBR is typically 0xFFFF7450
# Offset from GBR: 0xFFFFAD14 - 0xFFFF7450 = 0x38C4
print(f"\n  GBR offset to diag_state_E: 0x{0xFFFFAD14 - 0xFFFF7450:04X}")
print(f"  GBR offset to dtc_enable_flag: 0x{0xFFFF36F4 - 0xFFFF7450:04X}")
# dtc_enable_flag is BELOW GBR, so negative offset = can't use GBR-relative for it

print("\n" + "="*78)
print("  SECTION 11: TASK53 EXPANDED DISASSEMBLY")
print("="*78)
# Disassemble a wider range around task53
for line in disasm_range(0x602DC, 0x60800, "task53_diag_monitor — extended"):
    print(line)

# ── Section 12: Disassemble task55_mps_diag ──────────────────────────────
print("\n" + "="*78)
print("  SECTION 12: task55_mps_diag @ 0x900B4")
print("="*78)
for line in disasm_range(0x900B4, 0x90300, "task55_mps_diag"):
    print(line)

# ── Section 13: Disassemble task58_maf_diag ──────────────────────────────
print("\n" + "="*78)
print("  SECTION 13: task58_maf_diag @ 0x6F0B8")
print("="*78)
for line in disasm_range(0x6F0B8, 0x6F300, "task58_maf_diag"):
    print(line)

# ── Section 14: Trace diag_check_status function ─────────────────────────
# Called by task56_evap_purge @ 0x66580
print("\n" + "="*78)
print("  SECTION 14: task56_evap_purge (calls diag_check_status)")
print("="*78)
for line in disasm_range(0x66580, 0x66800, "task56_evap_purge @ 0x66580"):
    print(line)

print("\n\n[Done]")
