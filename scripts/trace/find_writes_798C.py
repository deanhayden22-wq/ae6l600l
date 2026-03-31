#!/usr/bin/env python3
"""Find all instructions in the ROM that WRITE to RAM address FFFF798C.

Search strategy:
1. Scan literal pool entries for 0xFFFF798C (exact match)
2. Scan literal pool entries for nearby base addresses (FFFF7988, FFFF7980, etc.)
   that could reach 798C via displacement
3. For each hit, trace backward to find what code loads it and uses it as a write dest
4. Also check GBR-relative writes (GBR=FFFF7450, offset=0x53C - too large for byte disp,
   but check word/long disp forms)
5. Check for fmov.s stores (floating point writes)
"""

import struct

ROM_PATH = 'C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin'
TARGET_ADDR = 0xFFFF798C
GBR = 0xFFFF7450
ROM_SIZE = 0x50000

with open(ROM_PATH, 'rb') as f:
    rom = f.read()

def read_u16(addr):
    return struct.unpack('>H', rom[addr:addr+2])[0]

def read_u32(addr):
    return struct.unpack('>I', rom[addr:addr+4])[0]

def read_s8(val):
    return val - 256 if val > 127 else val

def read_float_at(addr):
    return struct.unpack('>f', rom[addr:addr+4])[0]

def sign12(v):
    return v if v < 2048 else v - 4096

def classify_addr(val):
    if 0xFFFF0000 <= val <= 0xFFFFFFFF:
        return "RAM"
    elif val < 0x00100000:
        return "ROM"
    elif 0x000A0000 <= val <= 0x000FFFFF:
        return "CAL"
    elif 0xFFFE0000 <= val <= 0xFFFEFFFF:
        return "I/O"
    else:
        return "CONST"

# ============================================================
# Step 1: Find all literal pool entries containing FFFF798C
# or nearby addresses that could reach it via displacement
# ============================================================
print("=" * 100)
print(f"SEARCHING FOR ALL WRITES TO RAM 0x{TARGET_ADDR:08X}")
print("=" * 100)

# Scan all aligned 32-bit values in ROM for exact address
print("\n--- Literal pool scan for exact address 0xFFFF798C ---")
exact_hits = []
for addr in range(0, ROM_SIZE - 3, 2):  # check every 2-byte aligned position
    val = read_u32(addr)
    if val == TARGET_ADDR:
        exact_hits.append(addr)
        print(f"  Found 0x{TARGET_ADDR:08X} at ROM offset 0x{addr:05X}")

# Also check for nearby base addresses (within +/-16 bytes for displacement addressing)
print("\n--- Literal pool scan for nearby base addresses ---")
nearby_hits = []
for addr in range(0, ROM_SIZE - 3, 2):
    val = read_u32(addr)
    if 0xFFFF7980 <= val <= 0xFFFF7990 and val != TARGET_ADDR:
        nearby_hits.append((addr, val))
        diff = TARGET_ADDR - val
        print(f"  Found 0x{val:08X} at ROM offset 0x{addr:05X} (diff to target: {diff})")

# ============================================================
# Step 2: Check GBR-relative addressing
# ============================================================
print(f"\n--- GBR-relative check (GBR=0x{GBR:08X}) ---")
gbr_offset = TARGET_ADDR - GBR
print(f"  Offset needed: 0x{gbr_offset:04X} = {gbr_offset}")
if gbr_offset <= 0xFF:
    print(f"  -> In range for mov.b R0,@(disp,GBR) (C0xx)")
elif gbr_offset <= 0x1FE:
    print(f"  -> In range for mov.w R0,@(disp,GBR) (C1xx)")
elif gbr_offset <= 0x3FC:
    print(f"  -> In range for mov.l R0,@(disp,GBR) (C2xx)")
else:
    print(f"  -> 0x{gbr_offset:04X} = {gbr_offset} is OUT OF RANGE for all GBR-relative forms")
    print(f"     (max byte disp=255, word disp=510, long disp=1020)")

# Even though out of range, let's verify by scanning for the specific GBR-rel opcodes
# that would hit this address
# mov.l R0,@(disp,GBR): C2dd where disp = dd*4, effective = GBR + dd*4
# For FFFF798C: dd*4 = 0x53C, dd = 0x14F -- exceeds byte range (max 0xFF)
# So GBR-relative cannot reach FFFF798C. Confirmed.

# ============================================================
# Step 3: For each literal pool hit, find what code references it
# ============================================================
print("\n" + "=" * 100)
print("TRACING CODE REFERENCES TO LITERAL POOL ENTRIES")
print("=" * 100)

def find_code_loading_pool(pool_addr, pool_val):
    """Find mov.l @(disp,PC),Rn instructions that load from this pool address.

    For mov.l @(disp,PC),Rn (opcode Dndd):
      effective_addr = (PC+4 & ~3) + dd*4
      where PC = address of the mov.l instruction
      dd = 8-bit unsigned displacement
      max reach = 255*4 = 1020 bytes forward from (PC+4 & ~3)
    """
    refs = []
    # Search backward from pool_addr up to 1020 bytes
    search_start = max(0, pool_addr - 1020)
    for iaddr in range(search_start, pool_addr, 2):
        op = read_u16(iaddr)
        top = (op >> 12) & 0xF
        if top == 0xD:  # mov.l @(disp,PC),Rn
            n_reg = (op >> 8) & 0xF
            dd = op & 0xFF
            effective = ((iaddr + 4) & ~3) + dd * 4
            if effective == pool_addr:
                refs.append((iaddr, n_reg, 'mov.l'))
        elif top == 0xC and ((op >> 8) & 0xF) == 0x7:  # mova @(disp,PC),R0
            dd = op & 0xFF
            effective = ((iaddr + 4) & ~3) + dd * 4
            if effective == pool_addr:
                refs.append((iaddr, 0, 'mova'))
    return refs

def disasm_one_str(addr):
    """Quick disassembly of one instruction, returns string."""
    if addr < 0 or addr + 1 >= len(rom):
        return "???"
    op = read_u16(addr)
    n = (op >> 12) & 0xF
    n_reg = (op >> 8) & 0xF
    m_reg = (op >> 4) & 0xF
    d8 = op & 0xFF
    d4 = op & 0xF
    sub = op & 0xF
    top = n

    # Comprehensive enough for analysis
    if op == 0x0009: return "nop"
    if op == 0x000B: return "rts"

    if top == 0x0:
        if sub == 0x4: return f"mov.b  R{m_reg},@(R0,R{n_reg})"
        if sub == 0x5: return f"mov.w  R{m_reg},@(R0,R{n_reg})"
        if sub == 0x6: return f"mov.l  R{m_reg},@(R0,R{n_reg})"
        if sub == 0xC: return f"mov.b  @(R0,R{m_reg}),R{n_reg}"
        if sub == 0xD: return f"mov.w  @(R0,R{m_reg}),R{n_reg}"
        if sub == 0xE: return f"mov.l  @(R0,R{m_reg}),R{n_reg}"
        if sub == 0x7: return f"mul.l  R{m_reg},R{n_reg}"
        if sub == 0x3: return f"bsrf   R{n_reg}"
        if sub == 0x2:
            if m_reg == 0: return f"stc    SR,R{n_reg}"
            if m_reg == 1: return f"stc    GBR,R{n_reg}"
            if m_reg == 2: return f"stc    VBR,R{n_reg}"
        if sub == 0xA:
            if m_reg == 0: return f"sts    MACH,R{n_reg}"
            if m_reg == 1: return f"sts    MACL,R{n_reg}"
            if m_reg == 2: return f"sts    PR,R{n_reg}"
        return f".word  0x{op:04X}"

    if top == 0x1:
        disp = d4 * 4
        return f"mov.l  R{m_reg},@({disp},R{n_reg})"

    if top == 0x2:
        if sub == 0: return f"mov.b  R{m_reg},@R{n_reg}"
        if sub == 1: return f"mov.w  R{m_reg},@R{n_reg}"
        if sub == 2: return f"mov.l  R{m_reg},@R{n_reg}"
        if sub == 4: return f"mov.b  R{m_reg},@-R{n_reg}"
        if sub == 5: return f"mov.w  R{m_reg},@-R{n_reg}"
        if sub == 6: return f"mov.l  R{m_reg},@-R{n_reg}"
        if sub == 7: return f"div0s  R{m_reg},R{n_reg}"
        if sub == 8: return f"tst    R{m_reg},R{n_reg}"
        if sub == 9: return f"and    R{m_reg},R{n_reg}"
        if sub == 0xA: return f"xor    R{m_reg},R{n_reg}"
        if sub == 0xB: return f"or     R{m_reg},R{n_reg}"
        if sub == 0xC: return f"cmp/str R{m_reg},R{n_reg}"
        if sub == 0xD: return f"xtrct  R{m_reg},R{n_reg}"
        if sub == 0xE: return f"mulu.w R{m_reg},R{n_reg}"
        if sub == 0xF: return f"muls.w R{m_reg},R{n_reg}"
        return f".word  0x{op:04X}"

    if top == 0x3:
        ops3 = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",4:"div1",5:"dmulu.l",
                6:"cmp/hi",7:"cmp/gt",8:"sub",0xA:"subc",0xB:"subv",
                0xC:"add",0xD:"dmuls.l",0xE:"addc",0xF:"addv"}
        if sub in ops3: return f"{ops3[sub]}  R{m_reg},R{n_reg}"
        return f".word  0x{op:04X}"

    if top == 0x4:
        low8 = op & 0xFF
        if low8 == 0x22: return f"sts.l  PR,@-R{n_reg}"
        if low8 == 0x26: return f"lds.l  @R{n_reg}+,PR"
        if low8 == 0x13: return f"stc.l  GBR,@-R{n_reg}"
        if low8 == 0x17: return f"ldc.l  @R{n_reg}+,GBR"
        if low8 == 0x1E: return f"ldc    R{n_reg},GBR"
        if low8 == 0x0B: return f"jsr    @R{n_reg}"
        if low8 == 0x2B: return f"jmp    @R{n_reg}"
        if low8 == 0x15: return f"cmp/pl R{n_reg}"
        if low8 == 0x11: return f"cmp/pz R{n_reg}"
        if low8 == 0x10: return f"dt     R{n_reg}"
        if low8 == 0x00: return f"shll   R{n_reg}"
        if low8 == 0x01: return f"shlr   R{n_reg}"
        if low8 == 0x04: return f"rotl   R{n_reg}"
        if low8 == 0x05: return f"rotr   R{n_reg}"
        if low8 == 0x08: return f"shll2  R{n_reg}"
        if low8 == 0x09: return f"shlr2  R{n_reg}"
        if low8 == 0x18: return f"shll8  R{n_reg}"
        if low8 == 0x19: return f"shlr8  R{n_reg}"
        if low8 == 0x28: return f"shll16 R{n_reg}"
        if low8 == 0x29: return f"shlr16 R{n_reg}"
        if low8 == 0x20: return f"shal   R{n_reg}"
        if low8 == 0x21: return f"shar   R{n_reg}"
        if low8 == 0x24: return f"rotcl  R{n_reg}"
        if low8 == 0x25: return f"rotcr  R{n_reg}"
        if low8 == 0x0A: return f"lds    R{n_reg},MACH"
        if low8 == 0x1A: return f"lds    R{n_reg},MACL"
        if low8 == 0x2A: return f"lds    R{n_reg},PR"
        lo1 = d4
        if lo1 == 0xC: return f"shad   R{m_reg},R{n_reg}"
        if lo1 == 0xD: return f"shld   R{m_reg},R{n_reg}"
        if lo1 == 0xF: return f"mac.w  @R{m_reg}+,@R{n_reg}+"
        return f".word  0x{op:04X}"

    if top == 0x5:
        disp = d4 * 4
        return f"mov.l  @({disp},R{m_reg}),R{n_reg}"

    if top == 0x6:
        if sub == 0: return f"mov.b  @R{m_reg},R{n_reg}"
        if sub == 1: return f"mov.w  @R{m_reg},R{n_reg}"
        if sub == 2: return f"mov.l  @R{m_reg},R{n_reg}"
        if sub == 3: return f"mov    R{m_reg},R{n_reg}"
        if sub == 4: return f"mov.b  @R{m_reg}+,R{n_reg}"
        if sub == 5: return f"mov.w  @R{m_reg}+,R{n_reg}"
        if sub == 6: return f"mov.l  @R{m_reg}+,R{n_reg}"
        if sub == 7: return f"not    R{m_reg},R{n_reg}"
        if sub == 8: return f"swap.b R{m_reg},R{n_reg}"
        if sub == 9: return f"swap.w R{m_reg},R{n_reg}"
        if sub == 0xA: return f"negc   R{m_reg},R{n_reg}"
        if sub == 0xB: return f"neg    R{m_reg},R{n_reg}"
        if sub == 0xC: return f"extu.b R{m_reg},R{n_reg}"
        if sub == 0xD: return f"extu.w R{m_reg},R{n_reg}"
        if sub == 0xE: return f"exts.b R{m_reg},R{n_reg}"
        if sub == 0xF: return f"exts.w R{m_reg},R{n_reg}"
        return f".word  0x{op:04X}"

    if top == 0x7:
        imm = read_s8(d8)
        return f"add    #{imm},R{n_reg}"

    if top == 0x8:
        s = n_reg
        if s == 0x0: return f"mov.b  R0,@({d4},R{m_reg})"
        if s == 0x1: return f"mov.w  R0,@({d4*2},R{m_reg})"
        if s == 0x4: return f"mov.b  @({d4},R{m_reg}),R0"
        if s == 0x5: return f"mov.w  @({d4*2},R{m_reg}),R0"
        if s == 0x8: return f"cmp/eq #{read_s8(d8)},R0"
        if s == 0x9:
            target = addr + read_s8(d8) * 2 + 4
            return f"bt     0x{target:05X}"
        if s == 0xB:
            target = addr + read_s8(d8) * 2 + 4
            return f"bf     0x{target:05X}"
        if s == 0xD:
            target = addr + read_s8(d8) * 2 + 4
            return f"bt/s   0x{target:05X}"
        if s == 0xF:
            target = addr + read_s8(d8) * 2 + 4
            return f"bf/s   0x{target:05X}"
        return f".word  0x{op:04X}"

    if top == 0x9:
        disp = d8 * 2
        pool_addr = addr + 4 + disp
        if pool_addr + 1 < len(rom):
            val = read_u16(pool_addr)
            return f"mov.w  @(0x{pool_addr:05X},PC),R{n_reg}  ; R{n_reg}=0x{val:04X}"
        return f"mov.w  @(disp,PC),R{n_reg}"

    if top == 0xA:
        disp12 = op & 0xFFF
        target = addr + 4 + sign12(disp12) * 2
        return f"bra    0x{target:05X}"

    if top == 0xB:
        disp12 = op & 0xFFF
        target = addr + 4 + sign12(disp12) * 2
        return f"bsr    0x{target:05X}"

    if top == 0xC:
        s = n_reg
        if s == 0x0:
            gbr_addr = GBR + d8
            return f"mov.b  R0,@(0x{d8:02X},GBR)  ; [{gbr_addr:08X}]"
        if s == 0x1:
            gbr_addr = GBR + d8*2
            return f"mov.w  R0,@(0x{d8*2:03X},GBR)  ; [{gbr_addr:08X}]"
        if s == 0x2:
            gbr_addr = GBR + d8*4
            return f"mov.l  R0,@(0x{d8*4:03X},GBR)  ; [{gbr_addr:08X}]"
        if s == 0x4:
            gbr_addr = GBR + d8
            return f"mov.b  @(0x{d8:02X},GBR),R0  ; [{gbr_addr:08X}]"
        if s == 0x5:
            gbr_addr = GBR + d8*2
            return f"mov.w  @(0x{d8*2:03X},GBR),R0  ; [{gbr_addr:08X}]"
        if s == 0x6:
            gbr_addr = GBR + d8*4
            return f"mov.l  @(0x{d8*4:03X},GBR),R0  ; [{gbr_addr:08X}]"
        if s == 0x7:
            pool_addr = ((addr + 4) & ~3) + d8 * 4
            if pool_addr + 3 < len(rom):
                val = read_u32(pool_addr)
                return f"mova   @(0x{pool_addr:05X},PC),R0  ; R0=0x{pool_addr:05X}"
            return f"mova   @(disp,PC),R0"
        if s == 0x8: return f"tst    #0x{d8:02X},R0"
        if s == 0x9: return f"and    #0x{d8:02X},R0"
        if s == 0xA: return f"xor    #0x{d8:02X},R0"
        if s == 0xB: return f"or     #0x{d8:02X},R0"
        if s == 0xD: return f"and.b  #0x{d8:02X},@(R0,GBR)"
        if s == 0xF: return f"or.b   #0x{d8:02X},@(R0,GBR)"
        return f".word  0x{op:04X}"

    if top == 0xD:
        disp = d8 * 4
        pool_addr = ((addr + 4) & ~3) + disp
        if pool_addr + 3 < len(rom):
            val = read_u32(pool_addr)
            cls = classify_addr(val)
            return f"mov.l  @(0x{pool_addr:05X},PC),R{n_reg}  ; R{n_reg}=0x{val:08X} ({cls})"
        return f"mov.l  @(disp,PC),R{n_reg}"

    if top == 0xE:
        imm = read_s8(d8)
        return f"mov    #{imm},R{n_reg}"

    if top == 0xF:
        fn = n_reg
        fm = m_reg
        if sub == 0x0: return f"fadd   FR{fm},FR{fn}"
        if sub == 0x1: return f"fsub   FR{fm},FR{fn}"
        if sub == 0x2: return f"fmul   FR{fm},FR{fn}"
        if sub == 0x3: return f"fdiv   FR{fm},FR{fn}"
        if sub == 0x4: return f"fcmp/eq FR{fm},FR{fn}"
        if sub == 0x5: return f"fcmp/gt FR{fm},FR{fn}"
        if sub == 0x6: return f"fmov.s @(R0,R{m_reg}),FR{fn}"
        if sub == 0x7: return f"fmov.s FR{fm},@(R0,R{n_reg})"
        if sub == 0x8: return f"fmov.s @R{m_reg},FR{fn}"
        if sub == 0x9: return f"fmov.s @R{m_reg}+,FR{fn}"
        if sub == 0xA: return f"fmov.s FR{fm},@R{n_reg}"
        if sub == 0xB: return f"fmov.s FR{fm},@-R{n_reg}"
        if sub == 0xC: return f"fmov   FR{fm},FR{fn}"
        if sub == 0xD:
            if fm == 0x0: return f"fsts   FPUL,FR{fn}"
            if fm == 0x1: return f"flds   FR{fn},FPUL"
            if fm == 0x2: return f"float  FPUL,FR{fn}"
            if fm == 0x3: return f"ftrc   FR{fn},FPUL"
            if fm == 0x4: return f"fneg   FR{fn}"
            if fm == 0x5: return f"fabs   FR{fn}"
            if fm == 0x6: return f"fsqrt  FR{fn}"
            if fm == 0x8: return f"fldi0  FR{fn}"
            if fm == 0x9: return f"fldi1  FR{fn}"
            if fm == 0xA: return f"lds    R{n_reg},FPUL"
            return f".word  0x{op:04X}"
        if sub == 0xE: return f"fmac   FR0,FR{fm},FR{fn}"
        return f".word  0x{op:04X}"

    return f".word  0x{op:04X}"

def disasm_context(center_addr, before=30, after=30):
    """Disassemble instructions around center_addr with annotations."""
    start = max(0, center_addr - before * 2)
    end = min(ROM_SIZE, center_addr + after * 2)
    # Align start
    start = start & ~1

    lines = []
    addr = start
    while addr < end:
        asm = disasm_one_str(addr)
        marker = " >>>" if addr == center_addr else "    "
        lines.append(f"{marker} {addr:05X}: {read_u16(addr):04X}  {asm}")
        addr += 2
    return "\n".join(lines)


# ============================================================
# Step 4: For each exact hit, find the code that loads it
# ============================================================
all_write_sites = []

for pool_addr in exact_hits:
    print(f"\n{'='*100}")
    print(f"LITERAL POOL ENTRY at 0x{pool_addr:05X} contains 0x{TARGET_ADDR:08X}")
    print(f"{'='*100}")

    refs = find_code_loading_pool(pool_addr, TARGET_ADDR)
    if not refs:
        print("  WARNING: No code found loading this pool entry!")
        print("  (May be data, not a literal pool, or loaded via mova)")
        continue

    for load_addr, reg, load_type in refs:
        print(f"\n  Loaded by {load_type} at 0x{load_addr:05X} into R{reg}")
        print(f"  Now searching for writes using R{reg} as destination pointer...")

        # Search forward from the load for store instructions using this register
        # Look for: mov.l Rm,@Rn / mov.w Rm,@Rn / mov.b Rm,@Rn
        #           fmov.s FRm,@Rn / fmov.s FRm,@(R0,Rn)
        #           mov.l Rm,@(disp,Rn)
        # The register could be reassigned, so we stop at rts/jmp or if reg is overwritten

        # First, let's look at context around the load
        print(f"\n  --- Context around load at 0x{load_addr:05X} ---")
        print(disasm_context(load_addr, before=30, after=40))

        # Now specifically identify writes
        print(f"\n  --- Identifying write instructions using R{reg} ---")
        scan_start = load_addr + 2  # instruction after the load
        scan_end = min(scan_start + 200, ROM_SIZE)

        for saddr in range(scan_start, scan_end, 2):
            op = read_u16(saddr)
            top4 = (op >> 12) & 0xF
            n_r = (op >> 8) & 0xF
            m_r = (op >> 4) & 0xF
            low4 = op & 0xF

            is_write = False
            write_desc = ""

            # mov.l Rm,@Rn (2nm2)
            if top4 == 0x2 and low4 == 0x2 and n_r == reg:
                is_write = True
                write_desc = f"mov.l  R{m_r},@R{reg}  ; WRITE to [{TARGET_ADDR:08X}]"
            # mov.w Rm,@Rn (2nm1)
            elif top4 == 0x2 and low4 == 0x1 and n_r == reg:
                is_write = True
                write_desc = f"mov.w  R{m_r},@R{reg}  ; WRITE to [{TARGET_ADDR:08X}]"
            # mov.b Rm,@Rn (2nm0)
            elif top4 == 0x2 and low4 == 0x0 and n_r == reg:
                is_write = True
                write_desc = f"mov.b  R{m_r},@R{reg}  ; WRITE to [{TARGET_ADDR:08X}]"
            # mov.l Rm,@(disp,Rn) (1nmd)
            elif top4 == 0x1 and n_r == reg:
                disp = low4 * 4
                eff = TARGET_ADDR + disp
                is_write = True
                write_desc = f"mov.l  R{m_r},@({disp},R{reg})  ; WRITE to [0x{eff:08X}]"
            # fmov.s FRm,@Rn (FnmA)
            elif top4 == 0xF and low4 == 0xA and n_r == reg:
                is_write = True
                write_desc = f"fmov.s FR{m_r},@R{reg}  ; FLOAT WRITE to [{TARGET_ADDR:08X}]"
            # fmov.s FRm,@-Rn (FnmB)
            elif top4 == 0xF and low4 == 0xB and n_r == reg:
                is_write = True
                write_desc = f"fmov.s FR{m_r},@-R{reg}  ; FLOAT WRITE (pre-dec)"
            # fmov.s FRm,@(R0,Rn) (Fnm7)
            elif top4 == 0xF and low4 == 0x7 and n_r == reg:
                is_write = True
                write_desc = f"fmov.s FR{m_r},@(R0,R{reg})  ; FLOAT WRITE to [R0+{TARGET_ADDR:08X}]"
            # mov.b R0,@(disp,Rn) (80nd)
            elif top4 == 0x8 and n_r == 0x0 and m_r == reg:
                is_write = True
                write_desc = f"mov.b  R0,@({low4},R{reg})  ; BYTE WRITE"
            # mov.w R0,@(disp,Rn) (81nd)
            elif top4 == 0x8 and n_r == 0x1 and m_r == reg:
                disp = low4 * 2
                is_write = True
                write_desc = f"mov.w  R0,@({disp},R{reg})  ; WORD WRITE"
            # mov.b/w/l Rm,@(R0,Rn) (0nm4/5/6)
            elif top4 == 0x0 and low4 in (4,5,6) and n_r == reg:
                sz = {4:".b",5:".w",6:".l"}[low4]
                is_write = True
                write_desc = f"mov{sz}  R{m_r},@(R0,R{reg})  ; WRITE to [R0+{TARGET_ADDR:08X}]"

            if is_write:
                all_write_sites.append((saddr, write_desc, load_addr, pool_addr))
                print(f"\n  *** WRITE FOUND at 0x{saddr:05X}: {write_desc}")

            # Check if register is being overwritten (stop scanning)
            # mov.l @(disp,PC),Rn where n == reg
            if top4 == 0xD and n_r == reg and saddr != load_addr:
                print(f"  (R{reg} overwritten at 0x{saddr:05X}, stopping scan for this load)")
                break
            # mov Rm,Rn where n == reg
            if top4 == 0x6 and low4 == 0x3 and n_r == reg:
                print(f"  (R{reg} overwritten at 0x{saddr:05X}, stopping scan for this load)")
                break
            # mov #imm,Rn where n == reg
            if top4 == 0xE and n_r == reg:
                print(f"  (R{reg} overwritten at 0x{saddr:05X}, stopping scan for this load)")
                break
            # add #imm,Rn where n == reg -- reg is modified but still derived from original
            # Don't break on this, the address might be adjusted

            # rts = end of function
            if op == 0x000B:
                # Check one more instruction (delay slot)
                if saddr + 2 < scan_end:
                    dop = read_u16(saddr + 2)
                    dtop4 = (dop >> 12) & 0xF
                    dn_r = (dop >> 8) & 0xF
                    dm_r = (dop >> 4) & 0xF
                    dlow4 = dop & 0xF
                    # Check delay slot for writes too
                    if dtop4 == 0xF and dlow4 == 0xA and dn_r == reg:
                        all_write_sites.append((saddr+2, f"fmov.s FR{dm_r},@R{reg}  ; FLOAT WRITE (in delay slot)", load_addr, pool_addr))
                        print(f"\n  *** WRITE FOUND at 0x{saddr+2:05X} (delay slot): fmov.s FR{dm_r},@R{reg}")
                    if dtop4 == 0x2 and dlow4 == 0x2 and dn_r == reg:
                        all_write_sites.append((saddr+2, f"mov.l  R{dm_r},@R{reg}  ; WRITE (in delay slot)", load_addr, pool_addr))
                        print(f"\n  *** WRITE FOUND at 0x{saddr+2:05X} (delay slot): mov.l R{dm_r},@R{reg}")
                break

# Also check for writes via nearby base addresses
for pool_addr, base_val in nearby_hits:
    diff = TARGET_ADDR - base_val
    print(f"\n{'='*100}")
    print(f"NEARBY POOL ENTRY at 0x{pool_addr:05X} = 0x{base_val:08X} (offset {diff} to target)")
    print(f"{'='*100}")

    refs = find_code_loading_pool(pool_addr, base_val)
    if not refs:
        print("  No code found loading this pool entry")
        continue

    for load_addr, reg, load_type in refs:
        print(f"  Loaded by {load_type} at 0x{load_addr:05X} into R{reg}")

        # For nearby bases, the code would add a displacement
        # Check for add #imm,Rn or mov.l @(disp,Rn) patterns
        # that would make the effective address = FFFF798C

        # For mov.l Rm,@(disp,Rn) : disp = 0..60 in steps of 4
        if 0 <= diff <= 60 and diff % 4 == 0:
            d4 = diff // 4
            print(f"  Could reach target via mov.l Rm,@({diff},R{reg})")

            scan_start = load_addr + 2
            scan_end = min(scan_start + 200, ROM_SIZE)
            for saddr in range(scan_start, scan_end, 2):
                op = read_u16(saddr)
                top4 = (op >> 12) & 0xF
                n_r = (op >> 8) & 0xF
                m_r = (op >> 4) & 0xF
                low4 = op & 0xF

                if top4 == 0x1 and n_r == reg and low4 == d4:
                    print(f"\n  *** WRITE FOUND at 0x{saddr:05X}: mov.l R{m_r},@({diff},R{reg})")
                    all_write_sites.append((saddr, f"mov.l R{m_r},@({diff},R{reg})", load_addr, pool_addr))
                    print(disasm_context(saddr, before=30, after=30))

                # Check for register overwrite or rts
                if top4 == 0xD and n_r == reg and saddr != load_addr:
                    break
                if top4 == 0x6 and low4 == 0x3 and n_r == reg:
                    break
                if top4 == 0xE and n_r == reg:
                    break
                if op == 0x000B:
                    break

# ============================================================
# Step 5: Also do a brute-force scan for fmov.s writes where
# the destination register was loaded from a pool entry for FFFF798C
# This catches cases where R0 offset addressing is used
# ============================================================
print("\n" + "=" * 100)
print("BRUTE FORCE: Scanning ALL fmov.s store instructions")
print("=" * 100)

# For every fmov.s FRm,@Rn in the ROM, check if Rn was recently loaded
# with FFFF798C from a literal pool
fmov_stores = []
for addr in range(0, ROM_SIZE - 1, 2):
    op = read_u16(addr)
    top4 = (op >> 12) & 0xF
    low4 = op & 0xF
    n_r = (op >> 8) & 0xF
    m_r = (op >> 4) & 0xF

    # fmov.s FRm,@Rn = FnmA
    if top4 == 0xF and low4 == 0xA:
        # Check backward for mov.l loading FFFF798C into R{n_r}
        for baddr in range(addr - 2, max(0, addr - 200), -2):
            bop = read_u16(baddr)
            btop4 = (bop >> 12) & 0xF
            bn_r = (bop >> 8) & 0xF

            if btop4 == 0xD and bn_r == n_r:
                # mov.l @(disp,PC),Rn
                dd = bop & 0xFF
                pool = ((baddr + 4) & ~3) + dd * 4
                if pool + 3 < len(rom):
                    pval = read_u32(pool)
                    if pval == TARGET_ADDR:
                        # Check that R{n_r} wasn't overwritten between baddr and addr
                        overwritten = False
                        for caddr in range(baddr + 2, addr, 2):
                            cop = read_u16(caddr)
                            ctop4 = (cop >> 12) & 0xF
                            cn_r = (cop >> 8) & 0xF
                            clow4 = cop & 0xF
                            if ctop4 == 0xD and cn_r == n_r:
                                overwritten = True
                                break
                            if ctop4 == 0x6 and clow4 == 0x3 and cn_r == n_r:
                                overwritten = True
                                break
                            if ctop4 == 0xE and cn_r == n_r:
                                overwritten = True
                                break
                        if not overwritten:
                            fmov_stores.append((addr, m_r, n_r, baddr))
                break  # stop searching backward after first mov.l to this reg

if fmov_stores:
    for (saddr, fr, rn, load_addr) in fmov_stores:
        already = any(ws[0] == saddr for ws in all_write_sites)
        if not already:
            desc = f"fmov.s FR{fr},@R{rn}  ; FLOAT WRITE to [{TARGET_ADDR:08X}]"
            all_write_sites.append((saddr, desc, load_addr, None))
            print(f"\n  *** ADDITIONAL WRITE at 0x{saddr:05X}: {desc} (R{rn} loaded at 0x{load_addr:05X})")
else:
    print("  No additional fmov.s stores found targeting FFFF798C")

# ============================================================
# Also brute-force scan for integer mov stores
# ============================================================
print("\n" + "=" * 100)
print("BRUTE FORCE: Scanning ALL mov.l/mov.w/mov.b store instructions")
print("=" * 100)

int_stores_found = 0
for addr in range(0, ROM_SIZE - 1, 2):
    op = read_u16(addr)
    top4 = (op >> 12) & 0xF
    low4 = op & 0xF
    n_r = (op >> 8) & 0xF
    m_r = (op >> 4) & 0xF

    # mov.l Rm,@Rn = 2nm2 / mov.w = 2nm1 / mov.b = 2nm0
    if top4 == 0x2 and low4 in (0, 1, 2):
        dest_reg = n_r
        # Check backward for mov.l loading FFFF798C into dest_reg
        for baddr in range(addr - 2, max(0, addr - 200), -2):
            bop = read_u16(baddr)
            btop4 = (bop >> 12) & 0xF
            bn_r = (bop >> 8) & 0xF

            if btop4 == 0xD and bn_r == dest_reg:
                dd = bop & 0xFF
                pool = ((baddr + 4) & ~3) + dd * 4
                if pool + 3 < len(rom):
                    pval = read_u32(pool)
                    if pval == TARGET_ADDR:
                        overwritten = False
                        for caddr in range(baddr + 2, addr, 2):
                            cop = read_u16(caddr)
                            ctop4 = (cop >> 12) & 0xF
                            cn_r = (cop >> 8) & 0xF
                            clow4 = cop & 0xF
                            if ctop4 == 0xD and cn_r == dest_reg:
                                overwritten = True; break
                            if ctop4 == 0x6 and clow4 == 0x3 and cn_r == dest_reg:
                                overwritten = True; break
                            if ctop4 == 0xE and cn_r == dest_reg:
                                overwritten = True; break
                        if not overwritten:
                            sz = {0:".b",1:".w",2:".l"}[low4]
                            already = any(ws[0] == addr for ws in all_write_sites)
                            if not already:
                                desc = f"mov{sz}  R{m_r},@R{dest_reg}  ; WRITE to [{TARGET_ADDR:08X}]"
                                all_write_sites.append((addr, desc, baddr, pool))
                                print(f"\n  *** ADDITIONAL WRITE at 0x{addr:05X}: {desc} (R{dest_reg} loaded at 0x{baddr:05X})")
                                int_stores_found += 1
                break

if int_stores_found == 0:
    print("  No additional integer stores found targeting FFFF798C")


# ============================================================
# FINAL SUMMARY
# ============================================================
print("\n" + "=" * 100)
print(f"SUMMARY: ALL WRITES TO 0x{TARGET_ADDR:08X}")
print("=" * 100)

if not all_write_sites:
    print("  NO WRITES FOUND!")
else:
    # Deduplicate
    seen = set()
    unique_sites = []
    for ws in all_write_sites:
        if ws[0] not in seen:
            seen.add(ws[0])
            unique_sites.append(ws)

    for i, (saddr, desc, load_addr, pool_addr) in enumerate(unique_sites):
        print(f"\n  Write #{i+1}: ROM 0x{saddr:05X}")
        print(f"    Instruction: {desc}")
        print(f"    Address loaded at: 0x{load_addr:05X}")
        if pool_addr:
            print(f"    Pool entry at: 0x{pool_addr:05X}")

# ============================================================
# DETAILED CONTEXT for each write site
# ============================================================
if all_write_sites:
    seen = set()
    for saddr, desc, load_addr, pool_addr in all_write_sites:
        if saddr in seen:
            continue
        seen.add(saddr)
        print(f"\n{'='*100}")
        print(f"DETAILED CONTEXT: Write at 0x{saddr:05X}")
        print(f"{'='*100}")
        print(disasm_context(saddr, before=40, after=40))

        # Also dump literal pool entries near this code
        # Find the nearest data region (look for cluster of 32-bit values after code)
        func_region_end = saddr + 80  # approximate
        print(f"\n  --- Nearby literal pool entries ---")
        for pa in exact_hits:
            if abs(pa - saddr) < 1200:
                val = read_u32(pa)
                print(f"  Pool 0x{pa:05X}: 0x{val:08X}")
