#!/usr/bin/env python3
"""Disassemble sub_21D9A from Subaru ECU ROM (SH7058, SH-2A, Big-Endian)."""

import struct

ROM_PATH = r"C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin"

with open(ROM_PATH, "rb") as f:
    rom = f.read()

def read16(addr):
    return struct.unpack_from(">H", rom, addr)[0]

def read32(addr):
    return struct.unpack_from(">I", rom, addr)[0]

def sign_extend8(v):
    if v & 0x80:
        return v - 0x100
    return v

def sign_extend12(v):
    if v & 0x800:
        return v - 0x1000
    return v

def disasm_one(pc):
    """Disassemble one SH-2 instruction at pc. Returns (mnemonic, comment, is_rts, branch_target_or_None)."""
    op = read16(pc)
    hi4 = (op >> 12) & 0xF
    n = (op >> 8) & 0xF
    m = (op >> 4) & 0xF
    d = op & 0xFF
    d4 = op & 0xF

    comment = ""
    branch = None

    # Special opcodes
    if op == 0x000B:
        return "rts", "", True, None
    if op == 0x0009:
        return "nop", "", False, None

    # 0x00n9 = movt Rn (move T-bit to Rn)
    if (op & 0xF0FF) == 0x0029:
        return f"movt    R{n}", f"; R{n} = T", False, None

    # mov #imm8, Rn  (0xEnDD)
    if hi4 == 0xE:
        imm = sign_extend8(d)
        return f"mov     #{imm}, R{n}", f"; R{n} = {imm}", False, None

    # mov.l @(disp*4+(PC&~3)+4), Rn  (0xDnDD)
    if hi4 == 0xD:
        pool_addr = (pc & ~3) + 4 + d * 4
        val = read32(pool_addr)
        return f"mov.l   @({d}*4+PC), R{n}", f"; R{n} = [0x{pool_addr:08X}] = 0x{val:08X}", False, None

    # mov.w @(disp*2+PC+4), Rn  (0x9nDD)
    if hi4 == 0x9:
        pool_addr = pc + 4 + d * 2
        val = read16(pool_addr)
        return f"mov.w   @({d}*2+PC), R{n}", f"; R{n} = [0x{pool_addr:06X}] = 0x{val:04X}", False, None

    # 0x6nm? family
    if hi4 == 0x6:
        sub = op & 0xF
        if sub == 0x0:
            return f"mov.b   @R{m}, R{n}", "", False, None
        if sub == 0x3:
            return f"mov     R{m}, R{n}", "", False, None
        if sub == 0xC:
            return f"extu.b  R{m}, R{n}", f"; R{n} = R{m} & 0xFF", False, None
        if sub == 0x6:
            return f"mov.l   @R{m}+, R{n}", "", False, None
        if sub == 0x1:
            return f"mov.w   @R{m}, R{n}", "", False, None
        if sub == 0x2:
            return f"mov.l   @R{m}, R{n}", "", False, None
        if sub == 0x9:
            return f"swap.w  R{m}, R{n}", "", False, None
        if sub == 0xE:
            return f"exts.b  R{m}, R{n}", "", False, None

    # 0x2nm? family
    if hi4 == 0x2:
        sub = op & 0xF
        if sub == 0x0:
            return f"mov.b   R{m}, @R{n}", "", False, None
        if sub == 0x8:
            return f"tst     R{m}, R{n}", "", False, None
        if sub == 0x6:
            return f"mov.l   R{m}, @-R{n}", "", False, None
        if sub == 0x1:
            return f"mov.w   R{m}, @R{n}", "", False, None
        if sub == 0x2:
            return f"mov.l   R{m}, @R{n}", "", False, None

    # 0x4n?? family
    if hi4 == 0x4:
        low8 = op & 0xFF
        if low8 == 0x0B:
            return f"jsr     @R{n}", f"; call R{n}", False, None
        if op == 0x4F22:
            return "sts.l   PR, @-R15", "; push PR", False, None
        if op == 0x4F26:
            return "lds.l   @R15+, PR", "; pop PR", False, None
        if low8 == 0x28:
            return f"shll16  R{n}", "", False, None
        if low8 == 0x29:
            return f"shlr16  R{n}", "", False, None
        if low8 == 0x08:
            return f"shll2   R{n}", "", False, None
        if low8 == 0x09:
            return f"shlr2   R{n}", "", False, None
        if low8 == 0x00:
            return f"shll    R{n}", "", False, None
        if low8 == 0x01:
            return f"shlr    R{n}", "", False, None
        if low8 == 0x15:
            return f"cmp/pl  R{n}", "", False, None
        if low8 == 0x11:
            return f"cmp/pz  R{n}", "", False, None

    # add #imm8, Rn (0x7nDD)
    if hi4 == 0x7:
        imm = sign_extend8(d)
        return f"add     #{imm}, R{n}", "", False, None

    # add Rm, Rn (0x3nmC)
    if hi4 == 0x3:
        sub = op & 0xF
        if sub == 0xC:
            return f"add     R{m}, R{n}", "", False, None
        if sub == 0x0:
            return f"cmp/eq  R{m}, R{n}", "", False, None
        if sub == 0x2:
            return f"cmp/hs  R{m}, R{n}", "", False, None
        if sub == 0x3:
            return f"cmp/ge  R{m}, R{n}", "", False, None
        if sub == 0x6:
            return f"cmp/hi  R{m}, R{n}", "", False, None
        if sub == 0x7:
            return f"cmp/gt  R{m}, R{n}", "", False, None

    # cmp/eq #imm, R0 (0x88DD)
    if (op >> 8) == 0x88:
        imm = sign_extend8(d)
        return f"cmp/eq  #{imm}, R0", f"; T = (R0 == {imm})", False, None

    # Branches
    if (op >> 8) == 0x89:  # bt
        disp = sign_extend8(d)
        target = pc + 4 + disp * 2
        return f"bt      0x{target:05X}", f"; branch if T=1", False, target
    if (op >> 8) == 0x8B:  # bf
        disp = sign_extend8(d)
        target = pc + 4 + disp * 2
        return f"bf      0x{target:05X}", f"; branch if T=0", False, target
    if (op >> 8) == 0x8D:  # bt/s
        disp = sign_extend8(d)
        target = pc + 4 + disp * 2
        return f"bt/s    0x{target:05X}", f"; branch if T=1 (delayed)", False, target
    if (op >> 8) == 0x8F:  # bf/s
        disp = sign_extend8(d)
        target = pc + 4 + disp * 2
        return f"bf/s    0x{target:05X}", f"; branch if T=0 (delayed)", False, target

    # bra (0xAnDD) - 12-bit displacement
    if hi4 == 0xA:
        disp12 = op & 0xFFF
        disp_s = sign_extend12(disp12)
        target = pc + 4 + disp_s * 2
        return f"bra     0x{target:05X}", f"; unconditional branch", False, target

    # bsr (0xBnDD) - 12-bit displacement
    if hi4 == 0xB:
        disp12 = op & 0xFFF
        disp_s = sign_extend12(disp12)
        target = pc + 4 + disp_s * 2
        return f"bsr     0x{target:05X}", f"; call sub", False, target

    # mov.b R0, @(disp, GBR) (0xC0DD)
    if (op >> 8) == 0xC0:
        return f"mov.b   R0, @({d}, GBR)", "", False, None

    # mov.b @(disp, GBR), R0 (0xC4DD)
    if (op >> 8) == 0xC4:
        return f"mov.b   @({d}, GBR), R0", "", False, None

    # mov.b @(disp, Rm), R0  0x84mD
    if (op >> 8) & 0xFF == 0x84:
        rm = (op >> 4) & 0xF
        disp = op & 0xF
        return f"mov.b   @({disp}, R{rm}), R0", "", False, None

    # mov.b R0, @(disp, Rn)  0x80nD
    if (op >> 8) & 0xFF == 0x80:
        rn = (op >> 4) & 0xF
        disp = op & 0xF
        return f"mov.b   R0, @({disp}, R{rn})", "", False, None

    # mov.w @(disp, Rm), R0  0x85mD
    if (op >> 8) == 0x85:
        rm = (op >> 4) & 0xF
        disp = op & 0xF
        return f"mov.w   @({disp}*2, R{rm}), R0", "", False, None

    # 0x0nmC = mov.b @(R0, Rm), Rn
    if hi4 == 0x0 and d4 == 0xC:
        return f"mov.b   @(R0, R{m}), R{n}", "", False, None

    # 0x1nmD = mov.l Rm, @(disp*4, Rn)
    if hi4 == 0x1:
        disp = op & 0xF
        return f"mov.l   R{m}, @({disp}*4, R{n})", "", False, None

    # 0x5nmD = mov.l @(disp*4, Rm), Rn
    if hi4 == 0x5:
        disp = op & 0xF
        return f"mov.l   @({disp}*4, R{m}), R{n}", "", False, None

    return f".word   0x{op:04X}", "; *** UNKNOWN ***", False, None


def disasm_function(start_addr, label="sub"):
    """Disassemble a function from start_addr until RTS + delay slot."""
    print(f"\n{'='*70}")
    print(f"  {label}_{start_addr:05X}  (0x{start_addr:08X})")
    print(f"{'='*70}")

    pc = start_addr
    found_rts = False
    literals = {}  # pool_addr -> value
    ram_addrs = set()
    branch_targets = set()
    subfuncs = set()

    lines = []

    while True:
        opcode = read16(pc)
        mnem, comment, is_rts, btarget = disasm_one(pc)

        # Track literal pool references
        hi4 = (opcode >> 12) & 0xF
        d = opcode & 0xFF
        n = (opcode >> 8) & 0xF
        if hi4 == 0xD:  # mov.l @(disp,PC)
            pool_addr = (pc & ~3) + 4 + d * 4
            val = read32(pool_addr)
            literals[pool_addr] = val
            if 0xFFFF0000 <= val <= 0xFFFFFFFF:
                ram_addrs.add(val)
        if hi4 == 0x9:  # mov.w @(disp,PC)
            pool_addr = pc + 4 + d * 2
            val = read16(pool_addr)
            literals[pool_addr] = val

        if btarget:
            branch_targets.add(btarget)

        # Track BSR targets
        if hi4 == 0xB:
            disp12 = opcode & 0xFFF
            disp_s = sign_extend12(disp12)
            target = pc + 4 + disp_s * 2
            subfuncs.add(target)

        line = f"  {pc:08X}:  {opcode:04X}    {mnem:<30s} {comment}"
        lines.append(line)

        if found_rts:
            # This was the delay slot after RTS
            break

        if is_rts:
            found_rts = True

        pc += 2

        # Safety limit
        if pc - start_addr > 0x200:
            lines.append("  ... (safety limit reached)")
            break

    # Print with branch target markers
    for line in lines:
        addr_str = line.strip().split(":")[0]
        try:
            addr = int(addr_str, 16)
            if addr in branch_targets:
                print(f"  >>> target:")
            print(line)
        except:
            print(line)

    print(f"\n  --- Literal Pool ---")
    for addr in sorted(literals):
        val = literals[addr]
        if val > 0xFFFF:
            print(f"    0x{addr:08X}: 0x{val:08X}", end="")
            if 0xFFFF0000 <= val <= 0xFFFFFFFF:
                print(f"  -> RAM 0x{val:08X}")
            elif val < 0x00200000:
                print(f"  -> ROM sub/data")
            else:
                print()
        else:
            print(f"    0x{addr:08X}: 0x{val:04X}")

    print(f"\n  --- RAM Addresses Referenced ---")
    for addr in sorted(ram_addrs):
        print(f"    0x{addr:08X}")

    return subfuncs


# ============================================================
# Main: disassemble sub_21D9A
# ============================================================
print("=" * 70)
print("  DISASSEMBLY OF sub_21D9A")
print("  ROM: AE5L600L 20g rev 20.5 tiny wrex.bin")
print("=" * 70)

subs_to_trace = disasm_function(0x21D9A, "sub")

# Also disassemble any BSR-called subfunctions
traced = {0x21D9A}
while subs_to_trace - traced:
    next_sub = min(subs_to_trace - traced)
    traced.add(next_sub)
    new_subs = disasm_function(next_sub, "sub")
    subs_to_trace |= new_subs

# ============================================================
# Pseudocode summary
# ============================================================
print("\n")
print("=" * 70)
print("  PSEUDOCODE SUMMARY")
print("=" * 70)
print("""
Based on the disassembly above, here is the reconstructed logic.
(Check the actual disassembly output for the precise flow.)
""")

# Let's also do a raw hex dump of the region for reference
print("\n--- Raw hex dump 0x21D9A - 0x21E00 ---")
for off in range(0x21D9A, 0x21E00, 16):
    hexbytes = " ".join(f"{rom[off+i]:02X}" for i in range(min(16, 0x21E00 - off)))
    print(f"  {off:08X}: {hexbytes}")
