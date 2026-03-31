#!/usr/bin/env python3
"""Disassemble SH-2 function at 0x22F92 from Subaru ECU ROM."""

import struct
import sys

ROM_PATH = r"C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin"

def read_rom(path):
    with open(path, "rb") as f:
        return f.read()

def r16(rom, addr):
    return struct.unpack(">H", rom[addr:addr+2])[0]

def r32(rom, addr):
    return struct.unpack(">I", rom[addr:addr+4])[0]

def s8(v):
    return v - 256 if v > 127 else v

def s12(v):
    return v - 4096 if v > 2047 else v

def classify_addr(a):
    if a >= 0xFFFF0000:
        return f"RAM:{a:08X}"
    elif a >= 0x000A0000:
        return f"CAL:{a:08X}"
    else:
        return f"ROM_func:{a:08X}"

REG = [f"R{i}" for i in range(16)]

def disasm_one(rom, pc):
    """Disassemble one 16-bit SH-2 instruction at pc. Returns (mnemonic, comment, branch_target_or_None)."""
    op = r16(rom, pc)
    hi4 = (op >> 12) & 0xF
    lo4 = op & 0xF
    n = (op >> 8) & 0xF
    m = (op >> 4) & 0xF
    d8 = op & 0xFF
    d12 = op & 0xFFF
    comment = ""
    branch = None

    # Special exact matches first
    if op == 0x000B:
        return "rts", "", None
    if op == 0x0009:
        return "nop", "", None

    # 0xEnDD mov #imm8,Rn
    if hi4 == 0xE:
        imm = s8(d8)
        return f"mov #{imm},{REG[n]}", f"; {REG[n]}={imm}", None

    # 0xDnDD mov.l @(disp*4+(PC&~3)+4),Rn
    if hi4 == 0xD:
        disp = d8
        pool_addr = (pc & ~3) + 4 + disp * 4
        val = r32(rom, pool_addr)
        cl = classify_addr(val)
        return f"mov.l @({disp}*4,PC),{REG[n]}", f"; [{pool_addr:05X}]={val:08X} ({cl})", None

    # 0x9nDD mov.w @(disp*2+PC+4),Rn
    if hi4 == 0x9:
        disp = d8
        pool_addr = pc + 4 + disp * 2
        val = r16(rom, pool_addr)
        return f"mov.w @({disp}*2,PC),{REG[n]}", f"; [{pool_addr:05X}]={val:04X}", None

    # 0x6nm? family
    if hi4 == 0x6:
        if lo4 == 0x0:
            return f"mov.b @{REG[m]},{REG[n]}", "", None
        if lo4 == 0x1:
            return f"mov.w @{REG[m]},{REG[n]}", "", None
        if lo4 == 0x2:
            return f"mov.l @{REG[m]},{REG[n]}", "", None
        if lo4 == 0x3:
            return f"mov {REG[m]},{REG[n]}", "", None
        if lo4 == 0x6:
            return f"mov.l @{REG[m]}+,{REG[n]}", "", None
        if lo4 == 0xC:
            return f"extu.b {REG[m]},{REG[n]}", "", None
        if lo4 == 0xD:
            return f"extu.w {REG[m]},{REG[n]}", "", None
        if lo4 == 0xE:
            return f"exts.b {REG[m]},{REG[n]}", "", None

    # 0x2nm? family
    if hi4 == 0x2:
        if lo4 == 0x0:
            return f"mov.b {REG[m]},@{REG[n]}", "", None
        if lo4 == 0x1:
            return f"mov.w {REG[m]},@{REG[n]}", "", None
        if lo4 == 0x2:
            return f"mov.l {REG[m]},@{REG[n]}", "", None
        if lo4 == 0x6:
            return f"mov.l {REG[m]},@-{REG[n]}", "", None
        if lo4 == 0x8:
            return f"tst {REG[m]},{REG[n]}", "", None
        if lo4 == 0x9:
            return f"and {REG[m]},{REG[n]}", "", None
        if lo4 == 0xB:
            return f"or {REG[m]},{REG[n]}", "", None

    # 0x4n?? family
    if hi4 == 0x4:
        lo8 = op & 0xFF
        if lo8 == 0x0B:
            return f"jsr @{REG[n]}", "", "jsr"
        if lo8 == 0x2B:
            return f"jmp @{REG[n]}", "", "jmp"
        if lo8 == 0x22:
            return f"sts.l PR,@-{REG[n]}", "", None
        if lo8 == 0x26:
            return f"lds.l @{REG[n]}+,PR", "", None
        if lo8 == 0x11:
            return f"cmp/pz {REG[n]}", "", None
        if lo8 == 0x15:
            return f"cmp/pl {REG[n]}", "", None
        if lo8 == 0x18:
            return f"shll8 {REG[n]}", "", None
        if lo8 == 0x19:
            return f"shlr8 {REG[n]}", "", None
        if lo8 == 0x28:
            return f"shll16 {REG[n]}", "", None
        if lo8 == 0x29:
            return f"shlr16 {REG[n]}", "", None
        if lo8 == 0x00:
            return f"shll {REG[n]}", "", None
        if lo8 == 0x01:
            return f"shlr {REG[n]}", "", None
        if lo8 == 0x04:
            return f"rotl {REG[n]}", "", None
        if lo8 == 0x05:
            return f"rotr {REG[n]}", "", None

    # 0x7nDD add #imm8,Rn
    if hi4 == 0x7:
        imm = s8(d8)
        return f"add #{imm},{REG[n]}", "", None

    # 0x3nm? family
    if hi4 == 0x3:
        if lo4 == 0xC:
            return f"add {REG[m]},{REG[n]}", "", None
        if lo4 == 0x0:
            return f"cmp/eq {REG[m]},{REG[n]}", "", None
        if lo4 == 0x2:
            return f"cmp/hs {REG[m]},{REG[n]}", "", None
        if lo4 == 0x3:
            return f"cmp/ge {REG[m]},{REG[n]}", "", None
        if lo4 == 0x6:
            return f"cmp/hi {REG[m]},{REG[n]}", "", None
        if lo4 == 0x7:
            return f"cmp/gt {REG[m]},{REG[n]}", "", None
        if lo4 == 0x8:
            return f"sub {REG[m]},{REG[n]}", "", None
        if lo4 == 0xE:
            return f"addc {REG[m]},{REG[n]}", "", None

    # 0x88DD cmp/eq #imm,R0
    if (op >> 8) == 0x88:
        imm = s8(d8)
        return f"cmp/eq #{imm},R0", "", None

    # 0x89DD bt disp
    if (op >> 8) == 0x89:
        disp = s8(d8)
        target = pc + 4 + disp * 2
        return f"bt {target:05X}", f"; disp={disp}", target

    # 0x8BDD bf disp
    if (op >> 8) == 0x8B:
        disp = s8(d8)
        target = pc + 4 + disp * 2
        return f"bf {target:05X}", f"; disp={disp}", target

    # 0x8DDD bt/s disp
    if (op >> 8) == 0x8D:
        disp = s8(d8)
        target = pc + 4 + disp * 2
        return f"bt/s {target:05X}", f"; disp={disp}", target

    # 0x8FDD bf/s disp
    if (op >> 8) == 0x8F:
        disp = s8(d8)
        target = pc + 4 + disp * 2
        return f"bf/s {target:05X}", f"; disp={disp}", target

    # 0xAnDD bra disp12
    if hi4 == 0xA:
        disp = s12(d12)
        target = pc + 4 + disp * 2
        return f"bra {target:05X}", f"; disp={disp}", target

    # 0xBnDD bsr disp12
    if hi4 == 0xB:
        disp = s12(d12)
        target = pc + 4 + disp * 2
        return f"bsr {target:05X}", f"; disp={disp}", target

    # 0xC0DD mov.b R0,@(disp,GBR)
    if (op >> 8) == 0xC0:
        return f"mov.b R0,@({d8},GBR)", "", None

    # 0xC4DD mov.b @(disp,GBR),R0
    if (op >> 8) == 0xC4:
        return f"mov.b @({d8},GBR),R0", "", None

    # 0xC8DD tst #imm,R0
    if (op >> 8) == 0xC8:
        return f"tst #{d8},R0", f"; 0x{d8:02X}", None

    # 0xC9DD and #imm,R0
    if (op >> 8) == 0xC9:
        return f"and #{d8},R0", f"; 0x{d8:02X}", None

    # 0xCBDD or #imm,R0
    if (op >> 8) == 0xCB:
        return f"or #{d8},R0", f"; 0x{d8:02X}", None

    # 0x0nm7 mul.l Rm,Rn
    if hi4 == 0x0 and lo4 == 0x7:
        return f"mul.l {REG[m]},{REG[n]}", "", None

    # 0x001A sts MACL,Rn  (actually 0x0n1A)
    if hi4 == 0x0 and (op & 0xFF) == 0x1A:
        return f"sts MACL,{REG[n]}", "", None

    # 0x0n0A sts MACH,Rn
    if hi4 == 0x0 and (op & 0xFF) == 0x0A:
        return f"sts MACH,{REG[n]}", "", None

    # 0x80nm mov.b R0,@(disp,Rn) — actually 0x80nD
    if (op >> 8) == 0x80:
        disp_4 = op & 0xF
        rm = (op >> 4) & 0xF
        return f"mov.b R0,@({disp_4},{REG[rm]})", "", None

    # 0x84nm mov.b @(disp,Rm),R0
    if (op >> 8) == 0x84:
        disp_4 = op & 0xF
        rm = (op >> 4) & 0xF
        return f"mov.b @({disp_4},{REG[rm]}),R0", "", None

    # 0x85nm mov.w @(disp*2,Rm),R0
    if (op >> 8) == 0x85:
        disp_4 = op & 0xF
        rm = (op >> 4) & 0xF
        return f"mov.w @({disp_4}*2,{REG[rm]}),R0", "", None

    # 0x1nmD mov.l Rm,@(disp*4,Rn)
    if hi4 == 0x1:
        disp_4 = op & 0xF
        return f"mov.l {REG[m]},@({disp_4}*4,{REG[n]})", "", None

    # 0x5nmD mov.l @(disp*4,Rm),Rn
    if hi4 == 0x5:
        disp_4 = op & 0xF
        return f"mov.l @({disp_4}*4,{REG[m]}),{REG[n]}", "", None

    return f".word 0x{op:04X}", "; UNKNOWN", None


def disasm_function(rom, start_addr, label="sub"):
    """Disassemble from start_addr until RTS + delay slot."""
    print(f"\n{'='*70}")
    print(f"  Disassembly of {label}_{start_addr:05X}  (start: 0x{start_addr:05X})")
    print(f"{'='*70}\n")

    pc = start_addr
    found_rts = False
    literals = []
    ram_refs = []
    cal_refs = []
    rom_refs = []
    max_addr = start_addr + 0x200  # safety limit

    while pc < max_addr:
        op = r16(rom, pc)
        mnem, comment, branch = disasm_one(rom, pc)

        # Collect literal pool refs
        if (op >> 12) == 0xD:  # mov.l @(disp,PC)
            disp = op & 0xFF
            pool_addr = (pc & ~3) + 4 + disp * 4
            val = r32(rom, pool_addr)
            cl = classify_addr(val)
            literals.append((pool_addr, val, cl))
            if val >= 0xFFFF0000:
                ram_refs.append(val)
            elif val >= 0x000A0000:
                cal_refs.append(val)
            else:
                rom_refs.append(val)

        print(f"  {pc:05X}:  {op:04X}    {mnem:30s} {comment}")

        if found_rts:
            # This was the delay slot
            print()
            break

        if op == 0x000B:
            found_rts = True

        pc += 2

    return literals, ram_refs, cal_refs, rom_refs


def main():
    rom = read_rom(ROM_PATH)
    print(f"ROM loaded: {len(rom)} bytes ({len(rom)/1024:.0f} KB)")

    # Disassemble main function
    literals, ram_refs, cal_refs, rom_refs = disasm_function(rom, 0x22F92, "sub")

    # Check if it's a short wrapper that calls/jumps to another function
    # Scan for jsr/bsr targets
    pc = 0x22F92
    call_targets = []
    for i in range(50):  # scan up to 50 instructions
        op = r16(rom, pc)
        hi4 = (op >> 12) & 0xF
        if hi4 == 0xB:  # bsr
            disp = s12(op & 0xFFF)
            target = pc + 4 + disp * 2
            call_targets.append(("bsr", target))
        if hi4 == 0x4 and (op & 0xFF) == 0x0B:  # jsr @Rn
            n = (op >> 8) & 0xF
            call_targets.append(("jsr", f"@R{n}"))
        if op == 0x000B:
            break
        pc += 2

    # If there are subroutine calls, trace them
    for ctype, target in call_targets:
        if isinstance(target, int):
            print(f"\n  >>> Tracing called subroutine: {ctype} to 0x{target:05X}")
            disasm_function(rom, target, "sub")

    # Summary
    print(f"\n{'='*70}")
    print("  LITERAL POOL REFERENCES")
    print(f"{'='*70}")
    seen = set()
    for pool_addr, val, cl in literals:
        key = (pool_addr, val)
        if key not in seen:
            seen.add(key)
            print(f"  [{pool_addr:05X}] -> {val:08X}  ({cl})")

    if ram_refs:
        print(f"\n  RAM addresses referenced:")
        for a in sorted(set(ram_refs)):
            print(f"    {a:08X}")

    if cal_refs:
        print(f"\n  CAL/table addresses referenced:")
        for a in sorted(set(cal_refs)):
            print(f"    {a:08X}")

    if rom_refs:
        print(f"\n  ROM/function addresses referenced:")
        for a in sorted(set(rom_refs)):
            print(f"    {a:08X}")

    # Now produce pseudocode by re-reading the instructions
    print(f"\n{'='*70}")
    print("  PSEUDOCODE ANALYSIS")
    print(f"{'='*70}")
    print()
    print("  Analyzing instruction flow...")
    print()

    # Re-read all instructions for analysis
    pc = 0x22F92
    instrs = []
    while True:
        op = r16(rom, pc)
        mnem, comment, branch = disasm_one(rom, pc)
        instrs.append((pc, op, mnem, comment, branch))
        if len(instrs) >= 2 and instrs[-2][1] == 0x000B:
            break
        if pc > 0x22F92 + 0x200:
            break
        pc += 2

    # Print raw hex dump of the function
    print("  Raw hex dump:")
    start = 0x22F92
    end = instrs[-1][0] + 2
    for addr in range(start, end, 2):
        val = r16(rom, addr)
        if (addr - start) % 16 == 0:
            if addr != start:
                print()
            print(f"  {addr:05X}: ", end="")
        print(f"{val:04X} ", end="")
    print("\n")


if __name__ == "__main__":
    main()
