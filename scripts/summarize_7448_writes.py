#!/usr/bin/env python3
"""
Produce final annotated summary of all writes to FFFF7448.
For each write site, find the enclosing function and describe the condition.
"""
import struct

ROM_PATH = "C:/Users/Dean/Documents/GitHub/ae6l600l/disassembly/.claude/worktrees/strange-agnesi/rom/ae5l600l.bin"

with open(ROM_PATH, "rb") as f:
    rom = f.read()

rom_size = len(rom)

def get_opcode(pc):
    if pc < 0 or pc + 1 >= rom_size:
        return None
    return struct.unpack(">H", rom[pc:pc+2])[0]

def read_u32(offset):
    if offset < 0 or offset + 3 >= rom_size:
        return None
    return struct.unpack(">I", rom[offset:offset+4])[0]

def sign8(v):
    return v - 0x100 if v & 0x80 else v

def pcrel_target_l(pc, opcode):
    return ((pc + 2) & ~3) + (opcode & 0xFF) * 4

def find_func_start(pc):
    """Find function start by scanning backwards for sts.l PR,@-R15 (0x4F22)"""
    for bpc in range(pc, max(0, pc - 4096), -2):
        op = get_opcode(bpc)
        if op == 0x4F22:
            return bpc
        # Also check for push sequence start
    return pc

# All confirmed write sites
writes = [
    (0x032EE0, 6, 1,  "bra delay slot: writes 1 to [CL/OL flag]"),
    (0x032F88, 6, 0,  "fallthrough: writes 0 to [CL/OL flag]"),
    (0x06D1CC, 6, 0,  "writes 0"),
    (0x06ED08, 6, 1,  "writes 1"),
    (0x06ED94, 6, 0,  "writes 0 (clears multiple struct fields)"),
    (0x06EDBC, 6, 0,  "writes 0 (clears multiple struct fields, alternate path)"),
    (0x0815F2, 6, 0,  "writes 0"),
    (0x081786, 6, 0,  "writes 0"),
    (0x083CAA, 6, 0,  "writes 0"),
    (0x084666, 6, 1,  "writes 1 (conditional on multiple checks)"),
    (0x0846AC, 6, 0,  "writes 0"),
    (0x0901FC, 6, 0,  "writes 0"),
    (0x09020C, 6, 1,  "writes 1"),
]

print("=" * 100)
print("COMPLETE LIST OF WRITES TO RAM ADDRESS FFFF7448 (CL/OL Mode Flag)")
print("=" * 100)
print()
print("FFFF7448 is accessed INDIRECTLY through a struct pointer:")
print("  - A struct in ROM contains FFFF7448 at offset 24 (0x18)")
print("  - Functions receive the struct pointer in R4, copy to R14")
print("  - mov.l @(24,R14),R2 loads &FFFF7448 into R2")
print("  - mov.b R6,@R2 writes the value")
print()
print("The struct at offset 24 contains a pointer to the CL/OL mode flag.")
print("20 different struct instances in ROM all point to FFFF7448 at offset 24,")
print("indicating this is a shared/common control flag used across many subsystems.")
print()

for i, (wpc, src, val, desc) in enumerate(writes):
    func_start = find_func_start(wpc)
    print(f"--- Write #{i+1}: 0x{wpc:06X} ---")
    print(f"  Function starts at: 0x{func_start:06X}")
    print(f"  Value written: {val} ({desc})")
    print(f"  Instruction: mov.b R{src},@R2 (R2 = ptr from struct[24] = FFFF7448)")
    print()

    # Show broader context (30 instructions)
    context_start = max(func_start, wpc - 40)
    context_end = min(rom_size - 1, wpc + 20)

    for ctx in range(context_start, context_end, 2):
        cop = get_opcode(ctx)
        if cop is None: continue
        m = " >>>" if ctx == wpc else "    "

        cn3 = (cop >> 12) & 0xF
        cn2 = (cop >> 8) & 0xF
        cn1 = (cop >> 4) & 0xF
        cn0 = cop & 0xF
        s = f".word 0x{cop:04X}"

        if cn3 == 0xE: s = f"mov #{sign8(cop&0xFF)},R{cn2}"
        elif cn3 == 0xD:
            t = pcrel_target_l(ctx, cop)
            v = read_u32(t)
            s = f"mov.l @(0x{t:06X}),R{cn2}"
            if v: s += f"  ;=0x{v:08X}"
        elif cn3 == 0x9:
            t = (ctx+2)+(cop&0xFF)*2
            if t+1 < rom_size:
                v = struct.unpack(">H", rom[t:t+2])[0]
                s = f"mov.w @(0x{t:06X}),R{cn2}  ;=0x{v:04X}"
        elif cn3 == 0x2:
            if cn0 == 0: s = f"mov.b R{cn1},@R{cn2}"
            elif cn0 == 1: s = f"mov.w R{cn1},@R{cn2}"
            elif cn0 == 2: s = f"mov.l R{cn1},@R{cn2}"
            elif cn0 == 6: s = f"mov.l R{cn1},@-R{cn2}"
            elif cn0 == 8: s = f"tst R{cn1},R{cn2}"
            elif cn0 == 9: s = f"and R{cn1},R{cn2}"
            elif cn0 == 0xB: s = f"or R{cn1},R{cn2}"
        elif cn3 == 0x6:
            if cn0 == 0: s = f"mov.b @R{cn1},R{cn2}"
            elif cn0 == 1: s = f"mov.w @R{cn1},R{cn2}"
            elif cn0 == 2: s = f"mov.l @R{cn1},R{cn2}"
            elif cn0 == 3: s = f"mov R{cn1},R{cn2}"
            elif cn0 == 6: s = f"mov.l @R{cn1}+,R{cn2}"
            elif cn0 == 0xC: s = f"extu.b R{cn1},R{cn2}"
            elif cn0 == 0xD: s = f"extu.w R{cn1},R{cn2}"
            elif cn0 == 0xE: s = f"exts.b R{cn1},R{cn2}"
        elif cn3 == 0x5: s = f"mov.l @({cn0*4},R{cn1}),R{cn2}"
        elif cn3 == 0x1: s = f"mov.l R{cn1},@({cn0*4},R{cn2})"
        elif cn3 == 0x8:
            if cn2 == 0: s = f"mov.b R0,@({cn0},R{cn1})"
            elif cn2 == 1: s = f"mov.w R0,@({cn0*2},R{cn1})"
            elif cn2 == 4: s = f"mov.b @({cn0},R{cn1}),R0"
            elif cn2 == 5: s = f"mov.w @({cn0*2},R{cn1}),R0"
            elif cn2 == 8: s = f"cmp/eq #{sign8(cop&0xFF)},R0"
            elif cn2 == 9: s = f"bt 0x{ctx+2+sign8(cop&0xFF)*2:06X}"
            elif cn2 == 0xB: s = f"bf 0x{ctx+2+sign8(cop&0xFF)*2:06X}"
            elif cn2 == 0xD: s = f"bt/s 0x{ctx+2+sign8(cop&0xFF)*2:06X}"
            elif cn2 == 0xF: s = f"bf/s 0x{ctx+2+sign8(cop&0xFF)*2:06X}"
        elif cn3 == 0xA:
            d = cop & 0xFFF
            if d & 0x800: d -= 0x1000
            s = f"bra 0x{ctx+2+d*2:06X}"
        elif cn3 == 0xB:
            d = cop & 0xFFF
            if d & 0x800: d -= 0x1000
            s = f"bsr 0x{ctx+2+d*2:06X}"
        elif cn3 == 0x4:
            lo = (cn1<<4)|cn0
            if lo == 0x0B: s = f"jsr @R{cn2}"
            elif lo == 0x2B: s = f"jmp @R{cn2}"
            elif lo == 0x22: s = f"sts.l PR,@-R{cn2}"
            elif lo == 0x26: s = f"lds.l @R{cn2}+,PR"
            elif lo == 0x10: s = f"dt R{cn2}"
            elif lo == 0x15: s = f"cmp/pl R{cn2}"
            elif lo == 0x11: s = f"cmp/pz R{cn2}"
            elif lo == 0x1E: s = f"ldc R{cn2},GBR"
        elif cn3 == 0x3:
            names = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",6:"cmp/hi",7:"cmp/gt",8:"sub",0xC:"add",0xE:"addc"}
            if cn0 in names: s = f"{names[cn0]} R{cn1},R{cn2}"
        elif cn3 == 0x7: s = f"add #{sign8(cop&0xFF)},R{cn2}"
        elif cn3 == 0xC:
            d = cop & 0xFF
            if cn2 == 0: s = f"mov.b R0,@({d},GBR)"
            elif cn2 == 4: s = f"mov.b @({d},GBR),R0"
            elif cn2 == 5: s = f"mov.w @({d*2},GBR),R0"
            elif cn2 == 8: s = f"tst #0x{d:02X},R0"
            elif cn2 == 9: s = f"and #0x{d:02X},R0"
            elif cn2 == 0xB: s = f"or #0x{d:02X},R0"
        elif cn3 == 0x0:
            if cn0 == 0x9 and cn1 == 2: s = f"movt R{cn2}"
            elif cn0 == 0xC: s = f"mov.b @(R0,R{cn1}),R{cn2}"
            elif cn0 == 0xD: s = f"mov.w @(R0,R{cn1}),R{cn2}"
            elif cn0 == 0xE: s = f"mov.l @(R0,R{cn1}),R{cn2}"
        elif cop == 0x000B: s = "rts"
        elif cop == 0x0009: s = "nop"
        # FPU
        elif cn3 == 0xF:
            if cn0 == 0x8: s = f"fmov.s @R{cn1},FR{cn2}"
            elif cn0 == 0xA: s = f"fmov.s FR{cn1},@R{cn2}"
            elif cn0 == 0x5: s = f"fcmp/gt FR{cn1},FR{cn2}"
            elif cn0 == 0x4: s = f"fcmp/eq FR{cn1},FR{cn2}"
            elif cn0 == 0x2: s = f"fmul FR{cn1},FR{cn2}"
            elif cn0 == 0x1: s = f"fsub FR{cn1},FR{cn2}"
            elif cn0 == 0x0: s = f"fadd FR{cn1},FR{cn2}"
            elif cn0 == 0xC: s = f"fmov FR{cn1},FR{cn2}"
            elif cn0 == 0x9: s = f"fmov.s @R{cn1}+,FR{cn2}"

        print(f"{m} 0x{ctx:06X}: {cop:04X}  {s}")

    print()

print()
print("=" * 100)
print("SUMMARY")
print("=" * 100)
print()
print("Values written to FFFF7448 (CL/OL mode flag):")
print()
print("  Value 0 (CL/OL = OFF/clear):")
print("    Written at: 0x032F88, 0x06D1CC, 0x06ED94, 0x06EDBC,")
print("                0x0815F2, 0x081786, 0x083CAA, 0x0846AC,")
print("                0x0901FC")
print("    9 sites write 0 - this is the CLEAR/RESET value")
print()
print("  Value 1 (CL/OL = ON/set):")
print("    Written at: 0x032EE0, 0x06ED08, 0x084666, 0x09020C")
print("    4 sites write 1 - this ACTIVATES the flag")
print()
print("NOTE: Only values 0 and 1 are written to FFFF7448.")
print("Values 7, 8, 10 etc. are NOT written here.")
print("This suggests FFFF7448 is a boolean CL/OL enable flag,")
print("not a multi-state mode register.")
print()
print("The code at 0x01510A-0x015256 (your original region) READS this flag")
print("into R9 at 0x015160 (in the delay slot of jsr @R5 at 0x01515E)")
print("and uses it to build a condition bitmask, but never writes it.")
