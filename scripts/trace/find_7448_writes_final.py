#!/usr/bin/env python3
"""
Find all writes to FFFF7448 via the indirect struct pattern:
1. Function receives struct pointer in R4, copies to callee-saved reg (R8-R14)
2. mov.l @(24,Rbase),R2 loads the pointer to FFFF7448
3. mov.b Rm,@R2 writes to FFFF7448

Search pattern:
- Find all mov.l @(24,Rn),R2 (opcode: 0101 0010 nnnn 0110 = 52n6)
  where n=any register
- Then check if Rn points to a struct with FFFF7448 at offset 24
- Look forward for mov.b Rm,@R2
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

# Step 1: Find all structs with FFFF7448 at offset 24
struct_bases = set()
for pos in range(0, rom_size - 28, 4):
    v = read_u32(pos + 24)
    if v == 0xFFFF7448:
        # Verify this looks like a struct (not just random data)
        # Check that struct[0] looks like a valid address
        v0 = read_u32(pos)
        if v0 is not None and (0 < v0 < rom_size or 0xFFFF0000 <= v0 <= 0xFFFFFFFF):
            struct_bases.add(pos)

print(f"Found {len(struct_bases)} struct bases with FFFF7448 at offset 24")

# Step 2: Find all mov.l @(disp,Rn),Rm instructions in the ROM
# where the source register points to one of these structs
# 0101 mmmm nnnn dddd -> mov.l @(disp*4,Rn),Rm
# We want disp=6 (offset 24) and Rm = any register (the pointer to FFFF7448)

# But the struct pointer is loaded into a register at runtime,
# so we can't statically determine if Rn points to a struct.
# Instead, let's find all literal pool loads that load struct base addresses.

struct_load_sites = {}  # pc -> (rn, struct_base)
for sbase in struct_bases:
    tb = struct.pack(">I", sbase)
    pos = 0
    while True:
        pos = rom.find(tb, pos)
        if pos == -1: break
        # Find instructions that load this literal
        for pc in range(max(0, pos - 1020), pos + 2, 2):
            op = get_opcode(pc)
            if op is None: continue
            if (op >> 12) == 0xD:
                rn = (op >> 8) & 0xF
                if pcrel_target_l(pc, op) == pos:
                    v = read_u32(pos)
                    if v == sbase:
                        struct_load_sites[pc] = (rn, sbase)
        pos += 1

print(f"Found {len(struct_load_sites)} instructions that load struct base addresses")
print()

# Step 3: For each struct load, scan forward for:
# a) mov Rn,R14 (or other callee-saved) - struct pointer saved
# b) mov.l @(24,Rbase),R2 - load pointer to FFFF7448
# c) mov.b Rm,@R2 - write through pointer

all_writes = []

for load_pc in sorted(struct_load_sites.keys()):
    rn, sbase = struct_load_sites[load_pc]

    # Track which register(s) hold the struct pointer
    struct_regs = {rn}

    # Scan forward
    for spc in range(load_pc + 2, min(rom_size - 1, load_pc + 2048), 2):
        op = get_opcode(spc)
        if op is None: break

        n3 = (op >> 12) & 0xF
        n2 = (op >> 8) & 0xF
        n1 = (op >> 4) & 0xF
        n0 = op & 0xF

        # Check for mov Rn,Rm (copy struct pointer)
        if n3 == 0x6 and n0 == 0x3 and n1 in struct_regs:
            struct_regs.add(n2)

        # Check if any struct reg is overwritten
        if n3 == 0xD and n2 in struct_regs and n2 != rn:
            # litpool load overwrites reg
            t = pcrel_target_l(spc, op)
            v = read_u32(t)
            if v != sbase:
                struct_regs.discard(n2)

        # Check for mov.l @(24,Rbase),Rm -> Rm = &FFFF7448
        # opcode: 0101 mmmm nnnn 0110 where disp=6 (6*4=24)
        if n3 == 0x5 and n0 == 6 and n1 in struct_regs:
            ptr_reg = n2  # This register now holds &FFFF7448
            # Scan forward for mov.b Rm,@ptr_reg
            for wpc in range(spc + 2, min(rom_size - 1, spc + 100), 2):
                wop = get_opcode(wpc)
                if wop is None: break

                wn3 = (wop >> 12) & 0xF
                wn2 = (wop >> 8) & 0xF
                wn1 = (wop >> 4) & 0xF
                wn0 = wop & 0xF

                # mov.b Rm,@Rn where Rn == ptr_reg
                if wn3 == 0x2 and wn0 == 0x0 and wn2 == ptr_reg:
                    src_reg = wn1
                    # Trace source value
                    src_val = "?"
                    for bpc in range(wpc - 2, max(spc - 20, wpc - 60), -2):
                        bop = get_opcode(bpc)
                        if bop is None: break
                        bn3 = (bop >> 12) & 0xF
                        bn2 = (bop >> 8) & 0xF
                        if bn3 == 0xE and bn2 == src_reg:
                            src_val = f"#{sign8(bop & 0xFF)}"
                            break
                        if bn3 == 0x6 and bn2 == src_reg:
                            bn0 = bop & 0xF
                            bn1 = (bop >> 4) & 0xF
                            if bn0 == 0: src_val = f"byte[@R{bn1}]"; break
                            if bn0 == 3:
                                # Follow copy
                                for bpc2 in range(bpc - 2, max(spc - 40, bpc - 40), -2):
                                    bop2 = get_opcode(bpc2)
                                    if bop2 is None: break
                                    if (bop2 >> 12) == 0xE and ((bop2 >> 8) & 0xF) == bn1:
                                        src_val = f"#{sign8(bop2 & 0xFF)} (via R{bn1})"
                                        break
                                break
                            if bn0 == 0xC: src_val = f"extu.b(R{bn1})"; break
                            break

                    all_writes.append((wpc, src_reg, src_val, spc, load_pc, sbase, ptr_reg))

                # Check if ptr_reg is overwritten
                if wn2 == ptr_reg and wn3 in (0xD, 0x9, 0xE, 0x5):
                    break
                if wn3 == 0x6 and wn2 == ptr_reg:
                    break
                if wn3 == 0x7 and wn2 == ptr_reg:
                    break

                if wop == 0x000B:  # rts
                    break

        if op == 0x000B:  # rts
            break

# Also check: struct pointer passed as R4, function copies to R14
# Pattern: mov R4,R14 at function entry
# Then mov.l @(24,R14),R2
# Then mov.b Rm,@R2
# The struct base would be loaded OUTSIDE the function (in the caller)

# Let's find all mov.l @(6*4,R14),R2 = mov.l @(24,R14),R2
# opcode = 0101 0010 1110 0110 = 0x52E6
print("=== Searching for mov.l @(24,R14),R2 pattern ===")
for pc in range(0, rom_size - 1, 2):
    op = get_opcode(pc)
    if op == 0x52E6:  # mov.l @(24,R14),R2
        # Scan forward for mov.b Rm,@R2
        for wpc in range(pc + 2, min(rom_size - 1, pc + 80), 2):
            wop = get_opcode(wpc)
            if wop is None: break
            wn3 = (wop >> 12) & 0xF
            wn2 = (wop >> 8) & 0xF
            wn1 = (wop >> 4) & 0xF
            wn0 = wop & 0xF

            if wn3 == 0x2 and wn0 == 0x0 and wn2 == 2:  # mov.b Rm,@R2
                src = wn1
                # Check R2 wasn't overwritten
                r2_ok = True
                for cpc in range(pc + 2, wpc, 2):
                    cop = get_opcode(cpc)
                    if cop is None: break
                    cn3 = (cop >> 12) & 0xF
                    cn2 = (cop >> 8) & 0xF
                    cn0 = cop & 0xF
                    if cn2 == 2 and cn3 in (0xD, 0x9, 0xE, 0x5, 0x6, 0x7):
                        if not (cn3 == 0x2 and cn0 == 0):  # don't count store as overwrite
                            r2_ok = False
                            break
                    if cn3 == 0x3 and cn2 == 2 and cn0 in (0x4,0x8,0xA,0xB,0xC,0xE,0xF):
                        r2_ok = False
                        break

                if r2_ok:
                    # Find what value is in src
                    src_val = "?"
                    for bpc in range(wpc - 2, max(pc - 20, wpc - 60), -2):
                        bop = get_opcode(bpc)
                        if bop is None: break
                        bn3 = (bop >> 12) & 0xF
                        bn2 = (bop >> 8) & 0xF
                        if bn3 == 0xE and bn2 == src:
                            src_val = f"#{sign8(bop & 0xFF)}"
                            break

                    all_writes.append((wpc, src, src_val, pc, 0, 0, 2))

            # Stop conditions
            if wn2 == 2 and wn3 in (0xD, 0x9, 0xE, 0x5):
                break
            if wn3 == 0x6 and wn2 == 2:
                break
            if wop == 0x000B:
                break

# Deduplicate
seen = set()
unique_writes = []
for w in all_writes:
    if w[0] not in seen:
        seen.add(w[0])
        unique_writes.append(w)

print()
print("=" * 100)
print(f"ALL WRITES TO FFFF7448 (via struct offset 24)")
print("=" * 100)

for wpc, src, src_val, ldpc, load_pc, sbase, ptr_reg in sorted(unique_writes):
    print(f"\n  WRITE at 0x{wpc:06X}: mov.b R{src},@R{ptr_reg}  (value={src_val})")
    if sbase:
        print(f"    Struct base: 0x{sbase:06X}, loaded at 0x{load_pc:06X}")
    print(f"    Pointer loaded at 0x{ldpc:06X}: mov.l @(24,R14),R2")

    # Show context
    for ctx in range(wpc - 20, wpc + 8, 2):
        cop = get_opcode(ctx)
        if cop is None: continue
        m = ">>>" if ctx == wpc else "   "
        cn3 = (cop >> 12) & 0xF
        cn2 = (cop >> 8) & 0xF
        cn1 = (cop >> 4) & 0xF
        cn0 = cop & 0xF
        s = f"0x{cop:04X}"
        if cn3 == 0xE: s = f"mov #{sign8(cop&0xFF)},R{cn2}"
        elif cn3 == 0xD:
            t = pcrel_target_l(ctx, cop)
            v = read_u32(t)
            s = f"mov.l ;=0x{v:08X}" if v else f"mov.l @(0x{t:06X}),R{cn2}"
        elif cn3 == 0x2 and cn0 == 0: s = f"mov.b R{cn1},@R{cn2}"
        elif cn3 == 0x5: s = f"mov.l @({cn0*4},R{cn1}),R{cn2}"
        elif cn3 == 0x6 and cn0 == 0: s = f"mov.b @R{cn1},R{cn2}"
        elif cn3 == 0x6 and cn0 == 3: s = f"mov R{cn1},R{cn2}"
        elif cn3 == 0x6 and cn0 == 0xC: s = f"extu.b R{cn1},R{cn2}"
        elif cn3 == 0x8:
            if cn2==8: s=f"cmp/eq #{sign8(cop&0xFF)},R0"
            elif cn2==9: s=f"bt 0x{ctx+2+sign8(cop&0xFF)*2:06X}"
            elif cn2==0xB: s=f"bf 0x{ctx+2+sign8(cop&0xFF)*2:06X}"
            elif cn2==0xD: s=f"bt/s 0x{ctx+2+sign8(cop&0xFF)*2:06X}"
            elif cn2==0xF: s=f"bf/s 0x{ctx+2+sign8(cop&0xFF)*2:06X}"
        elif cop==0x000B: s="rts"
        elif cop==0x0009: s="nop"
        elif cn3==0xA:
            d=cop&0xFFF
            if d&0x800: d-=0x1000
            s=f"bra 0x{ctx+2+d*2:06X}"
        elif cn3==0xB:
            d=cop&0xFFF
            if d&0x800: d-=0x1000
            s=f"bsr 0x{ctx+2+d*2:06X}"
        elif cn3==0x4:
            lo=(cn1<<4)|cn0
            if lo==0x0B: s=f"jsr @R{cn2}"
            elif lo==0x22: s="sts.l PR,@-R15"
        elif cn3==0x7: s=f"add #{sign8(cop&0xFF)},R{cn2}"
        elif cn3 == 0xC:
            d = cop & 0xFF
            if cn2 == 0: s = f"mov.b R0,@({d},GBR)"
            elif cn2 == 4: s = f"mov.b @({d},GBR),R0"
        elif cn3 == 0x3:
            names = {0:"cmp/eq",3:"cmp/ge",7:"cmp/gt",0xC:"add",8:"sub"}
            if cn0 in names: s = f"{names[cn0]} R{cn1},R{cn2}"
        print(f"    {m} 0x{ctx:06X}: {cop:04X}  {s}")

print(f"\n\nTOTAL: {len(unique_writes)} write sites found")
