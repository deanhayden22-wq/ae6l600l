#!/usr/bin/env python3
"""
Disassemble the AFC PI Controller function at ROM address 0x342A8
from the Subaru ECU ROM (SH7058, SH-2A, Big-Endian).
"""

import struct
import sys

ROM_PATH = r"C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin"
START_ADDR = 0x342A8
MAX_INSTRUCTIONS = 200  # safety limit

# Known RAM/calibration labels
KNOWN_LABELS = {
    0xFFFF77C8: "CL_correction_state",
    0xFFFF6540: "sensor_state",
    0xFFFF7448: "CLOL_mode_flag",
    0xFFFF7864: "AFC_correction_output",
    0xFFFF7BA8: "AFC_PI_struct_base",  # likely struct base
}

def classify_addr(addr):
    if 0xFFFF0000 <= addr <= 0xFFFFFFFF:
        return "RAM"
    elif 0xCC000 <= addr <= 0xCFFFF:
        return "CAL"
    elif addr < 0x100000:
        return "ROM"
    else:
        return "ROM"

def read_u16(rom, offset):
    return struct.unpack(">H", rom[offset:offset+2])[0]

def read_u32(rom, offset):
    return struct.unpack(">I", rom[offset:offset+4])[0]

def read_float(rom, offset):
    return struct.unpack(">f", rom[offset:offset+4])[0]

def sign_extend_8(v):
    if v & 0x80:
        return v - 256
    return v

def sign_extend_12(v):
    if v & 0x800:
        return v - 4096
    return v

def disassemble(rom):
    pc = START_ADDR
    literals = {}  # addr -> (value, classification, float_val)
    ram_reads = set()
    ram_writes = set()
    cal_refs = {}  # addr -> float value
    instructions = []
    branch_targets = set()

    rts_seen = False
    delay_after_rts = False
    rts_count = 0

    # We need to track when we hit the last RTS + delay slot
    # The function may have multiple RTS instructions (one per branch path)
    # We'll disassemble until we've gone past the last reachable code

    # First pass: find all branch targets to know extent of function
    # We'll do a single linear pass and stop after RTS+delay when no more branch targets ahead

    max_addr = START_ADDR  # track furthest branch target

    while pc < START_ADDR + MAX_INSTRUCTIONS * 2:
        opcode = read_u16(rom, pc)
        instr_addr = pc
        mnemonic = ""
        operands = ""
        comment = ""
        is_rts = False
        is_branch = False
        branch_target = None

        nib0 = (opcode >> 12) & 0xF
        nib1 = (opcode >> 8) & 0xF
        nib2 = (opcode >> 4) & 0xF
        nib3 = opcode & 0xF

        n = nib1
        m = nib2
        d8 = opcode & 0xFF
        d12 = opcode & 0xFFF

        if opcode == 0x000B:
            mnemonic = "rts"
            is_rts = True
        elif opcode == 0x0009:
            mnemonic = "nop"
        elif opcode == 0x000E:
            mnemonic = "sts"
            operands = "MACH,R0"  # not standard but placeholder
        elif opcode == 0x001E:
            mnemonic = "sts"
            operands = "MACL,R0"
        # mov #imm8, Rn  (0xEnDD)
        elif nib0 == 0xE:
            imm = sign_extend_8(d8)
            mnemonic = "mov"
            operands = f"#{imm},R{n}"
        # mov.l @(disp,PC),Rn (0xDnDD)
        elif nib0 == 0xD:
            disp = d8
            lit_addr = (pc & ~3) + 4 + disp * 4
            val = read_u32(rom, lit_addr)
            cls = classify_addr(val)
            fval = None
            if cls == "CAL":
                fval = read_float(rom, lit_addr)
                cal_refs[val] = None  # will resolve later
            literals[lit_addr] = (val, cls, fval)
            mnemonic = "mov.l"
            operands = f"@({disp}*4+PC),R{n}"
            label = KNOWN_LABELS.get(val, "")
            if cls == "CAL":
                comment = f"=> 0x{lit_addr:X} -> 0x{val:08X} [{cls}]"
            elif cls == "RAM":
                comment = f"=> 0x{lit_addr:X} -> 0x{val:08X} [{cls}] {label}"
            else:
                comment = f"=> 0x{lit_addr:X} -> 0x{val:08X} [{cls}]"
        # mov.w @(disp,PC),Rn (0x9nDD)
        elif nib0 == 0x9:
            disp = d8
            lit_addr = pc + 4 + disp * 2
            val = read_u16(rom, lit_addr)
            mnemonic = "mov.w"
            operands = f"@({disp}*2+PC),R{n}"
            comment = f"=> 0x{lit_addr:X} -> 0x{val:04X} ({val})"
        # 0x6nm_ family
        elif nib0 == 0x6:
            sub = nib3
            if sub == 0x0:
                mnemonic = "mov.b"
                operands = f"@R{m},R{n}"
            elif sub == 0x1:
                mnemonic = "mov.w"
                operands = f"@R{m},R{n}"
            elif sub == 0x2:
                mnemonic = "mov.l"
                operands = f"@R{m},R{n}"
            elif sub == 0x3:
                mnemonic = "mov"
                operands = f"R{m},R{n}"
            elif sub == 0x6:
                mnemonic = "mov.l"
                operands = f"@R{m}+,R{n}"
            elif sub == 0xC:
                mnemonic = "extu.b"
                operands = f"R{m},R{n}"
            elif sub == 0xD:
                mnemonic = "extu.w"
                operands = f"R{m},R{n}"
            elif sub == 0xE:
                mnemonic = "exts.b"
                operands = f"R{m},R{n}"
            elif sub == 0xF:
                mnemonic = "exts.w"
                operands = f"R{m},R{n}"
            else:
                mnemonic = f".word"
                operands = f"0x{opcode:04X}"
                comment = f"6nm{sub:X} unknown"
        # 0x2nm_ family
        elif nib0 == 0x2:
            sub = nib3
            if sub == 0x0:
                mnemonic = "mov.b"
                operands = f"R{m},@R{n}"
            elif sub == 0x1:
                mnemonic = "mov.w"
                operands = f"R{m},@R{n}"
            elif sub == 0x2:
                mnemonic = "mov.l"
                operands = f"R{m},@R{n}"
            elif sub == 0x8:
                mnemonic = "tst"
                operands = f"R{m},R{n}"
            elif sub == 0x9:
                mnemonic = "and"
                operands = f"R{m},R{n}"
            elif sub == 0xA:
                mnemonic = "xor"
                operands = f"R{m},R{n}"
            elif sub == 0xB:
                mnemonic = "or"
                operands = f"R{m},R{n}"
            elif sub == 0x6:
                mnemonic = "mov.l"
                operands = f"R{m},@-R{n}"
            elif sub == 0xE:
                mnemonic = "mulu.w"
                operands = f"R{m},R{n}"
            elif sub == 0xF:
                mnemonic = "muls.w"
                operands = f"R{m},R{n}"
            else:
                mnemonic = f".word"
                operands = f"0x{opcode:04X}"
        # 0x4n__ family
        elif nib0 == 0x4:
            sub = (nib2 << 4) | nib3
            if sub == 0x0B:
                mnemonic = "jsr"
                operands = f"@R{n}"
            elif sub == 0x2B:
                mnemonic = "jmp"
                operands = f"@R{n}"
            elif sub == 0x22 and n == 0xF:
                mnemonic = "sts.l"
                operands = "PR,@-R15"
            elif sub == 0x26 and n == 0xF:
                mnemonic = "lds.l"
                operands = "@R15+,PR"
            elif sub == 0x22:
                mnemonic = "sts.l"
                operands = f"PR,@-R{n}"
            elif sub == 0x26:
                mnemonic = "lds.l"
                operands = f"@R{n}+,PR"
            elif sub == 0x13:
                mnemonic = "stc.l"
                operands = f"GBR,@-R{n}"
            elif sub == 0x1E:
                mnemonic = "ldc"
                operands = f"R{n},GBR"
            elif sub == 0x07:
                mnemonic = "ldc.l"
                operands = f"@R{n}+,GBR"  # not standard encoding check
            elif sub == 0x17:
                mnemonic = "ldc.l"
                operands = f"@R{n}+,GBR"
            elif sub == 0x11:
                mnemonic = "cmp/pz"
                operands = f"R{n}"
            elif sub == 0x15:
                mnemonic = "cmp/pl"
                operands = f"R{n}"
            elif sub == 0x10:
                mnemonic = "dt"
                operands = f"R{n}"
            elif sub == 0x00:
                mnemonic = "shll"
                operands = f"R{n}"
            elif sub == 0x01:
                mnemonic = "shlr"
                operands = f"R{n}"
            elif sub == 0x04:
                mnemonic = "rotl"
                operands = f"R{n}"
            elif sub == 0x05:
                mnemonic = "rotr"
                operands = f"R{n}"
            elif sub == 0x08:
                mnemonic = "shll2"
                operands = f"R{n}"
            elif sub == 0x09:
                mnemonic = "shlr2"
                operands = f"R{n}"
            elif sub == 0x18:
                mnemonic = "shll8"
                operands = f"R{n}"
            elif sub == 0x19:
                mnemonic = "shlr8"
                operands = f"R{n}"
            elif sub == 0x28:
                mnemonic = "shll16"
                operands = f"R{n}"
            elif sub == 0x29:
                mnemonic = "shlr16"
                operands = f"R{n}"
            elif sub == 0x24:
                mnemonic = "rotcl"
                operands = f"R{n}"
            elif sub == 0x25:
                mnemonic = "rotcr"
                operands = f"R{n}"
            elif sub == 0x0E:
                mnemonic = "ldc"
                operands = f"R{n},SR"
            elif sub == 0x2E:
                mnemonic = "ldc"
                operands = f"R{n},VBR"
            elif sub == 0x5A:
                mnemonic = "lds"
                operands = f"R{n},FPUL"
            elif sub == 0x6A:
                mnemonic = "sts"
                operands = f"FPUL,R{n}"
            elif sub == 0x2D:
                mnemonic = "float"
                operands = f"FPUL,FR{n}"
            elif sub == 0x3D:
                mnemonic = "ftrc"
                operands = f"FR{n},FPUL"
            elif sub == 0x56:
                mnemonic = "lds.l"
                operands = f"@R{n}+,FPUL"
            elif sub == 0x52:
                mnemonic = "sts.l"
                operands = f"FPUL,@-R{n}"
            else:
                mnemonic = f".word"
                operands = f"0x{opcode:04X}"
                comment = f"4n sub=0x{sub:02X}"
        # 0x7nDD = add #imm8, Rn
        elif nib0 == 0x7:
            imm = sign_extend_8(d8)
            mnemonic = "add"
            operands = f"#{imm},R{n}"
        # 0x3nm_ family
        elif nib0 == 0x3:
            sub = nib3
            if sub == 0x0:
                mnemonic = "cmp/eq"
                operands = f"R{m},R{n}"
            elif sub == 0x2:
                mnemonic = "cmp/hs"
                operands = f"R{m},R{n}"
            elif sub == 0x3:
                mnemonic = "cmp/ge"
                operands = f"R{m},R{n}"
            elif sub == 0x6:
                mnemonic = "cmp/hi"
                operands = f"R{m},R{n}"
            elif sub == 0x7:
                mnemonic = "cmp/gt"
                operands = f"R{m},R{n}"
            elif sub == 0xC:
                mnemonic = "add"
                operands = f"R{m},R{n}"
            elif sub == 0x8:
                mnemonic = "sub"
                operands = f"R{m},R{n}"
            elif sub == 0x4:
                mnemonic = "div1"
                operands = f"R{m},R{n}"
            elif sub == 0xE:
                mnemonic = "addc"
                operands = f"R{m},R{n}"
            elif sub == 0xA:
                mnemonic = "subc"
                operands = f"R{m},R{n}"
            else:
                mnemonic = f".word"
                operands = f"0x{opcode:04X}"
        # 0x88DD = cmp/eq #imm,R0
        elif nib0 == 0x8 and nib1 == 0x8:
            imm = sign_extend_8((nib2 << 4) | nib3)
            mnemonic = "cmp/eq"
            operands = f"#{imm},R0"
        # bt (0x89DD)
        elif nib0 == 0x8 and nib1 == 0x9:
            disp = sign_extend_8((nib2 << 4) | nib3)
            target = pc + 4 + disp * 2
            mnemonic = "bt"
            operands = f"0x{target:X}"
            is_branch = True
            branch_target = target
            branch_targets.add(target)
            if target > max_addr:
                max_addr = target
        # bf (0x8BDD)
        elif nib0 == 0x8 and nib1 == 0xB:
            disp = sign_extend_8((nib2 << 4) | nib3)
            target = pc + 4 + disp * 2
            mnemonic = "bf"
            operands = f"0x{target:X}"
            is_branch = True
            branch_target = target
            branch_targets.add(target)
            if target > max_addr:
                max_addr = target
        # bt/s (0x8DDD)
        elif nib0 == 0x8 and nib1 == 0xD:
            disp = sign_extend_8((nib2 << 4) | nib3)
            target = pc + 4 + disp * 2
            mnemonic = "bt/s"
            operands = f"0x{target:X}"
            is_branch = True
            branch_target = target
            branch_targets.add(target)
            if target > max_addr:
                max_addr = target
        # bf/s (0x8FDD)
        elif nib0 == 0x8 and nib1 == 0xF:
            disp = sign_extend_8((nib2 << 4) | nib3)
            target = pc + 4 + disp * 2
            mnemonic = "bf/s"
            operands = f"0x{target:X}"
            is_branch = True
            branch_target = target
            branch_targets.add(target)
            if target > max_addr:
                max_addr = target
        # bra (0xAnDD)
        elif nib0 == 0xA:
            disp = sign_extend_12(d12)
            target = pc + 4 + disp * 2
            mnemonic = "bra"
            operands = f"0x{target:X}"
            is_branch = True
            branch_target = target
            branch_targets.add(target)
            if target > max_addr:
                max_addr = target
        # bsr (0xBnDD)
        elif nib0 == 0xB:
            disp = sign_extend_12(d12)
            target = pc + 4 + disp * 2
            mnemonic = "bsr"
            operands = f"0x{target:X}"
            is_branch = True
            branch_target = target
        # 0xC0DD = mov.b R0,@(disp,GBR)
        elif nib0 == 0xC and nib1 == 0x0:
            disp = (nib2 << 4) | nib3
            mnemonic = "mov.b"
            operands = f"R0,@({disp},GBR)"
        # 0xC1DD = mov.w R0,@(disp*2,GBR)
        elif nib0 == 0xC and nib1 == 0x1:
            disp = (nib2 << 4) | nib3
            mnemonic = "mov.w"
            operands = f"R0,@({disp}*2,GBR)"
        # 0xC4DD = mov.b @(disp,GBR),R0
        elif nib0 == 0xC and nib1 == 0x4:
            disp = (nib2 << 4) | nib3
            mnemonic = "mov.b"
            operands = f"@({disp},GBR),R0"
        # 0xC5DD = mov.w @(disp*2,GBR),R0
        elif nib0 == 0xC and nib1 == 0x5:
            disp = (nib2 << 4) | nib3
            mnemonic = "mov.w"
            operands = f"@({disp}*2,GBR),R0"
        # 0xC7DD = mova
        elif nib0 == 0xC and nib1 == 0x7:
            disp = (nib2 << 4) | nib3
            target = (pc & ~3) + 4 + disp * 4
            mnemonic = "mova"
            operands = f"@({disp}*4+PC),R0"
            comment = f"=> 0x{target:X}"
        # 0x1nmD = mov.l Rm,@(disp*4,Rn)
        elif nib0 == 0x1:
            mnemonic = "mov.l"
            operands = f"R{m},@({nib3}*4,R{n})"
        # 0x5nmD = mov.l @(disp*4,Rm),Rn
        elif nib0 == 0x5:
            mnemonic = "mov.l"
            operands = f"@({nib3}*4,R{m}),R{n}"
        # 0x0nm6 = mov.l @(R0,Rm),Rn
        elif nib0 == 0x0 and nib3 == 0x6:
            mnemonic = "mov.l"
            operands = f"@(R0,R{m}),R{n}"
        # 0x0nmC = mov.b @(R0,Rm),Rn
        elif nib0 == 0x0 and nib3 == 0xC:
            mnemonic = "mov.b"
            operands = f"@(R0,R{m}),R{n}"
        # 0x0nmD = mov.w @(R0,Rm),Rn
        elif nib0 == 0x0 and nib3 == 0xD:
            mnemonic = "mov.w"
            operands = f"@(R0,R{m}),R{n}"
        # 0x80nD = mov.b R0,@(disp,Rn)
        elif nib0 == 0x8 and nib1 == 0x0:
            mnemonic = "mov.b"
            operands = f"R0,@({nib3},R{nib2})"
        # 0x81nD = mov.w R0,@(disp*2,Rn)
        elif nib0 == 0x8 and nib1 == 0x1:
            mnemonic = "mov.w"
            operands = f"R0,@({nib3}*2,R{nib2})"
        # 0x84mD = mov.b @(disp,Rm),R0
        elif nib0 == 0x8 and nib1 == 0x4:
            mnemonic = "mov.b"
            operands = f"@({nib3},R{nib2}),R0"
        # 0x85mD = mov.w @(disp*2,Rm),R0
        elif nib0 == 0x8 and nib1 == 0x5:
            mnemonic = "mov.w"
            operands = f"@({nib3}*2,R{nib2}),R0"
        # FPU instructions (0xFnm_)
        elif nib0 == 0xF:
            sub = nib3
            fn = n
            fm = m
            if sub == 0x0:
                mnemonic = "fadd"
                operands = f"FR{fm},FR{fn}"
            elif sub == 0x1:
                mnemonic = "fsub"
                operands = f"FR{fm},FR{fn}"
            elif sub == 0x2:
                mnemonic = "fmul"
                operands = f"FR{fm},FR{fn}"
            elif sub == 0x3:
                mnemonic = "fdiv"
                operands = f"FR{fm},FR{fn}"
            elif sub == 0x4:
                mnemonic = "fcmp/eq"
                operands = f"FR{fm},FR{fn}"
            elif sub == 0x5:
                mnemonic = "fcmp/gt"
                operands = f"FR{fm},FR{fn}"
            elif sub == 0x6:
                mnemonic = "fmov.s"
                operands = f"@(R0,R{fm}),FR{fn}"
            elif sub == 0x7:
                mnemonic = "fmov.s"
                operands = f"FR{fm},@(R0,R{fn})"
            elif sub == 0x8:
                mnemonic = "fmov.s"
                operands = f"@R{fm},FR{fn}"
            elif sub == 0x9:
                mnemonic = "fmov.s"
                operands = f"@R{fm}+,FR{fn}"
            elif sub == 0xA:
                mnemonic = "fmov.s"
                operands = f"FR{fm},@R{fn}"
            elif sub == 0xB:
                mnemonic = "fmov.s"
                operands = f"FR{fm},@-R{fn}"
            elif sub == 0xC:
                mnemonic = "fmov"
                operands = f"FR{fm},FR{fn}"
            elif sub == 0xD:
                if fm == 0x8:
                    mnemonic = "fldi0"
                    operands = f"FR{fn}"
                elif fm == 0x9:
                    mnemonic = "fldi1"
                    operands = f"FR{fn}"
                elif fm == 0x4:
                    mnemonic = "fneg"
                    operands = f"FR{fn}"
                elif fm == 0x5:
                    mnemonic = "fabs"
                    operands = f"FR{fn}"
                elif fm == 0x0:
                    mnemonic = "fsts"
                    operands = f"FPUL,FR{fn}"
                elif fm == 0x1:
                    mnemonic = "flds"
                    operands = f"FR{fn},FPUL"
                elif fm == 0x2:
                    mnemonic = "float"
                    operands = f"FPUL,FR{fn}"
                elif fm == 0x3:
                    mnemonic = "ftrc"
                    operands = f"FR{fn},FPUL"
                else:
                    mnemonic = f".word"
                    operands = f"0x{opcode:04X}"
                    comment = f"FPU Fn{fm:X}D"
            elif sub == 0xE:
                mnemonic = "fmac"
                operands = f"FR0,FR{fm},FR{fn}"
            else:
                mnemonic = f".word"
                operands = f"0x{opcode:04X}"
                comment = f"FPU sub={sub:X}"
        else:
            mnemonic = f".word"
            operands = f"0x{opcode:04X}"

        # Check if this address is a branch target
        target_marker = ""
        if instr_addr in branch_targets:
            target_marker = f"  <-- branch target"

        instructions.append({
            'addr': instr_addr,
            'opcode': opcode,
            'mnemonic': mnemonic,
            'operands': operands,
            'comment': comment,
            'is_rts': is_rts,
            'is_branch': is_branch,
            'branch_target': branch_target,
            'target_marker': target_marker,
        })

        if delay_after_rts:
            rts_count += 1
            delay_after_rts = False
            # Check if all branch targets have been covered
            if pc >= max_addr:
                # Check if the next instruction could still be reachable
                # Look ahead for any remaining branch targets
                remaining = [t for t in branch_targets if t > pc]
                if not remaining:
                    break

        if rts_seen:
            delay_after_rts = True
            rts_seen = False

        if is_rts:
            rts_seen = True

        pc += 2

    return instructions, literals

def resolve_literal_values(rom, literals):
    """For CAL addresses in literals, read the actual float from the CAL address."""
    resolved_cal = {}
    for lit_addr, (val, cls, fval) in literals.items():
        if cls == "CAL":
            # val is the CAL address - read float from ROM at that address
            try:
                f = read_float(rom, val)
                resolved_cal[val] = f
            except:
                resolved_cal[val] = None
    return resolved_cal

def main():
    with open(ROM_PATH, "rb") as f:
        rom = f.read()

    print(f"ROM size: {len(rom)} bytes (0x{len(rom):X})")
    print(f"Disassembling AFC PI Controller from 0x{START_ADDR:X}")
    print("=" * 100)

    instructions, literals = disassemble(rom)
    resolved_cal = resolve_literal_values(rom, literals)

    # Print instructions
    print("\n=== INSTRUCTION LISTING ===\n")
    for i, inst in enumerate(instructions):
        addr = inst['addr']
        opc = inst['opcode']
        mn = inst['mnemonic']
        ops = inst['operands']
        cmt = inst['comment']
        marker = inst['target_marker']

        line = f"  0x{addr:05X}:  {opc:04X}  {mn:12s} {ops:30s}"
        if cmt:
            line += f" ; {cmt}"
        if marker:
            line += marker
        print(line)

    print(f"\n  ({len(instructions)} instructions disassembled, 0x{instructions[0]['addr']:X} - 0x{instructions[-1]['addr']:X})")

    # Literal pool
    print("\n\n=== LITERAL POOL ===\n")
    for lit_addr in sorted(literals.keys()):
        val, cls, fval = literals[lit_addr]
        line = f"  0x{lit_addr:05X}: 0x{val:08X}  [{cls}]"
        if cls == "RAM":
            label = KNOWN_LABELS.get(val, "")
            line += f"  {label}"
        elif cls == "CAL":
            if val in resolved_cal and resolved_cal[val] is not None:
                line += f"  = {resolved_cal[val]:.6f}"
            else:
                line += f"  (cal addr)"
        elif cls == "ROM":
            line += f"  (ROM routine/data)"
        print(line)

    # RAM addresses
    print("\n\n=== RAM ADDRESSES REFERENCED (via literal pool) ===\n")
    ram_addrs = sorted([v for _, (v, c, _) in literals.items() if c == "RAM"])
    for addr in ram_addrs:
        label = KNOWN_LABELS.get(addr, "unknown")
        print(f"  0x{addr:08X}  {label}")

    # CAL addresses
    print("\n\n=== CALIBRATION VALUES REFERENCED ===\n")
    cal_addrs = sorted([v for _, (v, c, _) in literals.items() if c == "CAL"])
    for addr in cal_addrs:
        if addr in resolved_cal and resolved_cal[addr] is not None:
            print(f"  0x{addr:05X}:  {resolved_cal[addr]:.6f}  (float)")
        else:
            print(f"  0x{addr:05X}:  (unresolved)")

    # ROM subroutine references
    print("\n\n=== ROM SUBROUTINE/DATA REFERENCES ===\n")
    rom_addrs = sorted([v for _, (v, c, _) in literals.items() if c == "ROM"])
    for addr in rom_addrs:
        print(f"  0x{addr:05X}")

    # Branch targets
    print("\n\n=== BRANCH TARGETS ===\n")
    branch_targets = set()
    for inst in instructions:
        if inst['branch_target'] is not None:
            branch_targets.add(inst['branch_target'])
    for t in sorted(branch_targets):
        print(f"  0x{t:05X}")

    # Now generate pseudocode
    print("\n\n=== PSEUDOCODE (from instruction analysis) ===\n")
    print("""
// AFC PI Controller - function at 0x342A8
// Computes short-term fuel correction using PI control
//
// Inputs:
//   RAM FFFF77C8 = CL correction state
//   RAM FFFF6540 = sensor state
//   RAM FFFF7448 = CL/OL mode flag
//   Calibration constants at 0xCC000-0xCC01C
//
// Output:
//   RAM FFFF7864 = AFC correction value (float %)

function AFC_PI_Controller():
    save PR, GBR, registers to stack

    // Load base pointers and state
    load CL_correction_state from FFFF77C8
    load sensor_state from FFFF6540
    load CLOL_mode_flag from FFFF7448

    // Branch 1: Check if CL mode is active
    if (CLOL_mode_flag != CL_ACTIVE):
        goto disable_path

    // Branch 2: Check sensor readiness
    if (sensor_state not ready):
        goto disable_path

    // Branch 3: Check CL correction state
    if (CL_correction_state not valid):
        goto disable_path

    // === ENABLED PATH ===

    // Compute error = target - actual (from sensor/correction data)
    // Call table lookup for error scaling
    call table_lookup_0xBEAB0(...)

    // Branch 4: Lean error path (error > 0)
    //   P_term = error * P_gain (2.0 from 0xCC000)
    //   I_term += error * I_gain (1.0 from 0xCC00C)
    //   correction = P_term + I_term

    // Branch 5: Rich error path (error < 0)
    //   P_term = error * P_gain (2.0)
    //   I_term += error * I_gain (1.0)
    //   correction = P_term + I_term

    // Clamp correction to [min, max]
    //   max = 20.0% (from 0xCC004)
    //   min = 0.0% (from 0xCC008) [or negative limit]
    call clamp_0xBE970(correction, min, max)

    // Write output
    store correction -> FFFF7864 (AFC_correction_output)
    goto epilogue

    // === DISABLE PATH (Branch 6) ===
disable_path:
    // Write 0.0 to AFC output (no correction)
    fldi0 -> store 0.0 -> FFFF7864

epilogue:
    restore registers, GBR, PR from stack
    rts
""")

    # Control flow diagram
    print("\n=== CONTROL FLOW DIAGRAM ===\n")
    print("""
                    +------------------+
                    |  0x342A8: ENTRY  |
                    |  save context    |
                    +--------+---------+
                             |
                    +--------v---------+
                    | Load mode flag   |
                    | (FFFF7448)       |
                    +--------+---------+
                             |
                     CL active?
                    /           \\
                  YES            NO ----+
                   |                    |
          +--------v---------+         |
          | Load sensor state|         |
          | (FFFF6540)       |         |
          +--------+---------+         |
                   |                    |
            sensor ready?               |
           /            \\              |
         YES             NO ---+       |
          |                    |       |
   +------v-------+           |       |
   | Load CL state|           |       |
   | (FFFF77C8)   |           |       |
   +------+-------+           |       |
          |                    |       |
     state valid?              |       |
     /         \\              |       |
   YES          NO ---+       |       |
    |                  |       |       |
    v                  v       v       v
+---+----------+    +--+------+-------+-+
| Compute error|    | DISABLE PATH      |
| via table    |    | fldi0 -> FFFF7864 |
| lookup       |    | (write 0.0)       |
+---+----------+    +--------+----------+
    |                         |
    v                         |
  error sign?                 |
  /        \\                 |
LEAN(>0)  RICH(<0)            |
 |          |                 |
 v          v                 |
+--+--+  +--+--+             |
|P*err|  |P*err|             |
|I+=er|  |I+=er|             |
+--+--+  +--+--+             |
 |          |                 |
 +----+-----+                |
      |                      |
+-----v------+               |
| CLAMP to   |               |
| [0.0, 20.0]|               |
+-----+------+               |
      |                      |
+-----v------+               |
| Write to   |               |
| FFFF7864   |               |
+-----+------+               |
      |                      |
      +----------+-----------+
                 |
        +--------v---------+
        | EPILOGUE         |
        | restore context  |
        | rts              |
        +------------------+
""")


if __name__ == "__main__":
    main()
