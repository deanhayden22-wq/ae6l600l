#!/usr/bin/env python3
"""Minimal SH-2 disassembler for Subaru ECU ROM analysis."""
import os, struct, sys

def disasm_sh2(opcode, pc):
    """Disassemble a single SH-2 16-bit opcode. Returns mnemonic string."""
    n = (opcode >> 8) & 0xF
    m = (opcode >> 4) & 0xF
    d = opcode & 0xF
    imm8 = opcode & 0xFF
    imm12 = opcode & 0xFFF

    # Top nibble dispatch
    top = (opcode >> 12) & 0xF

    if opcode == 0x0009:
        return "nop"
    if opcode == 0x000B:
        return "rts"
    if opcode == 0x002B:
        return "rte"
    if opcode == 0x0008:
        return "clrt"
    if opcode == 0x0018:
        return "sett"
    if opcode == 0x0019:
        return "div0u"
    if opcode == 0x001B:
        return "sleep"
    if opcode == 0x0028:
        return "clrmac"

    if top == 0x0:
        lo4 = opcode & 0xF
        lo8 = opcode & 0xFF
        if lo4 == 0x2:
            # STC
            if m == 0: return f"stc SR,R{n}"
            if m == 1: return f"stc GBR,R{n}"
            if m == 2: return f"stc VBR,R{n}"
        if lo4 == 0x3:
            if m == 0: return f"bsrf R{n}"
            if m == 2: return f"braf R{n}"
        if lo8 == 0x23:
            return f"braf R{n}"
        if lo4 == 0x4:
            return f"mov.b R{m},@(R0,R{n})"
        if lo4 == 0x5:
            return f"mov.w R{m},@(R0,R{n})"
        if lo4 == 0x6:
            return f"mov.l R{m},@(R0,R{n})"
        if lo4 == 0x7:
            return f"mul.l R{m},R{n}"
        if lo4 == 0xC:
            return f"mov.b @(R0,R{m}),R{n}"
        if lo4 == 0xD:
            return f"mov.w @(R0,R{m}),R{n}"
        if lo4 == 0xE:
            return f"mov.l @(R0,R{m}),R{n}"
        if lo4 == 0xF:
            return f"mac.l @R{m}+,@R{n}+"
        return f".word 0x{opcode:04X}"

    if top == 0x1:
        disp = opcode & 0xF
        return f"mov.l R{m},@({disp*4},R{n})"

    if top == 0x2:
        lo4 = opcode & 0xF
        if lo4 == 0x0: return f"mov.b R{m},@R{n}"
        if lo4 == 0x1: return f"mov.w R{m},@R{n}"
        if lo4 == 0x2: return f"mov.l R{m},@R{n}"
        if lo4 == 0x4: return f"mov.b R{m},@-R{n}"
        if lo4 == 0x5: return f"mov.w R{m},@-R{n}"
        if lo4 == 0x6: return f"mov.l R{m},@-R{n}"
        if lo4 == 0x7: return f"div0s R{m},R{n}"
        if lo4 == 0x8: return f"tst R{m},R{n}"
        if lo4 == 0x9: return f"and R{m},R{n}"
        if lo4 == 0xA: return f"xor R{m},R{n}"
        if lo4 == 0xB: return f"or R{m},R{n}"
        if lo4 == 0xC: return f"cmp/str R{m},R{n}"
        if lo4 == 0xD: return f"xtrct R{m},R{n}"
        if lo4 == 0xE: return f"mulu.w R{m},R{n}"
        if lo4 == 0xF: return f"muls.w R{m},R{n}"
        return f".word 0x{opcode:04X}"

    if top == 0x3:
        lo4 = opcode & 0xF
        if lo4 == 0x0: return f"cmp/eq R{m},R{n}"
        if lo4 == 0x2: return f"cmp/hs R{m},R{n}"
        if lo4 == 0x3: return f"cmp/ge R{m},R{n}"
        if lo4 == 0x4: return f"div1 R{m},R{n}"
        if lo4 == 0x5: return f"dmulu.l R{m},R{n}"
        if lo4 == 0x6: return f"cmp/hi R{m},R{n}"
        if lo4 == 0x7: return f"cmp/gt R{m},R{n}"
        if lo4 == 0x8: return f"sub R{m},R{n}"
        if lo4 == 0xC: return f"add R{m},R{n}"
        if lo4 == 0xD: return f"dmuls.l R{m},R{n}"
        if lo4 == 0xE: return f"addc R{m},R{n}"
        if lo4 == 0xF: return f"addv R{m},R{n}"
        return f".word 0x{opcode:04X}"

    if top == 0x4:
        lo8 = opcode & 0xFF
        lo4 = opcode & 0xF
        if lo8 == 0x00: return f"shll R{n}"
        if lo8 == 0x01: return f"shlr R{n}"
        if lo8 == 0x02: return f"sts.l MACH,@-R{n}"
        if lo8 == 0x04: return f"rotl R{n}"
        if lo8 == 0x05: return f"rotr R{n}"
        if lo8 == 0x06: return f"lds.l @R{n}+,MACH"
        if lo8 == 0x08: return f"shll2 R{n}"
        if lo8 == 0x09: return f"shlr2 R{n}"
        if lo8 == 0x0A: return f"lds R{n},MACH"
        if lo8 == 0x0B: return f"jsr @R{n}"
        if lo8 == 0x0E: return f"ldc R{n},SR"
        if lo8 == 0x10: return f"dt R{n}"
        if lo8 == 0x11: return f"cmp/pz R{n}"
        if lo8 == 0x12: return f"sts.l MACL,@-R{n}"
        if lo8 == 0x15: return f"cmp/pl R{n}"
        if lo8 == 0x16: return f"lds.l @R{n}+,MACL"
        if lo8 == 0x18: return f"shll8 R{n}"
        if lo8 == 0x19: return f"shlr8 R{n}"
        if lo8 == 0x1A: return f"lds R{n},MACL"
        if lo8 == 0x1B: return f"tas.b @R{n}"
        if lo8 == 0x1E: return f"ldc R{n},GBR"
        if lo8 == 0x20: return f"shal R{n}"
        if lo8 == 0x21: return f"shar R{n}"
        if lo8 == 0x22: return f"sts.l PR,@-R{n}"
        if lo8 == 0x24: return f"rotcl R{n}"
        if lo8 == 0x25: return f"rotcr R{n}"
        if lo8 == 0x26: return f"lds.l @R{n}+,PR"
        if lo8 == 0x28: return f"shll16 R{n}"
        if lo8 == 0x29: return f"shlr16 R{n}"
        if lo8 == 0x2A: return f"lds R{n},PR"
        if lo8 == 0x2B: return f"jmp @R{n}"
        if lo8 == 0x2E: return f"ldc R{n},VBR"
        if lo4 == 0xF: return f"mac.w @R{m}+,@R{n}+"
        # SH-2E FPU: 4n6d patterns (not standard, skip)
        return f".word 0x{opcode:04X}"

    if top == 0x5:
        disp = opcode & 0xF
        return f"mov.l @({disp*4},R{m}),R{n}"

    if top == 0x6:
        lo4 = opcode & 0xF
        if lo4 == 0x0: return f"mov.b @R{m},R{n}"
        if lo4 == 0x1: return f"mov.w @R{m},R{n}"
        if lo4 == 0x2: return f"mov.l @R{m},R{n}"
        if lo4 == 0x3: return f"mov R{m},R{n}"
        if lo4 == 0x4: return f"mov.b @R{m}+,R{n}"
        if lo4 == 0x5: return f"mov.w @R{m}+,R{n}"
        if lo4 == 0x6: return f"mov.l @R{m}+,R{n}"
        if lo4 == 0x7: return f"not R{m},R{n}"
        if lo4 == 0x8: return f"swap.b R{m},R{n}"
        if lo4 == 0x9: return f"swap.w R{m},R{n}"
        if lo4 == 0xA: return f"negc R{m},R{n}"
        if lo4 == 0xB: return f"neg R{m},R{n}"
        if lo4 == 0xC: return f"extu.b R{m},R{n}"
        if lo4 == 0xD: return f"extu.w R{m},R{n}"
        if lo4 == 0xE: return f"exts.b R{m},R{n}"
        if lo4 == 0xF: return f"exts.w R{m},R{n}"
        return f".word 0x{opcode:04X}"

    if top == 0x7:
        simm = imm8 if imm8 < 128 else imm8 - 256
        return f"add #{simm},R{n}"

    if top == 0x8:
        lo_n = (opcode >> 8) & 0xF  # actually sub-op
        disp8 = opcode & 0xFF
        if lo_n == 0x0:
            return f"mov.b R0,@({disp8},R{m})"
        if lo_n == 0x1:
            return f"mov.w R0,@({disp8*2},R{m})"
        if lo_n == 0x4:
            return f"mov.b @({disp8},R{m}),R0"
        if lo_n == 0x5:
            return f"mov.w @({disp8*2},R{m}),R0"
        if lo_n == 0x8:
            return f"cmp/eq #{disp8 if disp8<128 else disp8-256},R0"
        if lo_n == 0x9:
            target = pc + 4 + (disp8 if disp8 < 128 else disp8 - 256) * 2
            return f"bt 0x{target:06X}"
        if lo_n == 0xB:
            target = pc + 4 + (disp8 if disp8 < 128 else disp8 - 256) * 2
            return f"bf 0x{target:06X}"
        if lo_n == 0xD:
            target = pc + 4 + (disp8 if disp8 < 128 else disp8 - 256) * 2
            return f"bt/s 0x{target:06X}"
        if lo_n == 0xF:
            target = pc + 4 + (disp8 if disp8 < 128 else disp8 - 256) * 2
            return f"bf/s 0x{target:06X}"
        return f".word 0x{opcode:04X}"

    if top == 0x9:
        disp8 = opcode & 0xFF
        addr = (pc & 0xFFFFFFFC) + 4 + disp8 * 2
        return f"mov.w @(0x{addr:06X}),R{n}  ; @(PC+{disp8*2})"

    if top == 0xA:
        sdisp = imm12 if imm12 < 2048 else imm12 - 4096
        target = pc + 4 + sdisp * 2
        return f"bra 0x{target:06X}"

    if top == 0xB:
        sdisp = imm12 if imm12 < 2048 else imm12 - 4096
        target = pc + 4 + sdisp * 2
        return f"bsr 0x{target:06X}"

    if top == 0xC:
        sub = (opcode >> 8) & 0xF
        if sub == 0x0: return f"mov.b R0,@({imm8},GBR)"
        if sub == 0x1: return f"mov.w R0,@({imm8*2},GBR)"
        if sub == 0x2: return f"mov.l R0,@({imm8*4},GBR)"
        if sub == 0x3: return f"trapa #{imm8}"
        if sub == 0x4: return f"mov.b @({imm8},GBR),R0"
        if sub == 0x5: return f"mov.w @({imm8*2},GBR),R0"
        if sub == 0x6: return f"mov.l @({imm8*4},GBR),R0"
        if sub == 0x7: return f"mova @(0x{((pc&0xFFFFFFFC)+4+imm8*4):06X}),R0"
        if sub == 0x8: return f"tst #{imm8},R0"
        if sub == 0x9: return f"and #{imm8},R0"
        if sub == 0xA: return f"xor #{imm8},R0"
        if sub == 0xB: return f"or #{imm8},R0"
        if sub == 0xC: return f"tst.b #{imm8},@(R0,GBR)"
        if sub == 0xD: return f"and.b #{imm8},@(R0,GBR)"
        if sub == 0xE: return f"xor.b #{imm8},@(R0,GBR)"
        if sub == 0xF: return f"or.b #{imm8},@(R0,GBR)"
        return f".word 0x{opcode:04X}"

    if top == 0xD:
        disp8 = opcode & 0xFF
        addr = (pc & 0xFFFFFFFC) + 4 + disp8 * 4
        return f"mov.l @(0x{addr:06X}),R{n}  ; @(PC+{disp8*4})"

    if top == 0xE:
        simm = imm8 if imm8 < 128 else imm8 - 256
        return f"mov #{simm},R{n}"

    if top == 0xF:
        # SH-2E / SH-4 FPU instructions
        lo4 = opcode & 0xF
        # Common FPU ops (SH-4 encoding, approximate for SH-2E)
        if lo4 == 0x0: return f"fadd FR{m},FR{n}"
        if lo4 == 0x1: return f"fsub FR{m},FR{n}"
        if lo4 == 0x2: return f"fmul FR{m},FR{n}"
        if lo4 == 0x3: return f"fdiv FR{m},FR{n}"
        if lo4 == 0x4: return f"fcmp/eq FR{m},FR{n}"
        if lo4 == 0x5: return f"fcmp/gt FR{m},FR{n}"
        if lo4 == 0x6: return f"fmov.s @(R0,R{m}),FR{n}"
        if lo4 == 0x7: return f"fmov.s FR{m},@(R0,R{n})"
        if lo4 == 0x8: return f"fmov.s @R{m},FR{n}"
        if lo4 == 0x9: return f"fmov.s @R{m}+,FR{n}"
        if lo4 == 0xA: return f"fmov.s FR{m},@R{n}"
        if lo4 == 0xB: return f"fmov.s FR{m},@-R{n}"
        if lo4 == 0xC: return f"fmov FR{m},FR{n}"
        if lo4 == 0xD:
            # FSTS, FLDS, FLOAT, FTRC, FNEG, FABS, FSQRT, etc
            sub = (opcode >> 4) & 0xF
            if sub == 0x0: return f"fsts FPUL,FR{n}"
            if sub == 0x1: return f"flds FR{n},FPUL"
            if sub == 0x2: return f"float FPUL,FR{n}"
            if sub == 0x3: return f"ftrc FR{n},FPUL"
            if sub == 0x4: return f"fneg FR{n}"
            if sub == 0x5: return f"fabs FR{n}"
            if sub == 0x6: return f"fsqrt FR{n}"
            if sub == 0x8: return f"fldi0 FR{n}"
            if sub == 0x9: return f"fldi1 FR{n}"
            return f"fpu_0x{opcode:04X}"
        if lo4 == 0xE:
            return f"fmac FR0,FR{m},FR{n}"
        return f"fpu_0x{opcode:04X}"

    return f".word 0x{opcode:04X}"


def disassemble_region(data, base_addr, length, rom_data=None):
    """Disassemble a region. rom_data is the full ROM for literal pool lookups."""
    lines = []
    i = 0
    while i < length and i < len(data) - 1:
        pc = base_addr + i
        opcode = struct.unpack('>H', data[i:i+2])[0]
        mnemonic = disasm_sh2(opcode, pc)

        # If it's a mov.l @(disp,PC),Rn, resolve the literal pool value
        comment = ""
        if (opcode >> 12) == 0xD and rom_data:
            disp8 = opcode & 0xFF
            rn = (opcode >> 8) & 0xF
            pool_addr = (pc & 0xFFFFFFFC) + 4 + disp8 * 4
            if pool_addr + 4 <= len(rom_data):
                val = struct.unpack('>I', rom_data[pool_addr:pool_addr+4])[0]
                comment = f"  ; =0x{val:08X}"

        # If it's a mov.w @(disp,PC),Rn, resolve
        if (opcode >> 12) == 0x9 and rom_data:
            disp8 = opcode & 0xFF
            pool_addr = (pc & 0xFFFFFFFC) + 4 + disp8 * 2
            if pool_addr + 2 <= len(rom_data):
                val = struct.unpack('>H', rom_data[pool_addr:pool_addr+2])[0]
                comment = f"  ; =0x{val:04X}"

        lines.append(f"  0x{pc:06X}:  {opcode:04X}    {mnemonic}{comment}")
        i += 2
    return "\n".join(lines)


def find_function_end(data, base_addr, max_len=1024):
    """Find approximate function end by looking for rts (000B) after lds.l @R15+,PR."""
    i = 0
    found_epilogue = False
    while i < max_len and i < len(data) - 3:
        opcode = struct.unpack('>H', data[i:i+2])[0]
        if opcode == 0x4F26:  # lds.l @R15+,PR
            found_epilogue = True
        if found_epilogue and opcode == 0x000B:  # rts
            # Include the delay slot
            return i + 4
        if found_epilogue and i > 10:
            # Reset if we went too far after epilogue marker
            found_epilogue = False
        i += 2
    return min(max_len, len(data))


def extract_jsr_targets(data, base_addr, length, rom_data):
    """Extract all jsr call targets from a region."""
    targets = []
    i = 0
    while i < length and i < len(data) - 1:
        pc = base_addr + i
        opcode = struct.unpack('>H', data[i:i+2])[0]

        # jsr @Rn = 0x4n0B
        if (opcode & 0xF0FF) == 0x400B:
            rn = (opcode >> 8) & 0xF
            # Look backwards for the mov.l that loaded Rn
            target_addr = resolve_register_load(data, i, rn, base_addr, rom_data)
            targets.append((pc, rn, target_addr))

        # bsr disp = 0xBxxx
        if (opcode >> 12) == 0xB:
            sdisp = opcode & 0xFFF
            if sdisp >= 2048: sdisp -= 4096
            target = pc + 4 + sdisp * 2
            targets.append((pc, -1, target))

        i += 2
    return targets


def resolve_register_load(data, jsr_offset, reg, base_addr, rom_data):
    """Look backwards from jsr to find the mov.l @(disp,PC),Rn that loaded the register."""
    # Search backwards up to 20 instructions
    for back in range(2, 42, 2):
        if jsr_offset - back < 0:
            break
        prev_opcode = struct.unpack('>H', data[jsr_offset-back:jsr_offset-back+2])[0]
        # mov.l @(disp,PC),Rn  = 0xDnXX
        if (prev_opcode >> 12) == 0xD and ((prev_opcode >> 8) & 0xF) == reg:
            disp8 = prev_opcode & 0xFF
            prev_pc = base_addr + jsr_offset - back
            pool_addr = (prev_pc & 0xFFFFFFFC) + 4 + disp8 * 4
            if pool_addr + 4 <= len(rom_data):
                val = struct.unpack('>I', rom_data[pool_addr:pool_addr+4])[0]
                return val
            break
        # mov Rm,Rn = 0x6n m3 - register copy, need to trace further
        if (prev_opcode >> 12) == 0x6 and (prev_opcode & 0xF) == 0x3:
            dst = (prev_opcode >> 8) & 0xF
            src = (prev_opcode >> 4) & 0xF
            if dst == reg:
                # Now trace src register
                return resolve_register_load(data, jsr_offset - back, src, base_addr, rom_data)
    return None


def search_for_bytes(rom_data, pattern):
    """Search entire ROM for a byte pattern."""
    results = []
    i = 0
    while i < len(rom_data) - len(pattern):
        if rom_data[i:i+len(pattern)] == pattern:
            results.append(i)
        i += 1
    return results


if __name__ == "__main__":
    rom_path = os.path.join(os.path.dirname(__file__), "..", "rom", "AE5L600L 20g rev 20.3 tiny wrex.bin")
    with open(rom_path, "rb") as f:
        rom = f.read()

    print(f"ROM size: {len(rom)} bytes (0x{len(rom):X})")
    print()

    # =========================================================
    # 1. Disassemble 0x033CC4 - CL fueling target calculation
    # =========================================================
    addr1 = 0x033CC4
    chunk1 = rom[addr1:]
    end1 = find_function_end(chunk1, addr1, max_len=600)
    # Ensure at least 300 bytes
    disasm_len1 = max(end1, 300)

    print("=" * 70)
    print(f"FUNCTION @ 0x{addr1:06X} - CL Fueling Target Calculation")
    print(f"  (disassembling {disasm_len1} bytes, function end estimate: +0x{end1:X})")
    print("=" * 70)
    print(disassemble_region(chunk1, addr1, disasm_len1, rom))
    print()

    # Extract JSR targets
    targets1 = extract_jsr_targets(chunk1, addr1, disasm_len1, rom)
    print(f"--- JSR/BSR call targets in 0x{addr1:06X} ---")
    for pc, rn, target in targets1:
        if target is not None:
            tgt_str = f"0x{target:06X}"
        else:
            tgt_str = "UNKNOWN"
        if rn >= 0:
            print(f"  0x{pc:06X}: jsr @R{rn}  -> {tgt_str}")
        else:
            print(f"  0x{pc:06X}: bsr        -> {tgt_str}")
    print()

    # =========================================================
    # 2. Disassemble 0x034488 - A/F Learning #1 Limits
    # =========================================================
    addr2 = 0x034488
    chunk2 = rom[addr2:]
    end2 = find_function_end(chunk2, addr2, max_len=600)
    disasm_len2 = max(end2, 300)

    print("=" * 70)
    print(f"FUNCTION @ 0x{addr2:06X} - A/F Learning #1 Limits")
    print(f"  (disassembling {disasm_len2} bytes, function end estimate: +0x{end2:X})")
    print("=" * 70)
    print(disassemble_region(chunk2, addr2, disasm_len2, rom))
    print()

    targets2 = extract_jsr_targets(chunk2, addr2, disasm_len2, rom)
    print(f"--- JSR/BSR call targets in 0x{addr2:06X} ---")
    for pc, rn, target in targets2:
        if target is not None:
            tgt_str = f"0x{target:06X}"
        else:
            tgt_str = "UNKNOWN"
        if rn >= 0:
            print(f"  0x{pc:06X}: jsr @R{rn}  -> {tgt_str}")
        else:
            print(f"  0x{pc:06X}: bsr        -> {tgt_str}")
    print()

    # =========================================================
    # 3. Search for callers of 0x033CC4
    # =========================================================
    print("=" * 70)
    print("SEARCH: Who calls 0x033CC4?")
    print("  Looking for byte pattern 00 03 3C C4 in literal pools")
    print("=" * 70)
    pattern = struct.pack('>I', 0x00033CC4)
    hits = search_for_bytes(rom, pattern)
    for h in hits:
        print(f"  Found at ROM offset 0x{h:06X}")
        # Show context: what's around this literal pool entry
        # Look backwards for the mov.l that references this pool entry
        # The mov.l @(disp,PC),Rn instruction references pool_addr = (PC & ~3) + 4 + disp*4
        # So PC = pool_addr - 4 - disp*4, and pool_addr = h
        # We need to find an instruction whose computed pool address = h
        # Scan backwards from h for possible referencing instructions
        found_ref = False
        for scan_back in range(4, 1028, 4):
            check_pc = h - scan_back
            if check_pc < 0 or check_pc + 2 > len(rom):
                continue
            candidate = struct.unpack('>H', rom[check_pc:check_pc+2])[0]
            if (candidate >> 12) == 0xD:  # mov.l @(disp,PC),Rn
                disp = candidate & 0xFF
                rn = (candidate >> 8) & 0xF
                computed_pool = (check_pc & 0xFFFFFFFC) + 4 + disp * 4
                if computed_pool == h:
                    print(f"    Referenced by mov.l instruction at 0x{check_pc:06X} -> R{rn}")
                    # Now find the jsr that uses this register nearby
                    for fwd in range(2, 40, 2):
                        if check_pc + fwd + 2 > len(rom):
                            break
                        fwd_op = struct.unpack('>H', rom[check_pc+fwd:check_pc+fwd+2])[0]
                        if (fwd_op & 0xF0FF) == 0x400B and ((fwd_op >> 8) & 0xF) == rn:
                            print(f"    jsr @R{rn} at 0x{check_pc+fwd:06X}")
                            found_ref = True
                            break

    print()

    # =========================================================
    # 4. Also search for 0x034488 callers
    # =========================================================
    print("=" * 70)
    print("SEARCH: Who calls 0x034488?")
    print("  Looking for byte pattern 00 03 44 88 in literal pools")
    print("=" * 70)
    pattern2 = struct.pack('>I', 0x00034488)
    hits2 = search_for_bytes(rom, pattern2)
    for h in hits2:
        print(f"  Found at ROM offset 0x{h:06X}")
        found_ref = False
        for scan_back in range(4, 1028, 4):
            check_pc = h - scan_back
            if check_pc < 0 or check_pc + 2 > len(rom):
                continue
            candidate = struct.unpack('>H', rom[check_pc:check_pc+2])[0]
            if (candidate >> 12) == 0xD:
                disp = candidate & 0xFF
                rn = (candidate >> 8) & 0xF
                computed_pool = (check_pc & 0xFFFFFFFC) + 4 + disp * 4
                if computed_pool == h:
                    print(f"    Referenced by mov.l instruction at 0x{check_pc:06X} -> R{rn}")
                    for fwd in range(2, 40, 2):
                        if check_pc + fwd + 2 > len(rom):
                            break
                        fwd_op = struct.unpack('>H', rom[check_pc+fwd:check_pc+fwd+2])[0]
                        if (fwd_op & 0xF0FF) == 0x400B and ((fwd_op >> 8) & 0xF) == rn:
                            print(f"    jsr @R{rn} at 0x{check_pc+fwd:06X}")
                            found_ref = True
                            break
    print()

    # =========================================================
    # 5. Search for 0x036070 callers (CL/OL transition)
    # =========================================================
    print("=" * 70)
    print("SEARCH: Who calls 0x036070? (CL/OL transition)")
    print("=" * 70)
    pattern3 = struct.pack('>I', 0x00036070)
    hits3 = search_for_bytes(rom, pattern3)
    for h in hits3:
        print(f"  Found at ROM offset 0x{h:06X}")
        for scan_back in range(4, 1028, 4):
            check_pc = h - scan_back
            if check_pc < 0 or check_pc + 2 > len(rom):
                continue
            candidate = struct.unpack('>H', rom[check_pc:check_pc+2])[0]
            if (candidate >> 12) == 0xD:
                disp = candidate & 0xFF
                rn = (candidate >> 8) & 0xF
                computed_pool = (check_pc & 0xFFFFFFFC) + 4 + disp * 4
                if computed_pool == h:
                    print(f"    Referenced by mov.l instruction at 0x{check_pc:06X} -> R{rn}")
    print()
