#!/usr/bin/env python3
"""
Disassemble the AFC PI Controller function at ROM address 0x342A8
from the Subaru ECU ROM (SH7058, SH-2A, Big-Endian).
Version 2: Refined with detailed annotation and accurate pseudocode.
"""

import struct

ROM_PATH = r"C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin"
START_ADDR = 0x342A8

KNOWN_LABELS = {
    0xFFFF77C8: "CL_correction_state",
    0xFFFF6540: "sensor_state",
    0xFFFF7448: "CLOL_mode_flag",
    0xFFFF7864: "AFC_struct_base",
}

def read_u16(rom, offset):
    return struct.unpack(">H", rom[offset:offset+2])[0]

def read_u32(rom, offset):
    return struct.unpack(">I", rom[offset:offset+4])[0]

def read_float(rom, offset):
    return struct.unpack(">f", rom[offset:offset+4])[0]

def sign_extend_8(v):
    return v - 256 if v & 0x80 else v

def sign_extend_12(v):
    return v - 4096 if v & 0x800 else v

def classify_addr(addr):
    if 0xFFFF0000 <= addr <= 0xFFFFFFFF:
        return "RAM"
    elif 0xCC000 <= addr <= 0xCFFFF:
        return "CAL"
    return "ROM"

def disassemble_one(rom, pc):
    """Disassemble a single instruction at pc. Returns (mnemonic, operands, comment, size=2)."""
    opcode = read_u16(rom, pc)
    nib0 = (opcode >> 12) & 0xF
    nib1 = (opcode >> 8) & 0xF
    nib2 = (opcode >> 4) & 0xF
    nib3 = opcode & 0xF
    n = nib1; m = nib2; d8 = opcode & 0xFF; d12 = opcode & 0xFFF

    mn = ""; ops = ""; cmt = ""; branch_target = None

    if opcode == 0x000B:
        mn = "rts"
    elif opcode == 0x0009:
        mn = "nop"
    elif nib0 == 0xE:
        mn = "mov"; ops = f"#{sign_extend_8(d8)},R{n}"
    elif nib0 == 0xD:
        disp = d8; lit_addr = (pc & ~3) + 4 + disp * 4
        val = read_u32(rom, lit_addr); cls = classify_addr(val)
        mn = "mov.l"; ops = f"@(0x{lit_addr:X}),R{n}"
        label = KNOWN_LABELS.get(val, "")
        if cls == "CAL":
            fv = read_float(rom, val)
            cmt = f"R{n} = &0x{val:X} [{cls}] = {fv}"
        elif cls == "RAM":
            cmt = f"R{n} = &0x{val:08X} [{cls}] {label}"
        else:
            cmt = f"R{n} = 0x{val:X} [{cls}]"
    elif nib0 == 0x9:
        disp = d8; lit_addr = pc + 4 + disp * 2
        val = read_u16(rom, lit_addr)
        mn = "mov.w"; ops = f"@(0x{lit_addr:X}),R{n}"; cmt = f"R{n} = 0x{val:04X} ({val})"
    elif nib0 == 0x6:
        sub = nib3
        tbl = {0:"mov.b",1:"mov.w",2:"mov.l",3:"mov",6:"mov.l",0xC:"extu.b",0xD:"extu.w",0xE:"exts.b",0xF:"exts.w"}
        mn = tbl.get(sub, f".word 0x{opcode:04X}")
        if sub in (0,1,2): ops = f"@R{m},R{n}"
        elif sub == 3: ops = f"R{m},R{n}"
        elif sub == 6: ops = f"@R{m}+,R{n}"
        elif sub in (0xC,0xD,0xE,0xF): ops = f"R{m},R{n}"
        else: ops = f"0x{opcode:04X}"
    elif nib0 == 0x2:
        sub = nib3
        tbl = {0:"mov.b",1:"mov.w",2:"mov.l",6:"mov.l",8:"tst",9:"and",0xA:"xor",0xB:"or",0xE:"mulu.w",0xF:"muls.w"}
        mn = tbl.get(sub, f".word")
        if sub in (0,1,2): ops = f"R{m},@R{n}"
        elif sub == 6: ops = f"R{m},@-R{n}"
        elif sub in (8,9,0xA,0xB,0xE,0xF): ops = f"R{m},R{n}"
        else: ops = f"0x{opcode:04X}"
    elif nib0 == 0x4:
        sub = (nib2 << 4) | nib3
        tbl = {
            0x0B: ("jsr", f"@R{n}"), 0x2B: ("jmp", f"@R{n}"),
            0x22: ("sts.l", f"PR,@-R{n}"), 0x26: ("lds.l", f"@R{n}+,PR"),
            0x13: ("stc.l", f"GBR,@-R{n}"), 0x1E: ("ldc", f"R{n},GBR"),
            0x17: ("ldc.l", f"@R{n}+,GBR"),
            0x11: ("cmp/pz", f"R{n}"), 0x15: ("cmp/pl", f"R{n}"),
            0x10: ("dt", f"R{n}"),
            0x5A: ("lds", f"R{n},FPUL"), 0x6A: ("sts", f"FPUL,R{n}"),
            0x2D: ("float", f"FPUL,FR{n}"), 0x3D: ("ftrc", f"FR{n},FPUL"),
        }
        if sub in tbl:
            mn, ops = tbl[sub]
        else:
            mn = ".word"; ops = f"0x{opcode:04X}"; cmt = f"4n sub=0x{sub:02X}"
    elif nib0 == 0x7:
        mn = "add"; ops = f"#{sign_extend_8(d8)},R{n}"
    elif nib0 == 0x3:
        sub = nib3
        tbl = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",6:"cmp/hi",7:"cmp/gt",0xC:"add",8:"sub"}
        mn = tbl.get(sub, ".word")
        ops = f"R{m},R{n}" if sub in tbl else f"0x{opcode:04X}"
    elif nib0 == 0x8:
        if nib1 == 0x8:
            mn = "cmp/eq"; ops = f"#{sign_extend_8((nib2<<4)|nib3)},R0"
        elif nib1 == 0x9:
            t = pc + 4 + sign_extend_8((nib2<<4)|nib3) * 2
            mn = "bt"; ops = f"0x{t:X}"; branch_target = t
        elif nib1 == 0xB:
            t = pc + 4 + sign_extend_8((nib2<<4)|nib3) * 2
            mn = "bf"; ops = f"0x{t:X}"; branch_target = t
        elif nib1 == 0xD:
            t = pc + 4 + sign_extend_8((nib2<<4)|nib3) * 2
            mn = "bt/s"; ops = f"0x{t:X}"; branch_target = t
        elif nib1 == 0xF:
            t = pc + 4 + sign_extend_8((nib2<<4)|nib3) * 2
            mn = "bf/s"; ops = f"0x{t:X}"; branch_target = t
        elif nib1 == 0x0:
            mn = "mov.b"; ops = f"R0,@({nib3},R{nib2})"
        elif nib1 == 0x1:
            mn = "mov.w"; ops = f"R0,@({nib3}*2,R{nib2})"
        elif nib1 == 0x4:
            mn = "mov.b"; ops = f"@({nib3},R{nib2}),R0"
        elif nib1 == 0x5:
            mn = "mov.w"; ops = f"@({nib3}*2,R{nib2}),R0"
        else:
            mn = ".word"; ops = f"0x{opcode:04X}"
    elif nib0 == 0xA:
        t = pc + 4 + sign_extend_12(d12) * 2
        mn = "bra"; ops = f"0x{t:X}"; branch_target = t
    elif nib0 == 0xB:
        t = pc + 4 + sign_extend_12(d12) * 2
        mn = "bsr"; ops = f"0x{t:X}"; branch_target = t
    elif nib0 == 0xC:
        disp = (nib2 << 4) | nib3
        ctbl = {0:("mov.b",f"R0,@({disp},GBR)"),1:("mov.w",f"R0,@({disp}*2,GBR)"),
                4:("mov.b",f"@({disp},GBR),R0"),5:("mov.w",f"@({disp}*2,GBR),R0"),
                7:("mova",f"@({disp}*4+PC),R0")}
        if nib1 in ctbl:
            mn, ops = ctbl[nib1]
            if nib1 == 7:
                target = (pc & ~3) + 4 + disp * 4
                cmt = f"R0 = 0x{target:X}"
        else:
            mn = ".word"; ops = f"0x{opcode:04X}"
    elif nib0 == 0x1:
        mn = "mov.l"; ops = f"R{m},@({nib3}*4,R{n})"
    elif nib0 == 0x5:
        mn = "mov.l"; ops = f"@({nib3}*4,R{m}),R{n}"
    elif nib0 == 0x0:
        if nib3 == 0x6:
            mn = "mov.l"; ops = f"@(R0,R{m}),R{n}"
        elif nib3 == 0xC:
            mn = "mov.b"; ops = f"@(R0,R{m}),R{n}"
        elif nib3 == 0xD:
            mn = "mov.w"; ops = f"@(R0,R{m}),R{n}"
        else:
            mn = ".word"; ops = f"0x{opcode:04X}"
    elif nib0 == 0xF:
        sub = nib3; fn = n; fm = m
        fpu_tbl = {0:"fadd",1:"fsub",2:"fmul",3:"fdiv",4:"fcmp/eq",5:"fcmp/gt",0xE:"fmac"}
        if sub in fpu_tbl:
            mn = fpu_tbl[sub]
            if sub <= 5: ops = f"FR{fm},FR{fn}"
            elif sub == 0xE: ops = f"FR0,FR{fm},FR{fn}"
        elif sub == 6: mn = "fmov.s"; ops = f"@(R0,R{fm}),FR{fn}"
        elif sub == 7: mn = "fmov.s"; ops = f"FR{fm},@(R0,R{fn})"
        elif sub == 8: mn = "fmov.s"; ops = f"@R{fm},FR{fn}"
        elif sub == 9: mn = "fmov.s"; ops = f"@R{fm}+,FR{fn}"
        elif sub == 0xA: mn = "fmov.s"; ops = f"FR{fm},@R{fn}"
        elif sub == 0xB: mn = "fmov.s"; ops = f"FR{fm},@-R{fn}"
        elif sub == 0xC: mn = "fmov"; ops = f"FR{fm},FR{fn}"
        elif sub == 0xD:
            dtbl = {8:"fldi0",9:"fldi1",4:"fneg",5:"fabs",0:"fsts",1:"flds",2:"float",3:"ftrc"}
            mn = dtbl.get(fm, ".word")
            if fm == 8: ops = f"FR{fn}"
            elif fm == 9: ops = f"FR{fn}"
            elif fm == 4: ops = f"FR{fn}"
            elif fm == 5: ops = f"FR{fn}"
            elif fm == 0: ops = f"FPUL,FR{fn}"
            elif fm == 1: ops = f"FR{fn},FPUL"
            elif fm == 2: ops = f"FPUL,FR{fn}"
            elif fm == 3: ops = f"FR{fn},FPUL"
            else: ops = f"0x{opcode:04X}"
        else: mn = ".word"; ops = f"0x{opcode:04X}"
    else:
        mn = ".word"; ops = f"0x{opcode:04X}"

    return opcode, mn, ops, cmt, branch_target

def main():
    with open(ROM_PATH, "rb") as f:
        rom = f.read()

    # First pass: collect all branch targets
    branch_targets = set()
    pc = START_ADDR
    end_pc = START_ADDR + 250 * 2  # generous limit
    rts_found = False
    rts_delay = False
    max_target = START_ADDR

    while pc <= end_pc:
        opcode, mn, ops, cmt, bt = disassemble_one(rom, pc)
        if bt and bt > max_target:
            max_target = bt
        if bt:
            branch_targets.add(bt)

        if rts_delay:
            if pc >= max_target:
                remaining = [t for t in branch_targets if t > pc]
                if not remaining:
                    end_pc = pc  # stop here
                    break
            rts_delay = False
        if rts_found:
            rts_delay = True
            rts_found = False
        if mn == "rts":
            rts_found = True
        pc += 2

    # ---- Determine GBR base ----
    # From code: R0 = 0xFFFF77C8 loaded, then ldc R0,GBR
    # GBR offsets: @(157,GBR) = GBR+157, @(96,GBR) = GBR+96, @(98,GBR) = GBR+98
    GBR_BASE = 0xFFFF77C8
    gbr_map = {
        157: (GBR_BASE + 157, "FFFF7865", "prev_CLOL_mode (byte)"),
        96:  (GBR_BASE + 96,  "FFFF7828", "AFC_enable_state (byte)"),
        98:  (GBR_BASE + 98,  "FFFF782A", "AFC_status_byte (byte)"),
    }

    # ---- Struct offset map (FFFF7864 base, R6) ----
    # R0=-80 (0xB0 unsigned, signed = -80): base+(-80) = FFFF7864 + (-80) = FFFF7814?
    # Wait - fmov.s uses @(R0,Rn) which is R0+Rn. R6 = FFFF7864, R0 = -80 sign-ext to 0xFFFFFFB0
    # So addr = 0xFFFF7864 + 0xFFFFFFB0 = 0xFFFF7814 (mod 32-bit = 0xFFFF7814)
    # Hmm, that doesn't make sense for AFC output at 7864.
    # Actually R0 = #-80 = 0xFFFFFFB0, R6 = 0xFFFF7864
    # @(R0,R6) = R0 + R6 = 0xFFFFFFB0 + 0xFFFF7864 = 0xFFFE7814? No... 32-bit wrap
    # 0xFFFFFFB0 + 0xFFFF7864 = 0x1FFFE7814 -> truncated to 0xFFFE7814
    # That's wrong. Let me reconsider.
    #
    # Actually for SH2, the R0 value is -80 = 0xFFFFFFB0 (sign extended 32-bit)
    # R6 = 0xFFFF7864
    # @(R0,R6) = 0xFFFF7864 + 0xFFFFFFB0 = wrap 32bit: 0xFFFF7814
    # Hmm. But the user says output is at FFFF7864.
    # Let me check R0=-76 = 0xFFFFFFB4
    # 0xFFFF7864 + 0xFFFFFFB4 = 0xFFFF7818
    #
    # Wait maybe R6 is used as struct base but not FFFF7864 itself.
    # Let me re-read: D658 loads R6 from literal at 0x34450 = 0xFFFF7864
    # Then E0B0 = mov #-80,R0 -> R0 = 0xFFFFFFB0
    # fmov.s FR4,@(R0,R6) -> addr = R0+R6 = 0xFFFF7864 + 0xFFFFFFB0
    # = 0x(1)FFFE7814 -> 0xFFFE7814? That seems wrong.
    #
    # Hmm wait: 0xFFFF7864 + 0xFFFFFFB0:
    # 0xFFFF7864 + 0xFFFFFFB0 = 0x1FFFE7814 -> low 32 = 0xFFFE7814
    # That can't be right for RAM. Let me reconsider...
    #
    # Actually maybe R6 is NOT the struct base pointer but a different value.
    # The literal at 34450 is 0xFFFF7864. But maybe R6 gets loaded with something else
    # by the time these indexed stores happen. Let me look at the instruction flow again.
    #
    # Actually: 0xFFFF7864 is the BASE of the AFC struct. The offsets are:
    # #-80 signed = -80 decimal. In SH2, @(R0,Rn) = R0+Rn as a memory address.
    # 0xFFFF7864 + (-80) = 0xFFFF7864 - 80 = 0xFFFF7814
    # 0xFFFF7864 + (-76) = 0xFFFF7864 - 76 = 0xFFFF7818
    #
    # Wait, -80 in DECIMAL. So: 0xFFFF7864 - 80 = 0xFFFF7814 (that's -0x50)
    # And -76 = 0xFFFF7864 - 76 = 0xFFFF7818 (that's -0x4C)
    #
    # But these don't land on 0xFFFF7864 (the AFC output). Let me think differently.
    #
    # OH WAIT. #-80 in mov is sign-extended to 32 bits: -80 decimal = 0xFFFFFFB0
    # SH2 address calc: R0 + R6 = 0xFFFFFFB0 + 0xFFFF7864
    # = 0xFFFFFFB0 + 0xFFFF7864
    # Let me just do modular: (0xFFFFFFB0 + 0xFFFF7864) mod 2^32
    # = (0xFFFFFFB0 + 0xFFFF7864)
    # 0xFFB0 + 0x7864 = 0x17814 carry 1
    # 0xFFFF + 0xFFFF + 1 = 0x1FFFF carry 1
    # So result = 0xFFFE7814. That's definitely wrong.
    #
    # I think the issue is that the struct base is FFFF7864 but it's being used
    # as a HIGH pointer. The offsets bring it DOWN to the actual struct fields.
    # So the struct actually starts lower in RAM and FFFF7864 is near the END.
    #
    # FFFF7864 + 0xFFFFFFB0 = FFFF7864 - 0x50 = FFFF7814
    # FFFF7864 + 0xFFFFFFB4 = FFFF7864 - 0x4C = FFFF7818
    #
    # Alternatively, maybe the literal is actually being used differently.
    # Let me check the actual hex at 0x34450:

    print(f"ROM size: {len(rom)} bytes")
    print(f"Literal at 0x34450: 0x{read_u32(rom, 0x34450):08X}")
    print(f"Literal at 0x3443C: 0x{read_u32(rom, 0x3443C):08X}")
    print()

    # OK so the struct base pointer IS 0xFFFF7864.
    # Effective addresses with offsets:
    struct_base = 0xFFFF7864
    off_b0 = (struct_base + sign_extend_8(0xB0)) & 0xFFFFFFFF  # -80
    off_b4 = (struct_base + sign_extend_8(0xB4)) & 0xFFFFFFFF  # -76
    print(f"Struct base: 0x{struct_base:08X}")
    print(f"@(R0=-80, R6=base) = @(0x{struct_base:08X} + {sign_extend_8(0xB0)}) = 0x{off_b0:08X}")
    print(f"@(R0=-76, R6=base) = @(0x{struct_base:08X} + {sign_extend_8(0xB4)}) = 0x{off_b4:08X}")
    print()

    # Hmm, those come out to FFFE7814 and FFFE7818 which are way off.
    # Let me reconsider. Maybe -80 means 0xB0 UNSIGNED used as unsigned displacement.
    # In SH2, mov #imm8,Rn DOES sign-extend. So #-80 = 0xFFFFFFB0.
    # BUT! What if they're using R0 as unsigned byte 0xB0 = 176?
    # 0xFFFF7864 + 176 = 0xFFFF7914. Still not 7864.
    #
    # Wait. Let me re-read SH2 manual: mov #imm8, Rn: sign-extends imm8 to 32 bits.
    # So E0B0: mov #-80, R0 -> R0 = 0xFFFFFFB0
    #
    # But the known output address is FFFF7864. What if the struct base is actually
    # FFFF78B4 (so that -80 = -0x50 gives FFFF7864)?
    # 0xFFFF78B4 - 0x50 = 0xFFFF7864. That works!
    # But literal says 0xFFFF7864...
    #
    # OR: maybe the displacement is NOT -80 decimal but 0xB0 = 176 and the base
    # is NOT FFFF7864 in R6 at that point because of a prior add.
    #
    # Actually, I think I need to be more careful. Let me look at the actual encoding.
    # E0B0: nib0=E, n=0, d8=0xB0. mov #imm8,R0 where imm8=0xB0.
    # sign_extend_8(0xB0) = 0xB0 - 0x100 = -80. So R0 = -80 = 0xFFFFFFB0. Confirmed.
    #
    # So the effective address for the AFC output store is:
    # R6(0xFFFF7864) + R0(0xFFFFFFB0) mod 2^32 = 0xFFFE7814
    # That's NOT in the normal FFFF RAM range. Something is off.
    #
    # WAIT - I made an arithmetic error!
    # 0xFFFF7864 + 0xFFFFFFB0:
    # Let me do this carefully in Python:

    ea = (0xFFFF7864 + 0xFFFFFFB0) & 0xFFFFFFFF
    print(f"Actual EA check: (0xFFFF7864 + 0xFFFFFFB0) & 0xFFFFFFFF = 0x{ea:08X}")
    # 0xFFFF7864 + 0xFFFFFFB0 = 0x1FFFE7814 & 0xFFFFFFFF = 0xFFFE7814
    # That IS correct arithmetic but weird address.

    ea2 = (0xFFFF7864 + 0xFFFFFFB4) & 0xFFFFFFFF
    print(f"Actual EA check: (0xFFFF7864 + 0xFFFFFFB4) & 0xFFFFFFFF = 0x{ea2:08X}")

    # Hmm, BUT on SH7058 the physical RAM is mirrored. Addresses in the range
    # 0xFFFE0000-0xFFFFFFFF are actually the same 8KB on-chip RAM.
    # The SH7058 has RAM at 0xFFFF8000-0xFFFF9FFF (8KB).
    # But it also has peripheral registers at 0xFFFE0000+.
    #
    # Actually wait: the SH7058 has 32KB RAM mapped at 0xFFFF0000-0xFFFF7FFF
    # and additional peripheral area.
    #
    # Let me reconsider: maybe the base pointer ISN'T at 0xFFFF7864.
    # Maybe I should look at what's really loaded into R6 at each use point.
    #
    # Actually, I think the issue is simpler. The SH7058 uses 0xFFFF7864 as
    # a pointer to the AFC struct, and the offsets -80 and -76 are RELATIVE to
    # an END pointer. So:
    # 0xFFFF7864 - 80 = 0xFFFF7814 (this is the "current correction" field)
    # 0xFFFF7864 - 76 = 0xFFFF7818 (this is the "I-term accumulator" field)
    # And the AFC output at FFFF7864 is written separately via @Rn (without offset).
    #
    # BUT looking at the code, the writes are ALL via @(R0,R6) with R6=FFFF7864.
    # The direct store to FFFF7864 would be fmov.s FRn,@R6 (opcode FnmA).
    # I don't see that pattern - they all use @(R0,R6).
    #
    # So maybe the user's label "FFFF7864 = AFC output" means the struct starts
    # there and the actual output field is at offset -80 or -76 from it.
    # OR: FFFF7864 is not the output address but the struct base, and the output
    # is at one of the calculated offsets.
    #
    # For now let me just compute and label the effective addresses.

    print()
    print("SH7058 RAM note: 0xFFFE7814 wraps in 32-bit space.")
    print("On SH7058, peripheral/RAM is 0xFFFE0000-0xFFFFFFFF")
    print(f"So 0x{ea:08X} is in the peripheral/extended RAM area")
    print()

    # Actually I realize the user said "Output: FFFF7864" and "writing to RAM 0xFFFF7864"
    # So let me check if maybe R6 gets a DIFFERENT value than FFFF7864 somewhere,
    # or if the signed add wraps correctly on the SH7058.
    #
    # For SH7058/SH-2A, address space is 32-bit and the on-chip RAM block at
    # 0xFFFF8000-0xFFFFBFFF (or similar). FFFF7864 is just below that.
    #
    # I think the answer is: FFFF7864 IS the struct/output address, accessed
    # as *(uint32_t*)FFFF7864 via fmov.s @Rn,FRn (no offset). The @(R0,R6)
    # accesses are to DIFFERENT fields.
    #
    # Checking: is there ANY fmov.s FRn,@R6 (Fn6A) in the disassembly?
    # Looking at F647, F657... F647 = F nib1=6 nib2=4 nib3=7 = fmov.s FR4,@(R0,R6)
    # F657 = fmov.s FR5,@(R0,R6). These all use @(R0,R6).
    #
    # So the write to "FFFF7864" likely means the struct contains the output at
    # one of these offsets. The user may be identifying the struct base as the
    # output address. Let me just document the effective addresses.

    # Recompute: maybe I should treat R6 differently per block.
    # Actually the simpler explanation: maybe the ROM base address convention
    # maps 0xFFFF7864 to physical 0xFFFE7814 on the bus. Or the user
    # simply means "the struct at FFFF7864" and the specific output field
    # is at the computed offset. Let me just proceed with the disassembly.

    # =====================================================
    # SECOND PASS: Full annotated disassembly
    # =====================================================
    print("=" * 110)
    print("  AFC PI CONTROLLER - COMPLETE ANNOTATED DISASSEMBLY")
    print("  Function: 0x342A8   ROM: AE5L600L rev 20.5")
    print("=" * 110)
    print()

    # Track label addresses
    labels = {}
    for t in sorted(branch_targets):
        labels[t] = f"L_{t:05X}"

    pc = START_ADDR
    count = 0
    while pc <= end_pc + 2:
        if pc in labels:
            print(f"\n{labels[pc]}:")

        opcode, mn, ops, cmt, bt = disassemble_one(rom, pc)
        marker = " <--" if pc in branch_targets else ""

        line = f"  {pc:05X}: {opcode:04X}  {mn:12s} {ops:32s}"
        if cmt:
            line += f"; {cmt}"
        print(line)

        count += 1
        pc += 2
        if pc > end_pc + 2:
            break

    print(f"\n  --- {count} instructions, 0x{START_ADDR:X} to 0x{end_pc:X} ---")

    # =====================================================
    # Literal pool
    # =====================================================
    print("\n" + "=" * 80)
    print("  LITERAL POOL DUMP")
    print("=" * 80)

    # Scan for all D-type loads to find literal addresses
    lit_addrs = set()
    pc = START_ADDR
    while pc <= end_pc:
        opc = read_u16(rom, pc)
        if (opc >> 12) == 0xD:
            disp = opc & 0xFF
            la = (pc & ~3) + 4 + disp * 4
            lit_addrs.add(la)
        pc += 2

    print()
    for la in sorted(lit_addrs):
        val = read_u32(rom, la)
        cls = classify_addr(val)
        line = f"  0x{la:05X}:  {rom[la]:02X} {rom[la+1]:02X} {rom[la+2]:02X} {rom[la+3]:02X}  = 0x{val:08X}  [{cls}]"
        if cls == "RAM":
            label = KNOWN_LABELS.get(val, "")
            line += f"  {label}"
        elif cls == "CAL":
            fv = read_float(rom, val)
            line += f"  -> float at 0x{val:X} = {fv}"
        elif cls == "ROM":
            line += f"  (subroutine)"
        print(line)

    # =====================================================
    # RAM addresses
    # =====================================================
    print("\n" + "=" * 80)
    print("  RAM ADDRESSES READ/WRITTEN")
    print("=" * 80)
    print()
    print("  Direct pointer loads (via literal pool):")
    for la in sorted(lit_addrs):
        val = read_u32(rom, la)
        if classify_addr(val) == "RAM":
            label = KNOWN_LABELS.get(val, "")
            print(f"    0x{val:08X}  {label}")

    print()
    print("  GBR-relative accesses (GBR = 0xFFFF77C8):")
    for disp, (addr, hexstr, desc) in sorted(gbr_map.items()):
        print(f"    GBR+{disp:3d} = 0x{hexstr}  {desc}")

    print()
    print("  Indexed struct accesses (base R6 = 0xFFFF7864):")
    for off_raw, desc in [(0xB0, "AFC PI correction (fmov.s write)"), (0xB4, "AFC I-term accumulator (fmov.s read/write)")]:
        signed_off = sign_extend_8(off_raw)
        ea_val = (0xFFFF7864 + signed_off) & 0xFFFFFFFF
        # For SH7058, high RAM wraps: show as FFFF....
        print(f"    R6 + #{signed_off} (0x{off_raw:02X}) -> 0x{ea_val:08X}  {desc}")

    # =====================================================
    # Calibration values
    # =====================================================
    print("\n" + "=" * 80)
    print("  CALIBRATION VALUES")
    print("=" * 80)
    print()
    cal_addrs_found = set()
    for la in sorted(lit_addrs):
        val = read_u32(rom, la)
        if classify_addr(val) == "CAL":
            cal_addrs_found.add(val)

    for ca in sorted(cal_addrs_found):
        fv = read_float(rom, ca)
        raw = read_u32(rom, ca)
        print(f"  0x{ca:05X}: raw=0x{raw:08X}  float={fv:12.6f}  ", end="")
        if abs(fv - 2.0) < 0.001: print("(P gain)")
        elif abs(fv - 20.0) < 0.001: print("(max clamp %)")
        elif abs(fv) < 0.001: print("(min clamp / dead zone)")
        elif abs(fv - 1.0) < 0.001: print("(I gain)")
        else: print()

    # =====================================================
    # ROM subroutine references
    # =====================================================
    print("\n" + "=" * 80)
    print("  ROM SUBROUTINE REFERENCES")
    print("=" * 80)
    print()
    for la in sorted(lit_addrs):
        val = read_u32(rom, la)
        if classify_addr(val) == "ROM":
            desc = ""
            if val == 0xBEAB0: desc = "table_lookup (error scaling)"
            elif val == 0xBE970: desc = "clamp_float"
            elif val == 0xBE960: desc = "clamp_float_neg (or variant)"
            print(f"  0x{val:05X}  {desc}")

    # =====================================================
    # DETAILED PSEUDOCODE
    # =====================================================
    print("\n" + "=" * 110)
    print("  PSEUDOCODE - AFC PI CONTROLLER (6 branch paths)")
    print("=" * 110)
    print("""
// ============================================================================
// AFC PI Controller at 0x342A8
// ============================================================================
// GBR = 0xFFFF77C8 (set at entry)
// R6 loaded from literal pool = 0xFFFF7864 (AFC struct base pointer)
// Struct offsets from base:
//   @(R0=-80, R6) = struct[-80] = PI correction output   (FFFE7814)
//   @(R0=-76, R6) = struct[-76] = I-term accumulator      (FFFE7818)
// GBR-relative fields:
//   GBR+157 = FFFF7865 = previous CL/OL mode byte (saved/restored)
//   GBR+96  = FFFF7828 = AFC enable state byte
//   GBR+98  = FFFF782A = AFC status/path code
//
// Calibration:
//   0xCC000 = 2.0   (P_gain)
//   0xCC004 = 20.0  (max_clamp)
//   0xCC008 = 0.0   (min_clamp / deadzone)
//   0xCC00C = 1.0   (I_gain)
//
// Subroutines:
//   0xBEAB0 = table_lookup (called with error in FR4, FR5=0)
//   0xBE960 = clamp_neg (subtract + clamp, called for path 2)
//   0xBE970 = clamp_pos (add + clamp, called for path 3)
// ============================================================================

function AFC_PI_Controller() {{
    // --- PROLOGUE (0x342A8-0x342B4) ---
    push R14, PR, GBR to stack
    GBR = 0xFFFF77C8          // CL correction state base
    R15 -= 8                  // allocate 8 bytes local space

    // --- LOAD INPUTS (0x342B4-0x342C4) ---
    R2 = &FFFF6540            // sensor_state pointer
    FR4 = *(float*)R2         // FR4 = sensor_state (current O2 reading)
    R6_mode = &FFFF7448       // CL/OL mode flag pointer
    R14 = *(byte*)R6_mode     // R14 = mode byte (preserved for epilogue)
    R6 = 0xFF                 // R6 = 255 (will become exit code)
    R0 = zero_extend(R14)     // R0 = mode byte unsigned

    // ============================================================
    // PATH CHECK 1: Is CL mode active? (0x342C0)
    // ============================================================
    if (R0 != 1) {{           // cmp/eq #1,R0 -> bf/s 0x34322
        R6 = 0xFF & 0xFF      // extu.b in delay slot: R6 = 255
        goto L_34322           // -> "was previously enabled?" check
    }}
    // (delay slot): R6 = extu.b(0xFF) = 255

    // ============================================================
    // PATH CHECK 2: Was AFC previously active? (0x342C6)
    // ============================================================
    R0 = GBR[157]             // FFFF7865: previous CL/OL mode
    if (R0 != 0) {{           // tst R0,R0 -> bf 0x34302
        goto L_34302           // -> upper limit check (PI active path)
    }}

    // ============================================================
    // PATH CHECK 3: Check AFC enable state (0x342CC)
    // ============================================================
    R0 = GBR[96]              // FFFF7828: AFC enable state
    stack[4] = R0             // save to local var
    R0 = zero_extend(R0)
    if (R0 != 1) {{           // cmp/eq #1 -> bf 0x34332
        goto L_34332           // -> path dispatch (skip computation)
    }}

    // ============================================================
    // COMPUTE ERROR AND CALL TABLE LOOKUP (0x342D6-0x342E2)
    // ============================================================
    R2 = &FFFF77C8            // CL correction state
    FR8 = *(float*)R2         // FR8 = CL correction target
    FR4 = FR4 - FR8           // FR4 = error = sensor - target
    *(float*)R15 = FR4        // save error to stack local[0]
    R2 = 0xBEAB0              // table lookup subroutine
    FR5 = 0.0                 // clear FR5 (parameter)
    call R2                   // jsr table_lookup(FR4=error, FR5=0)
    // Returns FR0 = scaled/looked-up value

    // ============================================================
    // CHECK P_GAIN THRESHOLD (0x342E4-0x342EA)
    // ============================================================
    R2 = &0xCC000             // P_gain cal pointer
    FR8 = *(float*)R2         // FR8 = P_gain = 2.0
    // fcmp/gt FR0,FR8: is FR8 > FR0? i.e., is P_gain > lookup_result?
    if (FR8 > FR0) {{         // bt 0x342F6
        // --- BRANCH PATH A: Below P threshold -> write 0.0 ---
        FR5 = 0.0             // fldi0
        R6 = &FFFF7864
        R0 = -80
        *(float*)(R0 + R6) = FR5   // struct[-80] = 0.0 (zero correction)
        goto L_342FE
    }}

    // --- BRANCH PATH B: Above P threshold -> write error ---
    FR4 = *(float*)R15        // reload error from stack
    R6 = &FFFF7864
    R0 = -80
    *(float*)(R0 + R6) = FR4  // struct[-80] = error value
    // falls through to L_342FE

L_342FE:  // (0x342FE)
    R6 = 1                    // path code = 1 (PI active, initial)
    goto L_34332              // -> path dispatch

    // ============================================================
    // PATH 4: UPPER LIMIT CHECK (0x34302) - entered when prev mode != 0
    // ============================================================
L_34302:
    R2 = &0xCC004             // max_clamp cal pointer
    FR9 = *(float*)R2         // FR9 = max_clamp = 20.0
    R6 = &FFFF7864
    R0 = -76
    FR8 = *(float*)(R0 + R6) // FR8 = struct[-76] (I-term accumulator)
    // fcmp/gt FR8,FR9: is FR9 > FR8? i.e., is max > I-term?
    if (FR9 > FR8) {{         // bt 0x34314 -> check lower limit
        goto L_34314
    }}
    // I-term >= max: already at/above upper limit
    R6 = 2                    // path code = 2 (upper-limited)
    goto L_34332

    // ============================================================
    // PATH 5: LOWER LIMIT CHECK (0x34314)
    // ============================================================
L_34314:
    FR9 = *(float*)(R0 + R6) // FR9 = struct[-76] (reload I-term)
    R2 = &0xCC008             // min_clamp cal pointer
    FR8 = *(float*)R2         // FR8 = min_clamp = 0.0
    // fcmp/gt FR9,FR8: is FR8 > FR9? i.e., is min > I-term?
    if (FR8 <= FR9) {{        // bf 0x34330 -> I-term >= min, set code 4
        goto L_34330
    }}
    // I-term < min: at/below lower limit
    R6 = 3                    // path code = 3 (lower-limited)
    goto L_34332

    // ============================================================
    // PATH 6: DISABLE / TRANSITION CHECK (0x34322)
    // Entered when CL mode is NOT active (mode != 1)
    // ============================================================
L_34322:
    R0 = GBR[96]              // FFFF7828: AFC enable state
    if (R0 != 1) {{           // cmp/eq #1 -> bf 0x34330
        goto L_34330           // -> set code 4 (fully disabled)
    }}
    // Was enabled but CL mode just turned off -> zero the output
    FR5 = 0.0
    R6 = &FFFF7864
    R0 = -80
    *(float*)(R0 + R6) = FR5  // struct[-80] = 0.0 (zero correction on disable)
    // fall through to L_34330

L_34330:  // (0x34330)
    R6 = 4                    // path code = 4 (disabled/idle)

    // ============================================================
    // PATH DISPATCH (0x34332) - execute action based on path code R6
    // ============================================================
L_34332:
    R0 = R6                   // R0 = path code

    // --- Code 1: Copy correction to I-term, set enable ---
    if (R0 == 1) {{
        R6 = &FFFF7864
        FR8 = *(float*)(R6 + (-80))   // FR8 = struct[-80] (PI correction)
        *(float*)(R6 + (-76)) = FR8    // struct[-76] = FR8 (copy to I-term)
        R0 = 1
        GBR[98] = R0                   // FFFF782A = 1 (AFC status = active)
        goto EPILOGUE
    }}

    // --- Code 2: Subtract I_gain from I-term (rich limiting) ---
    if (R0 == 2) {{
        R6 = &FFFF7864
        FR4 = *(float*)(R6 + (-76))   // FR4 = I-term
        R2 = &0xCC00C                  // I_gain cal
        FR8 = *(float*)R2             // FR8 = 1.0
        FR4 = FR4 - FR8              // FR4 = I-term - I_gain (decay toward zero)
        R2 = 0xBE960                  // clamp_neg subroutine
        FR5 = 0.0
        call R2                       // FR0 = clamp(FR4, 0, ...)
        R6 = &FFFF7864
        *(float*)(R6 + (-76)) = FR0   // struct[-76] = clamped I-term
        goto EPILOGUE
    }}

    // --- Code 3: Add I_gain to I-term (lean limiting) ---
    if (R0 == 3) {{
        R6 = &FFFF7864
        FR4 = *(float*)(R6 + (-76))   // FR4 = I-term
        R2 = &0xCC00C                  // I_gain cal
        FR8 = *(float*)R2             // FR8 = 1.0
        FR4 = FR4 + FR8              // FR4 = I-term + I_gain (grow correction)
        R2 = 0xBE970                  // clamp_pos subroutine
        FR5 = 0.0
        call R2                       // FR0 = clamp(FR4, limits...)
        R6 = &FFFF7864
        *(float*)(R6 + (-76)) = FR0   // struct[-76] = clamped I-term
        goto EPILOGUE
    }}

    // --- Code 4: Zero the I-term (disabled) ---
    if (R0 == 4) {{
        FR5 = 0.0
        R6 = &FFFF7864
        *(float*)(R6 + (-76)) = FR5   // struct[-76] = 0.0
        // fall through to epilogue
    }}

EPILOGUE:  // (0x34390)
    R0 = R14                   // restore original mode byte
    GBR[157] = R0              // FFFF7865 = current mode (for next call)
    R15 += 8                   // free local space
    restore GBR, PR, R14 from stack
    rts
}}""")

    # =====================================================
    # CONTROL FLOW DIAGRAM
    # =====================================================
    print("\n" + "=" * 110)
    print("  CONTROL FLOW DIAGRAM")
    print("=" * 110)
    print(r"""
    0x342A8 ENTRY: push R14, PR, GBR; GBR=FFFF77C8; alloc stack
        |
        v
    Load FR4=sensor(FFFF6540), R14=mode(FFFF7448), R6=0xFF
        |
        v
    [mode == 1?] ----NO----> L_34322: "was-enabled check"
        |                        |
       YES                  [GBR[96]==1?] --NO--> L_34330: R6=4
        |                        |
        v                       YES
    [GBR[157]!=0?] --YES--> L_34302: "limit check"       |
        |                        |                    write 0.0 to
       NO (prev=0)          [max > Iterm?]            struct[-80]
        |                    /        \                    |
        v                  NO         YES                  v
    [GBR[96]==1?]     R6=2         L_34314            L_34330: R6=4
        |           goto disp    [min > Iterm?]
       NO -> L_34332              /        \
        |                       NO         YES
       YES                   L_34330      R6=3
        |                    R6=4       goto disp
        v
    COMPUTE: FR4 = sensor - CL_target
    CALL table_lookup(FR4, 0)
        |
        v
    [P_gain > result?] ---YES---> write 0.0 to struct[-80]
        |                              |
       NO                              v
        |                         L_342FE: R6=1, goto dispatch
        v
    write error to struct[-80]
        |
        v
    L_342FE: R6=1, goto dispatch

    =================== DISPATCH (L_34332) ===================

    R0 = path code (R6)
        |
        +--[R0==1]--> copy struct[-80] to struct[-76]
        |             GBR[98]=1, goto epilogue
        |
        +--[R0==2]--> Iterm -= I_gain(1.0)
        |             call clamp_neg(BE960)
        |             write clamped -> struct[-76], goto epilogue
        |
        +--[R0==3]--> Iterm += I_gain(1.0)
        |             call clamp_pos(BE970)
        |             write clamped -> struct[-76], goto epilogue
        |
        +--[R0==4]--> write 0.0 -> struct[-76]
        |             fall through to epilogue
        |
        v
    EPILOGUE (0x34390): GBR[157]=mode, restore stack, rts
""")

    # =====================================================
    # SUMMARY OF 6 BRANCH PATHS
    # =====================================================
    print("=" * 110)
    print("  SUMMARY: 6 BRANCH PATHS TO FFFF7864 STRUCT")
    print("=" * 110)
    print("""
  Path A (0x342F6): P_gain > lookup_result
    -> Write 0.0 to struct[-80] (correction = zero, below threshold)
    -> Set code=1, enter dispatch

  Path B (0x342EC): P_gain <= lookup_result
    -> Write error to struct[-80] (non-zero correction)
    -> Set code=1, enter dispatch

  Path 1 dispatch (code=1): Initial PI activation
    -> Copy struct[-80] to struct[-76] (seed I-term with current correction)
    -> GBR[98] = 1 (mark AFC as active)

  Path 2 dispatch (code=2): I-term at/above upper limit (rich error)
    -> I-term -= I_gain (1.0) with clamp via 0xBE960
    -> Decays I-term back toward limit

  Path 3 dispatch (code=3): I-term below lower limit (lean error)
    -> I-term += I_gain (1.0) with clamp via 0xBE970
    -> Grows I-term toward limit

  Path 4 dispatch (code=4): Disabled/idle
    -> Write 0.0 to struct[-76] (zero I-term)
    -> Entered from: CL mode off + not previously enabled, or limit checks passed

  Path 6 (0x34322-0x3432E): CL mode OFF but was previously enabled
    -> Write 0.0 to struct[-80] (zero correction on CL->OL transition)
    -> Falls to code=4 (zero I-term too)
""")


if __name__ == "__main__":
    main()
